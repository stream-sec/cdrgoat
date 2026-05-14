# 5. SSRF on Function App → Blind SP Credential Injection

## Overview
This scenario demonstrates an attack where a Server-Side Request Forgery (SSRF) vulnerability in an Azure Function App is exploited to steal Managed Identity tokens. The attacker discovers that the MI has `Application.ReadWrite.OwnedBy` permissions on Microsoft Graph, enabling them to discover and inject credentials into App Registrations the MI owns. One of the compromised apps has `Contributor` on a Resource Group containing sensitive data, enabling lateral movement and data exfiltration.

This attack mirrors the AWS Scenario 5 (`CreateAccessKey` blind user enumeration) pattern, adapted for Azure's identity model using `addPassword` credential injection.

&nbsp;

## Required Resources

**Identity & Access**
- Azure Function App with User-Assigned Managed Identity
- MI granted `Application.ReadWrite.OwnedBy` on Microsoft Graph
- Multiple App Registrations owned by the MI
- One App Registration with `Contributor` on the Resource Group

**Compute**
- Azure Function App (Linux, Python 3.11, Consumption plan) with SSRF-vulnerable endpoint

**Storage**
- Storage Account with sensitive data blobs (exfiltration target)

&nbsp;

## Scenario Goals
The attacker's objective is to exploit SSRF to steal MI tokens, discover owned App Registrations, inject credentials via `addPassword`, identify a privileged app, and exfiltrate data from a Storage Account.

&nbsp;

## Diagram
![Diagram](./diagram.png)

&nbsp;

## Attack Walkthrough

### Phase 1: Initial Access via SSRF
- **SSRF Exploitation** — Use the Function App's `/api/fetch` endpoint to make server-side requests to internal endpoints
- **IMDS Token Theft** — Request ARM and Graph tokens from `169.254.169.254` via SSRF

### Phase 2: Reconnaissance
- **Listing Denied** — Attempt to list all applications via Graph API → 403 Forbidden
- **Owned Objects Discovery** — Query `/servicePrincipals/{id}/ownedObjects` to discover apps the MI owns

### Phase 3: Credential Injection
- **addPassword Attack** — For each owned App Registration, call `POST /applications/{id}/addPassword` to inject a new client secret
- **Credential Collection** — Collect all injected client_id + client_secret pairs

### Phase 4: Privilege Discovery
- **Authentication Sweep** — Authenticate as each compromised app using `client_credentials` flow
- **RBAC Enumeration** — Check Azure role assignments for each identity
- **Privileged App Found** — Identify the app with `Contributor` on the Resource Group

### Phase 5: Data Exfiltration
- **Storage Enumeration** — List Storage Accounts, containers, and blobs
- **Data Theft** — Download sensitive blobs using the privileged app's credentials

&nbsp;

## Expected Results
**Successful Completion** — Starting from an SSRF vulnerability, the attacker steals MI tokens, injects credentials into multiple App Registrations, discovers a privileged one, and exfiltrates sensitive data from Azure Storage.

&nbsp;

## Getting Started

#### Install Dependencies

macOS
```bash
brew install terraform azure-cli jq curl python3
```

Linux (Debian/Ubuntu)
```bash
sudo apt update && sudo apt install -y terraform jq curl python3
```

#### Deploy

```bash
az login
terraform init
terraform apply -var='attack_whitelist=["<your_ip>/32"]' -auto-approve
```

After deployment, note the Function App URL:

```bash
terraform output function_app_url
```

#### Attack Execution

```bash
chmod +x attack.sh
./attack.sh
```

The script will prompt for the Function App URL and execute the full attack chain.

#### Clean Up

```bash
terraform destroy -var='attack_whitelist=[]' -auto-approve
```

&nbsp;

## Detection Opportunities

| Signal | Service | Description |
|--------|---------|-------------|
| SSRF to IMDS | Function App logs | Outbound requests to 169.254.169.254 |
| Graph API ownedObjects | Azure AD Audit Logs | Service principal querying owned objects |
| addPassword | Azure AD Audit Logs | New credentials added to App Registrations |
| SP Authentication | Azure AD Sign-in Logs | client_credentials flow from unexpected apps |
| Storage Access | Storage Analytics | Blob reads from unexpected principals |

&nbsp;

## Remediation Guidance

1. **SSRF Prevention**
   - Validate and sanitize URLs in server-side request functions
   - Block requests to internal/metadata IP ranges (169.254.169.254)
   - Use allowlists for outbound destinations

2. **Managed Identity Permissions**
   - Avoid `Application.ReadWrite.OwnedBy` unless strictly necessary
   - Prefer more specific Graph API permissions
   - Regularly audit MI app role assignments

3. **App Registration Security**
   - Monitor for new credential additions (addPassword events)
   - Alert on credentials added by non-human identities
   - Implement credential expiration policies

4. **Monitoring**
   - Alert on IMDS access from Function Apps
   - Track addPassword calls in Azure AD audit logs
   - Monitor for authentication from newly created SP credentials
