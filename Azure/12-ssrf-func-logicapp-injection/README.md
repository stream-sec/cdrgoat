# 12. SSRF on Function App → Logic App Workflow Injection → Key Vault → Service Bus

## Overview
This scenario demonstrates how `Logic App Contributor` permissions can be abused to inject malicious actions into integration workflows. The attacker exploits an SSRF vulnerability on a Function App, steals the Managed Identity's token, reads and modifies a Logic App workflow to exfiltrate Key Vault secrets to an attacker-controlled webhook, and uses the stolen Service Bus connection string to read queued business messages.

Logic Apps serve as integration hubs with broad permissions (Key Vault, Service Bus, databases). Modifying a workflow to add an exfiltration step is stealthy — the normal flow continues working while secrets are siphoned. This mirrors real supply-chain attacks on orchestration platforms.

&nbsp;

## Required Resources

**Identity & Access**
- User-Assigned MI (Function App) with Logic App Contributor + Reader on RG
- Logic App System-Assigned MI with Key Vault Secrets User + Service Bus Data Sender

**Compute**
- Function App with SSRF-vulnerable endpoint
- Logic App (Consumption) with HTTP trigger and Key Vault integration

**Data**
- Key Vault storing Service Bus connection strings
- Service Bus namespace with queue

&nbsp;

## Scenario Goals
Demonstrate that Logic App Contributor allows full workflow modification, enabling stealthy secret exfiltration through integration workflow injection.

&nbsp;

## Diagram
![Diagram](./diagram.png)

&nbsp;

## Attack Walkthrough

### Phase 1: Initial Access via SSRF
- **SSRF Exploitation** — Use Function App's `/api/fetch` to reach IMDS
- **Token Theft** — Steal ARM management token for the MI

### Phase 2: Reconnaissance
- **Resource Enumeration** — Discover Logic App, Key Vault, Service Bus
- **Workflow Analysis** — Read Logic App definition to understand actions and triggers

### Phase 3: Workflow Injection
- **Modify Workflow** — Add an HTTP action that POSTs Key Vault secrets to an attacker webhook
- **Maintain Normal Flow** — The original actions continue working (stealth)
- **Re-deploy** — PUT the modified workflow definition via ARM API

### Phase 4: Trigger and Exfiltrate
- **Trigger Logic App** — POST a sample order to the HTTP trigger
- **Secret Exfiltration** — Logic App fetches KV secrets and forwards to attacker webhook
- **Connection String Theft** — Extract Service Bus connection string from webhook

### Phase 5: Service Bus Access
- **Generate SAS Token** — Use stolen connection string to create auth token
- **Read Messages** — Peek/receive messages from the queue

&nbsp;

## Expected Results
**Successful Completion** — Key Vault secrets are exfiltrated via injected Logic App action. Service Bus connection string is used to access queued messages.

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

After deployment:

```bash
terraform output function_app_url
terraform output mi_client_id
```

You will also need a webhook endpoint for exfiltration (e.g., https://webhook.site).

#### Attack Execution

```bash
chmod +x attack.sh
./attack.sh
```

#### Clean Up

The attack script offers to restore the original Logic App workflow. Then:

```bash
terraform destroy -var='attack_whitelist=[]' -auto-approve
```

&nbsp;

## Detection Opportunities

| Signal | Service | Description |
|--------|---------|-------------|
| Workflow Update | Activity Log | Logic App definition modified by non-CI/CD identity |
| Outbound HTTP | Logic App Run History | HTTP action to unknown external endpoint |
| SSRF to IMDS | Function App Logs | Request to 169.254.169.254 |
| Key Vault Access | Key Vault Audit Logs | Secret reads triggered by Logic App |
| Service Bus Access | Service Bus Metrics | Reads from unexpected SAS policy/client |

&nbsp;

## Remediation Guidance

1. **Logic App Access Control**
   - Restrict Logic App Contributor to CI/CD identities only
   - Use Azure Policy to prevent workflow modifications outside approved pipelines
   - Enable change tracking for Logic App definitions

2. **Workflow Security**
   - Use Logic App access control to restrict trigger access
   - Implement approval workflows for Logic App changes
   - Monitor Logic App run history for unexpected actions

3. **Key Vault Protection**
   - Audit which identities have Key Vault Secrets User
   - Enable Key Vault logging to detect unusual read patterns
   - Use private endpoints

4. **Service Bus Security**
   - Rotate SAS keys regularly
   - Use Azure AD authentication instead of SAS where possible
   - Monitor for SAS token usage from unexpected IPs

5. **SSRF Prevention**
   - Block requests to metadata endpoints
   - Validate URLs in server-side request functions
   - Use outbound network restrictions
