# 9. Leaked SP → ARM Deployment History → Secret Extraction → SQL Database

## Overview
This scenario demonstrates one of the most overlooked secret leakage vectors in Azure: ARM deployment history. A leaked Service Principal with only **Reader** role — seemingly the lowest privilege — can read deployment history, which stores template parameters and outputs in plaintext. A previous deployment that passed the SQL admin password as a parameter and exposed it in an output is discovered, giving the attacker full database access.

Microsoft documents this risk, but it remains widely ignored by organizations that assume Reader is a safe, harmless role.

&nbsp;

## Required Resources

**Identity & Access**
- App Registration with Reader role on the Resource Group
- Azure SQL Server with admin credentials

**Data**
- Azure SQL Database (Basic tier)
- Key Vault (decoy — access denied for the leaked SP)
- Storage Account (decoy — visible during enumeration)

**Critical**
- ARM template deployment with SQL password in outputs (creates the secret leak)

&nbsp;

## Scenario Goals
Demonstrate that Reader role can extract secrets from ARM deployment history, and that organizations must treat deployment outputs as sensitive data.

&nbsp;

## Diagram
![Diagram](./diagram.png)

&nbsp;

## Attack Walkthrough

### Phase 1: Initial Access
- **Leaked Credentials** — Attacker obtains SP credentials from CI/CD logs or public repository
- **Authentication** — OAuth client_credentials flow with Reader-only access

### Phase 2: Reconnaissance
- **Resource Enumeration** — List all resources in the Resource Group
- **Access Testing** — Confirm Key Vault (denied), SQL (no credentials), Storage (no data plane access)
- **Apparent Dead End** — Reader seems harmless

### Phase 3: Deployment History Mining
- **List Deployments** — Query ARM deployment history for the Resource Group
- **Inspect Outputs** — Read deployment details, find one with sensitive outputs
- **Secret Extraction** — Extract SQL connection string (including password) from deployment output

### Phase 4: Data Exfiltration
- **SQL Connection** — Connect to Azure SQL Database with extracted admin credentials
- **Data Exfiltration** — Query system tables and user data

&nbsp;

## Expected Results
**Successful Completion** — Starting from a Reader-only SP, the attacker extracts SQL admin credentials from ARM deployment history and gains full database access.

&nbsp;

## Getting Started

#### Install Dependencies

macOS
```bash
brew install terraform azure-cli jq curl
# Optional for SQL connection: brew install sqlcmd
```

Linux (Debian/Ubuntu)
```bash
sudo apt update && sudo apt install -y terraform jq curl
# Optional: install sqlcmd from Microsoft repos
```

#### Deploy

```bash
az login
terraform init
terraform apply -auto-approve
```

After deployment, retrieve the leaked credentials:

```bash
terraform output -json leaked_credentials | jq
```

#### Attack Execution

```bash
chmod +x attack.sh
./attack.sh
```

#### Clean Up

```bash
terraform destroy -auto-approve
```

&nbsp;

## Detection Opportunities

| Signal | Service | Description |
|--------|---------|-------------|
| Deployment History Read | Activity Log | GET on /deployments from non-CI/CD identity |
| SP Authentication | Azure AD Sign-in Logs | Client credentials from unusual location |
| SQL Login | SQL Audit Logs | Admin login from unexpected IP |
| Multiple Deployment Reads | Activity Log | Sequential reads of multiple deployments (enumeration) |

&nbsp;

## Remediation Guidance

1. **Deployment History Hygiene**
   - Never pass secrets as ARM template parameters — use Key Vault references
   - Never expose secrets in ARM template outputs
   - Regularly purge old deployment history
   - Use `secureString` AND avoid referencing secure parameters in outputs

2. **Reader Role Awareness**
   - Treat Reader as capable of reading deployment secrets
   - Audit who has Reader on Resource Groups with deployment history
   - Consider custom roles that exclude `Microsoft.Resources/deployments/read`

3. **SQL Security**
   - Use Azure AD authentication instead of SQL auth
   - Never rely on firewall rules alone (restrict to specific IPs)
   - Enable SQL Auditing and Advanced Threat Protection

4. **Monitoring**
   - Alert on ARM deployment history reads from non-deployment identities
   - Monitor SQL logins from unexpected sources
   - Track SP authentication patterns
