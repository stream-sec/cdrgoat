# 10. Leaked SP → Data Factory Pipeline Injection → Cosmos DB Exfiltration

## Overview
This scenario demonstrates a "living off the land" data exfiltration technique using Azure Data Factory. A leaked Service Principal with `Data Factory Contributor` role creates a malicious pipeline that leverages existing linked services to copy all data from Cosmos DB to attacker-accessible blob storage. The attacker never sees the Cosmos DB credentials — ADF resolves them at runtime, making this attack especially stealthy.

This mirrors real-world scenarios where data engineering roles are over-provisioned and pipeline modifications go unmonitored.

&nbsp;

## Required Resources

**Identity & Access**
- Leaked App Registration with Data Factory Contributor on ADF + Reader on RG + Storage Blob Data Reader on Storage
- Data Factory System-Assigned MI with Key Vault Secrets User + Storage Blob Data Contributor

**Data**
- Cosmos DB with sample customer documents
- Key Vault storing Cosmos DB connection string
- Storage Account with backup and exfiltration containers

**Compute**
- Azure Data Factory with linked services, datasets, and a legitimate pipeline

&nbsp;

## Scenario Goals
Demonstrate that Data Factory Contributor can create pipelines that leverage existing credentials without direct access, enabling stealthy data exfiltration.

&nbsp;

## Diagram
![Diagram](./diagram.png)

&nbsp;

## Attack Walkthrough

### Phase 1: Initial Access
- **Leaked Credentials** — SP credentials found in CI/CD logs
- **Authentication** — OAuth client_credentials flow

### Phase 2: Reconnaissance
- **Resource Enumeration** — Discover Data Factory, Cosmos DB, Key Vault, Storage
- **Direct Access Denied** — Cannot access Cosmos DB data plane directly
- **ADF Inspection** — List linked services, datasets, and existing pipelines

### Phase 3: Pipeline Injection
- **Dataset Creation** — Create a new blob dataset pointing to an "exfiltrated" container
- **Pipeline Creation** — Create a malicious Copy pipeline that reads from Cosmos DB (via existing linked service) and writes to the new blob dataset
- **No Credential Access** — Attacker never sees Cosmos DB key; ADF resolves it at runtime

### Phase 4: Data Exfiltration
- **Pipeline Trigger** — Execute the malicious pipeline
- **Data Download** — Read exfiltrated JSON blobs from the storage container

&nbsp;

## Expected Results
**Successful Completion** — All Cosmos DB customer documents are copied to blob storage and downloaded by the attacker, without the attacker ever obtaining Cosmos DB credentials directly.

&nbsp;

## Getting Started

#### Install Dependencies

macOS
```bash
brew install terraform azure-cli jq curl
```

Linux (Debian/Ubuntu)
```bash
sudo apt update && sudo apt install -y terraform jq curl
```

#### Deploy

```bash
az login
terraform init
terraform apply -auto-approve
```

After deployment:

```bash
terraform output -json leaked_credentials | jq
terraform output data_factory_name
terraform output storage_account_name
```

#### Attack Execution

```bash
chmod +x attack.sh
./attack.sh
```

#### Clean Up

The attack script offers to delete the malicious pipeline and dataset. Then:

```bash
terraform destroy -auto-approve
```

&nbsp;

## Detection Opportunities

| Signal | Service | Description |
|--------|---------|-------------|
| Pipeline Creation | ADF Monitoring | New pipeline created by non-CI/CD identity |
| Pipeline Execution | ADF Monitoring | Pipeline run to unexpected sink container |
| Dataset Creation | ADF Activity Log | New dataset targeting "exfiltrated" container |
| SP Authentication | Azure AD Sign-in Logs | Data Factory Contributor SP from unusual location |
| Blob Writes | Storage Analytics | ADF runtime writing to unexpected containers |

&nbsp;

## Remediation Guidance

1. **Data Factory Access Control**
   - Restrict Data Factory Contributor to CI/CD service connections only
   - Use Azure DevOps or GitHub pipelines for ADF deployments (not direct ARM API)
   - Implement approval workflows for pipeline changes

2. **Pipeline Monitoring**
   - Alert on new pipeline creation or modification
   - Monitor pipeline runs for unexpected source/sink combinations
   - Implement ADF diagnostic logging to Log Analytics

3. **Linked Service Security**
   - Use Key Vault references for all linked service credentials
   - Restrict Data Factory MI permissions to minimum required
   - Audit which identities can access linked service definitions

4. **Data Protection**
   - Implement Cosmos DB access controls (RBAC, firewall)
   - Use private endpoints for Cosmos DB and Storage
   - Monitor for unusual data transfer volumes
