# 11. RCE on App Service → ACR Image Pull → Embedded Secrets → Lateral Movement

## Overview
This scenario demonstrates how secrets embedded in container images can lead to cross-Resource Group lateral movement. The attacker exploits an RCE vulnerability on an Azure App Service, steals the Managed Identity's token (which has `AcrPull` on a Container Registry), pulls image layers from ACR, and discovers Service Principal credentials baked into a `.env` file within the image. The extracted SP has `Contributor` on a separate Resource Group containing sensitive financial data.

Embedding secrets in container images is one of the most common container security mistakes. Organizations treat ACR as "internal" and rarely scan images for secrets.

&nbsp;

## Required Resources

**Identity & Access**
- User-Assigned MI with AcrPull on ACR + Reader on main RG
- App Registration with credentials baked into a container image
- The App Registration SP has Contributor + Storage Blob Data Reader on target RG

**Compute**
- App Service (Linux, Python, B1) with RCE-vulnerable endpoint
- Azure Container Registry with image containing embedded secrets

**Storage**
- Storage Account in target RG with sensitive data blobs

&nbsp;

## Scenario Goals
Demonstrate the risk of embedding secrets in container images and the lateral movement potential when container registries are accessible to compute identities.

&nbsp;

## Diagram
![Diagram](./diagram.png)

&nbsp;

## Attack Walkthrough

### Phase 1: Initial Access
- **RCE Exploitation** — Command injection via `/exec?cmd=` on App Service
- **MI Token Theft** — Steal ARM token via identity endpoint or IMDS

### Phase 2: Registry Discovery
- **Resource Enumeration** — Find Azure Container Registry
- **ACR Authentication** — Exchange ARM token for ACR access token
- **Repository Listing** — Enumerate repositories and tags

### Phase 3: Image Layer Inspection
- **Manifest Pull** — Get image manifest with layer digests
- **Layer Download** — Download and extract layer tarballs via RCE
- **Secret Discovery** — Find `.env` file with SP credentials in image layer

### Phase 4: Lateral Movement
- **SP Authentication** — Use extracted credentials to authenticate
- **Cross-RG Access** — Discover resources in a different Resource Group
- **Data Exfiltration** — Download sensitive blobs from target storage

&nbsp;

## Expected Results
**Successful Completion** — SP credentials extracted from a container image enable cross-Resource Group access and financial data exfiltration.

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

Note the outputs:

```bash
terraform output app_service_url
terraform output mi_client_id
```

#### Attack Execution

```bash
chmod +x attack.sh
./attack.sh
```

#### Clean Up

```bash
terraform destroy -var='attack_whitelist=[]' -auto-approve
```

&nbsp;

## Detection Opportunities

| Signal | Service | Description |
|--------|---------|-------------|
| RCE Execution | App Service Logs | Shell command execution via web endpoint |
| ACR Pull | ACR Audit Logs | Image pull by App Service MI |
| ARM Token Exchange | ACR Logs | OAuth token exchange for ACR access |
| SP Authentication | Azure AD Sign-in Logs | Client credentials from unexpected SP |
| Cross-RG Access | Activity Log | Resource enumeration in different RG |
| Blob Download | Storage Analytics | Data reads from unexpected identity |

&nbsp;

## Remediation Guidance

1. **Container Image Security**
   - Never embed secrets in Docker images (use env vars or Key Vault at runtime)
   - Implement secret scanning in CI/CD pipelines (e.g., Trivy, GitLeaks)
   - Use multi-stage builds to prevent secret leakage in layers
   - Regularly scan ACR images for vulnerabilities and secrets

2. **ACR Access Control**
   - Restrict AcrPull to identities that actually need it
   - Use private endpoints for ACR
   - Enable content trust for image signing

3. **App Service Security**
   - Validate input to prevent command injection
   - Use managed identity with minimal permissions
   - Enable App Service diagnostics and alerting

4. **Monitoring**
   - Alert on ACR pulls from non-container compute
   - Track cross-RG access patterns
   - Monitor SP authentication from unexpected sources
