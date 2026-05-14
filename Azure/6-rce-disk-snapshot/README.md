# 6. RCE on VM → Disk Snapshot Pivot → Secret Extraction from Private VM

## Overview
This scenario demonstrates a disk snapshot attack — a technique used by advanced threat actors (including NOBELIUM/Midnight Blizzard) to bypass network segmentation and extract secrets from isolated virtual machines. The attacker exploits an RCE vulnerability on a public-facing VM, steals its Managed Identity token (Contributor on the Resource Group), and discovers a backend VM on a private subnet with no public IP and strict NSG rules. Unable to reach it via the network, the attacker creates a snapshot of the backend VM's OS disk, creates a new managed disk from the snapshot, attaches it to the compromised VM, and mounts it to extract secrets — including Service Principal credentials used to compromise user identities.

&nbsp;

## Required Resources

**Identity & Access**
- User-Assigned Managed Identity with Contributor on Resource Group
- App Registration with User.ReadWrite.All on Microsoft Graph (pre-seeded on backend VM)
- Target Azure AD user (for password reset demonstration)

**Compute**
- Public VM with RCE-vulnerable web app (public subnet, port 8080)
- Private VM with secrets on filesystem (private subnet, no public IP)

**Networking**
- VNet with public and private subnets
- NSGs enforcing network isolation (deny all inbound to private subnet)

&nbsp;

## Scenario Goals
Demonstrate that network segmentation alone is insufficient when an attacker has control-plane (ARM) access. Disk-level operations bypass all network controls.

&nbsp;

## Diagram
![Diagram](./diagram.png)

&nbsp;

## Attack Walkthrough

### Phase 1: Initial Access
- **RCE Exploitation** — Command injection via `/cmd?c=` on the public VM
- **IMDS Token Theft** — Steal Managed Identity ARM token from 169.254.169.254

### Phase 2: Reconnaissance
- **Resource Enumeration** — List all resources in the Resource Group
- **Backend VM Discovery** — Identify a private VM with no public IP
- **Network Isolation Confirmed** — Verify the backend VM is unreachable via network

### Phase 3: Disk Snapshot Attack
- **OS Disk Identification** — Get the backend VM's OS disk resource ID
- **Snapshot Creation** — Create a snapshot of the OS disk using Contributor permissions
- **Disk Creation** — Create a new managed disk from the snapshot
- **Disk Attachment** — Attach the new disk to the compromised public VM

### Phase 4: Secret Extraction
- **Mount Disk** — Mount the stolen disk via RCE on the public VM
- **Filesystem Browsing** — Navigate to sensitive paths on the mounted disk
- **Secret Extraction** — Read SP credentials, database passwords, SSH keys

### Phase 5: Identity Compromise
- **SP Authentication** — Authenticate with extracted App Registration credentials
- **User Enumeration** — List Azure AD users via Graph API
- **Password Reset** — Reset a target user's password using User.ReadWrite.All

&nbsp;

## Expected Results
**Successful Completion** — Network-isolated VM's secrets are extracted via disk snapshot. Extracted SP credentials are used to compromise an Azure AD user identity.

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
terraform apply -var='attack_whitelist=["<your_ip>/32"]' -auto-approve
```

After deployment, note the outputs:

```bash
terraform output public_vm_ip
terraform output mi_client_id
```

#### Attack Execution

```bash
chmod +x attack.sh
./attack.sh
```

The script will prompt for the public VM IP and MI Client ID, then execute the full attack chain.

#### Clean Up

The attack script will offer to clean up attack-created resources (snapshot, disk). After cleanup:

```bash
terraform destroy -var='attack_whitelist=[]' -auto-approve
```

&nbsp;

## Detection Opportunities

| Signal | Service | Description |
|--------|---------|-------------|
| Disk Snapshot Creation | Activity Log | Snapshot of another VM's disk by a Managed Identity |
| Disk Attachment | Activity Log | New data disk attached to a running VM |
| Managed Disk Creation | Activity Log | Disk created from snapshot (Copy source) |
| IMDS Token Request | VM-level | Token request for ARM management |
| SP Authentication | Azure AD Sign-in Logs | client_credentials from unexpected SP |
| Password Reset | Azure AD Audit Logs | User password changed by application identity |

&nbsp;

## Remediation Guidance

1. **Disk Operation Controls**
   - Use Azure Policy to restrict snapshot creation on sensitive VMs
   - Monitor for disk operations performed by compute identities
   - Consider encrypting VM disks with customer-managed keys + key access policies

2. **Managed Identity Permissions**
   - Avoid granting Contributor broadly — use specific roles
   - Disk snapshot requires `Microsoft.Compute/disks/read` + `Microsoft.Compute/snapshots/write`
   - Create custom roles that exclude disk/snapshot operations

3. **Secret Management**
   - Never store credentials on VM filesystems
   - Use Azure Key Vault with Managed Identity access
   - Rotate credentials stored on compute resources

4. **Monitoring**
   - Alert on snapshot creation from non-deployment identities
   - Track disk attachment/detachment events
   - Monitor for unusual ARM operations from VM Managed Identities
