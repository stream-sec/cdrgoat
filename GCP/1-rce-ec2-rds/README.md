# 1. RCE on VM to CloudSQL Pivot

## 🗺️ Overview
This scenario demonstrates a multi-stage GCP compromise in which an attacker exploits a remote code execution vulnerability in a public web application hosted on Virtual Machine A. Leveraging the instance’s IAM role credentials obtained from the metadata service, then enumerate the environment and identify another Virtual Machine. By injecting an SSH key into VM metadata, attacker pivot into Virtual Machine B, where he uncover credentials and connection details for an CloudSQL database. Using this access, the attacker connects to the database and exfiltrates sensitive data. This exercise highlights how exposed services, weak segmentation between public and private resources, and over-permissive IAM roles can be chained together, public exposure, IAM credential misuse, and poor network design, culminating in full compromise of sensitive information inside Google cloud.

&nbsp;

## 🧩 Required Resources

**Networking**
- 1 default network, single region
- Subnets - 1 private

**Compute**
- VM-A - Public web server (vulnerable web application, internet-facing)
- VM-B - Second instance for internal purposes but internet-facing

**Database / Storage**
- CloudSQL - Internal database storing sensitive data

**IAM / Service Accounts and Roles**
- Service Accounts assigned to VM-A with permissions to list instances and modify their Metadata

&nbsp;

## 🎯 Scenario Goals
The attacker’s objective is to compromise an internet-exposed VM instance, use its permissions to gain access to an internal VM host, and ultimately reach an CloudSQL database to exfiltrate sensitive data stored within it.

&nbsp;

## 🗡️ Attack Walkthrough
- **Initial Access** – Exploit a vulnerable web application on VM-A to achieve remote code execution.
- **Credential Harvesting** – Obtain IAM role credentials from the instance metadata service.
- **Enumeration** – Use the stolen credentials to list VM instances and identify VM-B within the VPC.
- **Pivoting** – Push an SSH public key via VM Instance Connect to gain access to VM-B.
- **Database Access** – Extract CloudSQL connection details from VM-B for credentials exfiltration.
- **Data Retrieval** – Connect to the CloudSQL database and retrieve the sensitive data.

&nbsp;

## 📈 Expected Results
**Successful Completion** - Sensitive data retrieved from CloudSQL.

&nbsp;

## 🚀 Getting Started

#### Install Dependencies

MacOS
```bash
brew install terraform jq
```
Linux
```bash
sudo apt update && sudo apt install -y terraform jq
```

To install **gcloud** cli tool please check official documentation: https://docs.cloud.google.com/sdk/docs/install

#### Deploy

Before deploying, download the provided Terraform configuration and Attack Script to the machine where you will run the attack steps.

Use the provided Terraform configuration to deploy the full lab environment.

At the end of the deployment Terraform will display output values (e.g. public IP address of the target instance). Save these details, you will need them to run the attack script in the next stage.

⚠️ When a scenario’s initial step targets a public IP, add the public IP (or CIDR) of the machine that will run the attack script to the environment whitelist via terraform apply so the script can reach the target and complete any required interactions. See example

```bash
terraform init
terraform apply -var='attack_whitelist=["87.68.140.7/32","203.0.113.0/24"]' -auto-approve
```

#### Attack Execution
Execute the attack script from your local terminal and use the output values provided at the end of the deployment as input parameters.

```bash
chmod +x attack.sh
./attack.sh
```

#### 🧹 Clean Up
When you are finished, destroy all resources to avoid ongoing costs. This will tear down the entire lab environment including all compute, networking, and IAM components created during deployment.
Use the following command for a full cleanup

```bash
terraform destroy -var='attack_whitelist=[]' -auto-approve
```