# 7. Leaked AWS Key to RDS via Lambda Abuse

## Overview
This scenario demonstrates how a leaked AWS access key with limited Lambda permissions can be escalated into a full database compromise.
Starting with credentials that allow only Lambda `list` and `describe` actions, the attacker enumerates functions and inspects environment variables to discover a second AWS key embedded in a function. That second credential carries RDS manipulation privileges, enabling the attacker to enumerate databases, create a backup and restore it as a publicly accessible instance, change the database password, and connect directly to the exposed RDS, gaining persistent access to sensitive information.
This exercise highlights the dangers of poor secret management, overly permissive IAM roles, and insecure RDS configurations that allow chaining of weak access into full database compromise.

&nbsp;

## Required Resources

**Networking**
- 1 x VPC — private and public subnets
- Security Group — allows RDS connectivity

**Compute**
- Lambda function — stores AWS keys in environment variables

**Serverless**
- Lambda — permissions to list/describe RDS

**Storage / Database**
- RDS instance — stores sensitive data, manipulated by attacker

**IAM / Identities & Access**
- Leaked AWS key — Lambda list/describe permissions
- IAM role for Lambda — contains AWS key in environment variables
- Secondary IAM role — RDS manipulation permissions

&nbsp;

## Scenario Goals
Simulate abuse of leaked AWS credentials, escalation from Lambda to RDS, and the impact of unauthorized database access and manipulation.

&nbsp;

## Diagram
![Diagram](./diagram.png)

&nbsp;

## Attack Walkthrough
1. **Initial access** — Attacker obtains AWS key with Lambda permissions.
2. **Enumeration** — Use the key to list and describe Lambda functions.
3. **Credential discovery** — Extract environment variables to reveal a second AWS key.
4. **Privilege escalation** — Second key grants RDS manipulation permissions.
5. **Database reconnaissance** — List available RDS databases.
6. **Exposure** — Create backup, restore as public instance, and change password.
7. **Access** — Connect to the exposed RDS database.

&nbsp;

## Expected Results
- RDS instance exposed and accessed with modified credentials
- AWS credentials extracted from Lambda environment variables
- Snapshot created, restored as publicly accessible instance
- Data exfiltrated from compromised database

&nbsp;

## Getting Started

#### Install Dependencies

MacOS
```bash
brew install terraform awscli jq mysql-client
```
Linux
```bash
sudo apt update && sudo apt install -y terraform awscli jq mysql-client
```

#### Deploy

Use the provided Terraform configuration to deploy the full lab environment. Add the public IP (or CIDR) of your attack machine to the whitelist so the script can connect to the restored RDS instance.

```bash
terraform init
terraform apply -var='attack_whitelist=["87.68.140.7/32"]' -auto-approve
```

#### Get Output Values

After deployment, retrieve the leaked credentials to use with the attack script:

```bash
terraform output --json | jq -r '"ACCESS KEY ID: \(.streamgoat_eva_access_key_id.value) \nACCESS SECRET KEY: \(.streamgoat_eva_secret.value)"'
```

#### Attack Execution

Execute the attack script from your local terminal and use the output values provided at the end of the deployment as input parameters.

```bash
chmod +x attack.sh
./attack.sh
```

#### Clean Up

Destroy all resources to avoid ongoing costs.

```bash
terraform destroy -auto-approve
```
