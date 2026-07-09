############################
# Terraform: AWS Attack Path Scenario 4 – Helpdesk User → Group PrivEsc → Secret Exfiltration
############################

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.5"
    }
  }
}

provider "aws" {
  region = var.region
}

############################
# Variables
############################

variable "region" {
  type    = string
  default = "us-east-1"
}

############################
# Random suffix + locals
############################

resource "random_id" "suffix" {
  byte_length = 4
}

resource "random_id" "secret_suffix" {
  byte_length = 2
}

locals {
  prefix = "StreamGoat-aws4"
  suffix = random_id.suffix.hex
}

############################
# IAM User
############################

resource "aws_iam_user" "leaked_user" {
  name = "${local.prefix}-peter.parker-${local.suffix}"
}

############################
# IAM Groups
############################

resource "aws_iam_group" "helpdesk" {
  name = "${local.prefix}-Group-helpdesk-${local.suffix}"
}

resource "aws_iam_group_membership" "leaked_user_helpdesk" {
  name  = "leaked-helpdesk-membership"
  users = [aws_iam_user.leaked_user.name]
  group = aws_iam_group.helpdesk.name
}

resource "aws_iam_policy" "helpdesk_policy" {
  name = "${local.prefix}-HelpdeskPolicy-${local.suffix}"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid      = "AllowSelfGroupCheck",
        Effect   = "Allow",
        Action   = "iam:ListGroupsForUser",
        Resource = "*"
      },
      {
        Sid      = "AllowAddUserToStreamGoatGroups",
        Effect   = "Allow",
        Action   = "iam:AddUserToGroup",
        Resource = "arn:aws:iam::*:group/${local.prefix}-Group-*"
      },
      {
        Sid    = "AllowReadPoliciesOnStreamGoatGroups",
        Effect = "Allow",
        Action = [
          "iam:ListGroupPolicies",
          "iam:GetGroupPolicy",
          "iam:ListAttachedGroupPolicies",
          "iam:GetPolicy",
          "iam:GetPolicyVersion"
        ],
        Resource = "arn:aws:iam::*:group/${local.prefix}-Group-*"
      },
      {
        Sid    = "AllowReadStreamGoatManagedPolicies",
        Effect = "Allow",
        Action = [
          "iam:GetPolicy",
          "iam:GetPolicyVersion"
        ],
        Resource = "arn:aws:iam::*:policy/${local.prefix}*"
      }
    ]
  })
}

resource "aws_iam_group_policy_attachment" "helpdesk_attach" {
  group      = aws_iam_group.helpdesk.name
  policy_arn = aws_iam_policy.helpdesk_policy.arn
}

resource "aws_iam_group" "secretreaders" {
  name = "${local.prefix}-Group-secretreaders-${local.suffix}"
}

resource "aws_iam_policy" "secretreader_policy" {
  name = "${local.prefix}-SecretReader-${local.suffix}"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid      = "AllowReadStreamGoatSecrets",
        Effect   = "Allow",
        Action   = "secretsmanager:GetSecretValue",
        Resource = "arn:aws:secretsmanager:*:*:secret:${local.prefix}-*"
      },
      {
        Sid      = "AllowListSecretsGlobally",
        Effect   = "Allow",
        Action   = "secretsmanager:ListSecrets",
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_group_policy_attachment" "secretreader_attach" {
  group      = aws_iam_group.secretreaders.name
  policy_arn = aws_iam_policy.secretreader_policy.arn
}

############################
# Secrets Manager
############################

resource "aws_secretsmanager_secret" "streamgoat_secret1" {
  name = "${local.prefix}-DB-PROD-${random_id.secret_suffix.hex}"
}

resource "aws_secretsmanager_secret_version" "streamgoat_secret1_version" {
  secret_id = aws_secretsmanager_secret.streamgoat_secret1.id
  secret_string = jsonencode({
    username = "admin",
    password = "N0t4nE@syGuess"
  })
}

############################
# Access Keys + Outputs
############################

resource "aws_iam_access_key" "leaked_key" {
  user = aws_iam_user.leaked_user.name
}

output "leaked_user_access_key_id" {
  value     = aws_iam_access_key.leaked_key.id
  sensitive = true
}

output "leaked_user_secret_access_key" {
  value     = aws_iam_access_key.leaked_key.secret
  sensitive = true
}
