#terraform apply -auto-approve

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# IAM User
resource "aws_iam_user" "leaked_user" {
  name = "peter.parker"
}

resource "random_id" "secret_suffix" {
  byte_length = 2
}

# Helpdesk Group
resource "aws_iam_group" "helpdesk" {
  name = "StreamGoat-Group-helpdesk"
}

# Attach User to Helpdesk Group
resource "aws_iam_group_membership" "leaked_user_helpdesk" {
  name  = "leaked-helpdesk-membership"
  users = [aws_iam_user.leaked_user.name]
  group = aws_iam_group.helpdesk.name
}

# Policy for Helpdesk Group
resource "aws_iam_policy" "helpdesk_policy" {
  name   = "StreamGoatHelpdeskPolicy"
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
        Resource = "arn:aws:iam::*:group/StreamGoat-Group-*"
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
        Resource = "arn:aws:iam::*:group/StreamGoat-Group-*"
      },
      {
        Sid    = "AllowReadStreamGoatManagedPolicies",
        Effect = "Allow",
        Action = [
          "iam:GetPolicy",
          "iam:GetPolicyVersion"
        ],
        Resource = "arn:aws:iam::*:policy/StreamGoat*"
      }
    ]
  })
}

resource "aws_iam_group_policy_attachment" "helpdesk_attach" {
  group      = aws_iam_group.helpdesk.name
  policy_arn = aws_iam_policy.helpdesk_policy.arn
}

# Secret Readers Group
resource "aws_iam_group" "secretreaders" {
  name = "StreamGoat-Group-secretreaders"
}

# Secret Reader Policy
resource "aws_iam_policy" "secretreader_policy" {
  name = "StreamGoatSecretReader"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        "Sid": "AllowReadStreamGoatSecrets",
        "Effect": "Allow",
        "Action": "secretsmanager:GetSecretValue",
        "Resource": "arn:aws:secretsmanager:*:*:secret:StreamGoat-*"
      },
      {
        "Sid": "AllowListSecretsGlobally",
        "Effect": "Allow",
        "Action": "secretsmanager:ListSecrets",
        "Resource": "*"
      }
    ]
  })
}

resource "aws_iam_group_policy_attachment" "secretreader_attach" {
  group      = aws_iam_group.secretreaders.name
  policy_arn = aws_iam_policy.secretreader_policy.arn
}

# Secret
resource "aws_secretsmanager_secret" "streamgoat_secret1" {
  name = "StreamGoat-DB-PROD-${random_id.secret_suffix.hex}"
}

resource "aws_secretsmanager_secret_version" "streamgoat_secret1_version" {
  secret_id     = aws_secretsmanager_secret.streamgoat_secret1.id
  secret_string = jsonencode({
    username = "admin",
    password = "N0t4nE@syGuess"
  })
}

# Output Leaked Credentials
resource "aws_iam_access_key" "leaked_key" {
  user = aws_iam_user.leaked_user.name
}

output "leaked_user_access_key_id" {
  value = aws_iam_access_key.leaked_key.id
  sensitive = true
}

output "leaked_user_secret_access_key" {
  value     = aws_iam_access_key.leaked_key.secret
  sensitive = true
}
