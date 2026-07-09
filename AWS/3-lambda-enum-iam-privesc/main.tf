############################
# Terraform: AWS Attack Path Scenario 3 – Leaked Keys → Lambda Code Injection → PrivEsc
############################

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.4"
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
# Random suffix for parallel deployments
############################

resource "random_id" "suffix" {
  byte_length = 4
}

############################
# Data
############################

data "aws_caller_identity" "current" {}

locals {
  prefix     = "StreamGoat-aws3"
  suffix     = random_id.suffix.hex
  account_id = data.aws_caller_identity.current.account_id
}

############################
# Lambda Source (inline)
############################

resource "local_file" "lambda1_py" {
  filename = "${path.module}/lambda1/index.py"
  content  = <<-PY
import json, random

def handler(event, context):
    n = f"{random.randint(0, 99999999):08d}"
    return {"random8": n}
PY
}

data "archive_file" "lambda1_zip" {
  type        = "zip"
  output_path = "${path.module}/lambda1.zip"
  source_dir  = "${path.module}/lambda1"
  depends_on  = [local_file.lambda1_py]
}

resource "local_file" "lambda2_py" {
  filename = "${path.module}/lambda2/index.py"
  content  = <<-PY
import json, random

def handler(event, context):
    n = f"{random.randint(0, 99999999):08d}"
    return {"random8": n}
PY
}

data "archive_file" "lambda2_zip" {
  type        = "zip"
  output_path = "${path.module}/lambda2.zip"
  source_dir  = "${path.module}/lambda2"
  depends_on  = [local_file.lambda2_py]
}

############################
# IAM Policies
############################

resource "aws_iam_policy" "policy_user" {
  name        = "${local.prefix}-Policy-user-${local.suffix}"
  description = "User can enumerate IAM and Lambda; full lambda:* except CreateFunction (explicit Deny)."
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid      = "IamReadOnly"
        Effect   = "Allow"
        Action   = ["iam:List*", "iam:Get*"]
        Resource = "*"
      },
      {
        Sid      = "LambdaAll"
        Effect   = "Allow"
        Action   = ["lambda:*"]
        Resource = "*"
      },
      {
        Sid      = "DenyCreateFunction"
        Effect   = "Deny"
        Action   = ["lambda:CreateFunction"]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_policy" "policy_admin" {
  name        = "${local.prefix}-Policy-admin-${local.suffix}"
  description = "Admin policy: * on *"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = "*",
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_policy" "policy_dev" {
  name        = "${local.prefix}-Policy-dev-${local.suffix}"
  description = "Dev can do lambda:*"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = ["lambda:*"],
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_policy" "policy_engineer" {
  name        = "${local.prefix}-Policy-engineer-${local.suffix}"
  description = "Engineer/IT can do ec2:*, s3:*, lambda:*"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = ["ec2:*", "s3:*", "lambda:*"],
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_policy" "policy_marketing" {
  name        = "${local.prefix}-Policy-marketing-${local.suffix}"
  description = "Marketing can list/get S3"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = ["s3:List*", "s3:Get*"],
        Resource = "*"
      }
    ]
  })
}

############################
# Lambda Execution Roles
############################

resource "aws_iam_role" "lambda1_exec_role" {
  name = "${local.prefix}-Lambda1-ExecRole-${local.suffix}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect    = "Allow",
        Principal = { Service = "lambda.amazonaws.com" },
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role" "lambda2_exec_role" {
  name = "${local.prefix}-Lambda2-ExecRole-${local.suffix}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect    = "Allow",
        Principal = { Service = "lambda.amazonaws.com" },
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda1_basic_logs" {
  role       = aws_iam_role.lambda1_exec_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "lambda2_basic_logs" {
  role       = aws_iam_role.lambda2_exec_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_policy" "lambda2_assume_role_policy" {
  name        = "${local.prefix}-Lambda2-Assume-StreamGoat-Roles-${local.suffix}"
  description = "Lambda_2 can AssumeRole on any role named StreamGoat-aws3-* in this account."
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = ["sts:AssumeRole"],
        Resource = "arn:aws:iam::${local.account_id}:role/${local.prefix}-*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda2_attach_assume" {
  role       = aws_iam_role.lambda2_exec_role.name
  policy_arn = aws_iam_policy.lambda2_assume_role_policy.arn
}

############################
# Target Roles (trust Lambda_2 exec role)
############################

locals {
  trust_lambda2 = {
    Version = "2012-10-17",
    Statement = [
      {
        Effect    = "Allow",
        Principal = { AWS = aws_iam_role.lambda2_exec_role.arn },
        Action    = "sts:AssumeRole"
      }
    ]
  }
}

resource "aws_iam_role" "role_user" {
  name               = "${local.prefix}-Role-user-${local.suffix}"
  assume_role_policy = jsonencode(local.trust_lambda2)
}

resource "aws_iam_role" "role_admin" {
  name               = "${local.prefix}-Role-admin-${local.suffix}"
  assume_role_policy = jsonencode(local.trust_lambda2)
}

resource "aws_iam_role" "role_dev" {
  name               = "${local.prefix}-Role-dev-${local.suffix}"
  assume_role_policy = jsonencode(local.trust_lambda2)
}

resource "aws_iam_role" "role_engineer" {
  name               = "${local.prefix}-Role-engineer-${local.suffix}"
  assume_role_policy = jsonencode(local.trust_lambda2)
}

resource "aws_iam_role" "role_marketing" {
  name               = "${local.prefix}-Role-marketing-${local.suffix}"
  assume_role_policy = jsonencode(local.trust_lambda2)
}

resource "aws_iam_role_policy_attachment" "attach_user" {
  role       = aws_iam_role.role_user.name
  policy_arn = aws_iam_policy.policy_user.arn
}

resource "aws_iam_role_policy_attachment" "attach_admin" {
  role       = aws_iam_role.role_admin.name
  policy_arn = aws_iam_policy.policy_admin.arn
}

resource "aws_iam_role_policy_attachment" "attach_dev" {
  role       = aws_iam_role.role_dev.name
  policy_arn = aws_iam_policy.policy_dev.arn
}

resource "aws_iam_role_policy_attachment" "attach_engineer" {
  role       = aws_iam_role.role_engineer.name
  policy_arn = aws_iam_policy.policy_engineer.arn
}

resource "aws_iam_role_policy_attachment" "attach_marketing" {
  role       = aws_iam_role.role_marketing.name
  policy_arn = aws_iam_policy.policy_marketing.arn
}

############################
# Lambda Functions
############################

resource "aws_lambda_function" "lambda1" {
  function_name    = "${local.prefix}-Lambda_1-${local.suffix}"
  role             = aws_iam_role.lambda1_exec_role.arn
  handler          = "index.handler"
  runtime          = "python3.12"
  filename         = data.archive_file.lambda1_zip.output_path
  source_code_hash = data.archive_file.lambda1_zip.output_base64sha256
  timeout          = 10
}

resource "aws_lambda_function" "lambda2" {
  function_name    = "${local.prefix}-Lambda_2-${local.suffix}"
  role             = aws_iam_role.lambda2_exec_role.arn
  handler          = "index.handler"
  runtime          = "python3.12"
  filename         = data.archive_file.lambda2_zip.output_path
  source_code_hash = data.archive_file.lambda2_zip.output_base64sha256
  timeout          = 10
}

############################
# IAM User + Access Keys
############################

resource "aws_iam_user" "user" {
  name = "${local.prefix}-user-${local.suffix}"
  path = "/"
}

resource "aws_iam_user_policy_attachment" "user_attach_userpolicy" {
  user       = aws_iam_user.user.name
  policy_arn = aws_iam_policy.policy_user.arn
}

resource "aws_iam_access_key" "user_key" {
  user = aws_iam_user.user.name
}

############################
# Outputs
############################

output "streamgoat_user_access_key_id" {
  value     = aws_iam_access_key.user_key.id
  sensitive = true
}

output "streamgoat_user_secret_access_key" {
  value     = aws_iam_access_key.user_key.secret
  sensitive = true
}
