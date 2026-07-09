############################
# Terraform: AWS Attack Path Scenario 5 – Leaked Keys → Lambda Code Injection → CreateAccessKey
############################

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }

    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
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

locals {
  prefix = "StreamGoat-aws5"
  suffix = random_id.suffix.hex
}

#######################################
# [1] IAM Users
#######################################

resource "aws_iam_user" "neo" {
  name = "${local.prefix}-User-neo-${local.suffix}"
}

resource "aws_iam_user" "peter" {
  name = "${local.prefix}-User-peter-${local.suffix}"
}

resource "aws_iam_user" "john" {
  name = "${local.prefix}-User-john-${local.suffix}"
}

resource "aws_iam_user" "maria" {
  name = "${local.prefix}-User-maria-${local.suffix}"
}

#######################################
# [2] Shared IAM Policy for Neo, Peter, John
#######################################

data "aws_iam_policy_document" "limited_user_policy" {
  statement {
    sid    = "SelfOnlyIamAccess"
    effect = "Allow"
    actions = [
      "iam:GetUser",
      "iam:GetUserPolicy",
      "iam:ListUserPolicies",
      "iam:ListAttachedUserPolicies"
    ]
    resources = [
      "arn:aws:iam::*:user/$${aws:username}"
    ]
  }

  statement {
    sid    = "LambdaAccess"
    effect = "Allow"
    actions = [
      "lambda:*"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_user_policy" "shared_policy_neo" {
  name   = "${local.prefix}-Policy-basic-${local.suffix}"
  user   = aws_iam_user.neo.name
  policy = data.aws_iam_policy_document.limited_user_policy.json
}

resource "aws_iam_user_policy" "shared_policy_peter" {
  name   = "${local.prefix}-Policy-basic-${local.suffix}"
  user   = aws_iam_user.peter.name
  policy = data.aws_iam_policy_document.limited_user_policy.json
}

resource "aws_iam_user_policy" "shared_policy_john" {
  name   = "${local.prefix}-Policy-basic-${local.suffix}"
  user   = aws_iam_user.john.name
  policy = data.aws_iam_policy_document.limited_user_policy.json
}

#######################################
# [3] Maria = Full Admin
#######################################

resource "aws_iam_user_policy_attachment" "maria_admin" {
  user       = aws_iam_user.maria.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

#######################################
# [4] Leaked Access Key for Neo
#######################################

resource "aws_iam_access_key" "neo_access_key" {
  user = aws_iam_user.neo.name
}

output "neo_access_key_id" {
  value     = aws_iam_access_key.neo_access_key.id
  sensitive = true
}

output "neo_secret_access_key" {
  value     = aws_iam_access_key.neo_access_key.secret
  sensitive = true
}

#######################################
# [5] Lambda IAM Role + Permissions
#######################################

resource "aws_iam_role" "lambda_exec_role" {
  name = "${local.prefix}-Lambda-ExecRole-${local.suffix}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = {
        Service = "lambda.amazonaws.com"
      },
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "lambda_permissions" {
  name = "${local.prefix}-Policy-lambda-create-${local.suffix}"
  role = aws_iam_role.lambda_exec_role.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "iam:Create*",
          "iam:Delete*"
        ],
        Resource = "*"
      }
    ]
  })
}

#######################################
# [6] Inline Lambda Python Code
#######################################

resource "local_file" "lambda_source" {
  filename = "${path.module}/lambda/index.py"

  content = <<EOT
import boto3
import random
import string

def handler(event, context):
    iam = boto3.client('iam')

    rand_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=5))
    user_name = f"${local.prefix}-User-{rand_suffix}"
    group_name = f"${local.prefix}-Group-{rand_suffix}"

    # Create user
    user = iam.create_user(UserName=user_name)

    # Create group
    group = iam.create_group(GroupName=group_name)

    return {
        "user": user,
        "group": group
    }
EOT
}

data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/lambda"
  output_path = "${path.module}/lambda_payload.zip"

  depends_on = [local_file.lambda_source]
}

#######################################
# [7] Lambda Function Deployment
#######################################

resource "aws_lambda_function" "streamgoat_lambda" {
  function_name = "${local.prefix}-Lambda-mgmt-${local.suffix}"
  role          = aws_iam_role.lambda_exec_role.arn
  handler       = "index.handler"
  runtime       = "python3.10"

  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  depends_on = [
    aws_iam_role_policy.lambda_permissions
  ]
}
