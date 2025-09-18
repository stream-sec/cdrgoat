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
  }
}

provider "aws" {
  region = "us-east-1"
}

#######################################
# [1] Ensure Lambda folder exists
#######################################

resource "null_resource" "prepare_lambda_folder" {
  provisioner "local-exec" {
    command = "mkdir -p lambda"
  }
}

#######################################
# [2] IAM Users
#######################################

resource "aws_iam_user" "neo" {
  name = "StreamGoat-User-neo"
}

resource "aws_iam_user" "peter" {
  name = "StreamGoat-User-peter"
}

resource "aws_iam_user" "john" {
  name = "StreamGoat-User-john"
}

resource "aws_iam_user" "maria" {
  name = "StreamGoat-User-maria"
}

#######################################
# [3] Shared IAM Policy for Neo, Peter, John
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
  name   = "StreamGoat-Policy-basic"
  user   = aws_iam_user.neo.name
  policy = data.aws_iam_policy_document.limited_user_policy.json
}

resource "aws_iam_user_policy" "shared_policy_peter" {
  name   = "StreamGoat-Policy-basic"
  user   = aws_iam_user.peter.name
  policy = data.aws_iam_policy_document.limited_user_policy.json
}

resource "aws_iam_user_policy" "shared_policy_john" {
  name   = "StreamGoat-Policy-basic"
  user   = aws_iam_user.john.name
  policy = data.aws_iam_policy_document.limited_user_policy.json
}

#######################################
# [4] Maria = Full Admin
#######################################

resource "aws_iam_user_policy_attachment" "maria_admin" {
  user       = aws_iam_user.maria.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

#######################################
# [5] Leaked Access Key for Neo
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
# [6] Lambda IAM Role + Permissions
#######################################

resource "aws_iam_role" "lambda_exec_role" {
  name = "StreamGoat-Lambda-ExecRole"

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
  name = "StreamGoat-Policy-lambda-create"
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
# [7] Inline Lambda Python Code
#######################################

resource "local_file" "lambda_source" {
  depends_on = [null_resource.prepare_lambda_folder]
  filename   = "${path.module}/lambda/index.py"

  content = <<EOT
import boto3
import random
import string

def handler(event, context):
    iam = boto3.client('iam')

    rand_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=5))
    user_name = f"StreamGoat-User-{rand_suffix}"
    group_name = f"StreamGoat-Group-{rand_suffix}"

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
# [8] Lambda Function Deployment
#######################################

resource "aws_lambda_function" "streamgoat_lambda" {
  function_name = "StreamGoat-Lambda-mgmt"
  role          = aws_iam_role.lambda_exec_role.arn
  handler       = "index.handler"
  runtime       = "python3.10"

  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  depends_on = [
    aws_iam_role_policy.lambda_permissions
  ]
}
