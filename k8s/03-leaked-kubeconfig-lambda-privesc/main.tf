terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

resource "random_string" "sfx" {
  length  = 4
  upper   = false
  special = false
  numeric = true
}

variable "eks_cluster_name" {
  description = "Name of the EKS cluster"
  type        = string
}

variable "namespace" {
  description = "K8s namespace for the scenario"
  type        = string
  default     = "cdrgoat-sc03"
}

variable "service_account_name" {
  description = "K8s service account name"
  type        = string
  default     = "dev-deployer-sa"
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

data "aws_eks_cluster" "cluster" {
  name = var.eks_cluster_name
}

#######################################
# OIDC provider for IRSA
#######################################

locals {
  oidc_url      = data.aws_eks_cluster.cluster.identity[0].oidc[0].issuer
  oidc_provider = replace(local.oidc_url, "https://", "")
}

data "aws_iam_openid_connect_provider" "cluster" {
  url = local.oidc_url
}

#######################################
# IRSA role for the pod
# Over-permissioned: Lambda + IAM enum + PassRole
#######################################

resource "aws_iam_role" "irsa_pod_role" {
  name = "StreamGoat-k8s03-PodIRSA-${random_string.sfx.result}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = data.aws_iam_openid_connect_provider.cluster.arn
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "${local.oidc_provider}:sub" = "system:serviceaccount:${var.namespace}:${var.service_account_name}"
          "${local.oidc_provider}:aud" = "sts.amazonaws.com"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "irsa_pod_perms" {
  name = "StreamGoat-k8s03-PodPerms-${random_string.sfx.result}"
  role = aws_iam_role.irsa_pod_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "IAMEnumeration"
        Effect = "Allow"
        Action = [
          "iam:ListRoles",
          "iam:ListRolePolicies",
          "iam:GetRolePolicy",
          "iam:ListAttachedRolePolicies",
          "iam:GetRole",
          "sts:GetCallerIdentity"
        ]
        Resource = "*"
      },
      {
        Sid    = "LambdaPerms"
        Effect = "Allow"
        Action = [
          "lambda:CreateFunction",
          "lambda:InvokeFunction",
          "lambda:DeleteFunction",
          "lambda:GetFunction"
        ]
        Resource = "arn:aws:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:function:StreamGoat-k8s03-*"
      },
      {
        Sid    = "PassRoleToLambda"
        Effect = "Allow"
        Action = "iam:PassRole"
        Resource = aws_iam_role.lambda_privesc_role.arn
      }
    ]
  })
}

#######################################
# Lambda execution role - the privesc vector
# Has iam:AttachRolePolicy
#######################################

resource "aws_iam_role" "lambda_privesc_role" {
  name = "StreamGoat-k8s03-LambdaExecRole-${random_string.sfx.result}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "lambda_privesc_perms" {
  name = "StreamGoat-k8s03-LambdaPrivEsc-${random_string.sfx.result}"
  role = aws_iam_role.lambda_privesc_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "PrivEscVector"
        Effect = "Allow"
        Action = "iam:AttachRolePolicy"
        Resource = "*"
      },
      {
        Sid    = "BasicLambdaLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

#######################################
# Outputs
#######################################

output "irsa_role_arn" {
  value = aws_iam_role.irsa_pod_role.arn
}

output "irsa_role_name" {
  value = aws_iam_role.irsa_pod_role.name
}

output "lambda_privesc_role_arn" {
  value = aws_iam_role.lambda_privesc_role.arn
}

output "lambda_privesc_role_name" {
  value = aws_iam_role.lambda_privesc_role.name
}
