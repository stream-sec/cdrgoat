############################
# Terraform: AWS Attack Path Scenario 2 – SSRF → IMDS → Lambda PrivEsc
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

variable "vpc_cidr" {
  type    = string
  default = "10.0.0.0/16"
}

variable "public_subnet_cidr" {
  type    = string
  default = "10.0.1.0/24"
}

variable "private_subnet_cidr" {
  type    = string
  default = "10.0.2.0/24"
}

variable "ec2_instance_type" {
  type    = string
  default = "t2.micro"
}

variable "attack_whitelist" {
  description = "User's public IP address(es)"
  type        = list(string)
}

variable "ec2_ami" {
  type    = string
  default = ""
}

############################
# Random suffix for parallel deployments
############################

resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  prefix = "StreamGoat-aws2"
  suffix = random_id.suffix.hex
}

############################
# Data (latest Ubuntu 24.04 AMI)
############################

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

locals {
  ami_id = var.ec2_ami != "" ? var.ec2_ami : data.aws_ami.ubuntu.id
}

############################
# Networking
############################

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "${local.prefix}-vpc" }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${local.prefix}-igw" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_cidr
  map_public_ip_on_launch = true
  tags                    = { Name = "${local.prefix}-public-subnet" }
}

resource "aws_subnet" "private" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.private_subnet_cidr
  map_public_ip_on_launch = false
  tags                    = { Name = "${local.prefix}-private-subnet" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
  tags = { Name = "${local.prefix}-public-rt" }
}

resource "aws_route_table_association" "public_assoc" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

############################
# NAT Gateway (EC2-B internet access)
############################

resource "aws_eip" "nat_eip" {
  domain = "vpc"
  tags   = { Name = "${local.prefix}-nat-eip" }
}

resource "aws_nat_gateway" "nat" {
  subnet_id     = aws_subnet.public.id
  allocation_id = aws_eip.nat_eip.id
  tags          = { Name = "${local.prefix}-nat" }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat.id
  }
  tags = { Name = "${local.prefix}-private-rt" }
}

resource "aws_route_table_association" "private_assoc" {
  subnet_id      = aws_subnet.private.id
  route_table_id = aws_route_table.private.id
}

############################
# Security Groups
############################

resource "aws_security_group" "public_sg" {
  name                   = "${local.prefix}-public-sg"
  description            = "Allow HTTP and SSH from attacker IP"
  vpc_id                 = aws_vpc.main.id
  revoke_rules_on_delete = true

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.attack_whitelist
  }

  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = var.attack_whitelist
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${local.prefix}-public-sg" }
}

resource "aws_security_group" "private_sg" {
  name                   = "${local.prefix}-private-sg"
  description            = "Allow SSH from public subnet"
  vpc_id                 = aws_vpc.main.id
  revoke_rules_on_delete = true

  ingress {
    description     = "SSH from public SG"
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.public_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${local.prefix}-private-sg" }
}

############################
# IAM for EC2-A (JumpHost)
############################

data "aws_iam_policy_document" "ec2_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "jumphost_role" {
  name               = "${local.prefix}-JumpHostRole-${local.suffix}"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
}

resource "aws_iam_role_policy" "jumphost_policy" {
  name = "${local.prefix}-JumpHost-Policy"
  role = aws_iam_role.jumphost_role.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "ec2:DescribeInstances",
          "ssm:StartSession",
          "ssm:SendCommand",
          "ssm:DescribeSessions",
          "ssm:GetConnectionStatus",
          "ssm:DescribeInstanceProperties",
          "ssm:TerminateSession",
          "ssm:ResumeSession",
          "ssm:GetCommandInvocation"
        ],
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "jumphost_ssm_core" {
  role       = aws_iam_role.jumphost_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "jumphost_profile" {
  name = "${local.prefix}-JumpHostProfile-${local.suffix}"
  role = aws_iam_role.jumphost_role.name
}

############################
# IAM for EC2-B (Lambda Management)
############################

resource "aws_iam_role" "lambda_mgmt_role" {
  name               = "${local.prefix}-LambdaMgmt-Role-${local.suffix}"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
}

resource "aws_iam_role_policy" "lambda_mgmt_policy" {
  name = "${local.prefix}-LambdaMgmt-Policy"
  role = aws_iam_role.lambda_mgmt_role.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "lambda:InvokeFunction",
          "lambda:CreateFunction",
          "iam:PassRole",
          "iam:ListRoles",
          "iam:GetRole",
          "iam:ListRolePolicies",
          "iam:GetRolePolicy"
        ],
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_mgmt_ssm_core" {
  role       = aws_iam_role.lambda_mgmt_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "lambda_mgmt_profile" {
  name = "${local.prefix}-LambdaMgmtProfile-${local.suffix}"
  role = aws_iam_role.lambda_mgmt_role.name
}

############################
# IAM for Lambda (AttachRolePolicy)
############################

data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "attach_role_policy" {
  name               = "${local.prefix}-AttachRolePolicy-Role-${local.suffix}"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
}

resource "aws_iam_role_policy" "attach_role_policy" {
  name = "${local.prefix}-AttachRolePolicy-Policy"
  role = aws_iam_role.attach_role_policy.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = ["iam:AttachRolePolicy"],
        Resource = "*"
      }
    ]
  })
}

############################
# User-data for EC2 instances
############################

locals {
  ec2_a_user_data = <<-EOT
    #!/bin/bash
    set -euxo pipefail
    export DEBIAN_FRONTEND=noninteractive

    # ensure SSM agent is running
    snap install amazon-ssm-agent --classic 2>/dev/null || true
    snap start amazon-ssm-agent 2>/dev/null || true

    # refresh package lists and install deps
    apt-get update -y
    apt-get install -y python3 python3-flask python3-requests

    # create limited service user
    useradd -r -s /usr/sbin/nologin webapp

    # vulnerable flask app with SSRF endpoint
    cat >/opt/app.py <<'PY'
    from flask import Flask, request
    app = Flask(__name__)
    @app.route('/')
    def index():
        return 'Vulnerable app placeholder – replace with your SSRF demo.'
    @app.route('/ssrf')
    def ssrf():
        import requests as req
        target = request.args.get("url")
        r = req.get(target, timeout=5)
        return r.content, r.status_code, dict(r.headers)
    if __name__ == '__main__':
        app.run(host='0.0.0.0', port=8080)
    PY

    chown webapp:webapp /opt/app.py
    sudo -u webapp nohup python3 /opt/app.py >/var/log/app.log 2>&1 &
    EOT

  ec2_b_user_data = <<-EOT
    #!/bin/bash
    set -euxo pipefail
    export DEBIAN_FRONTEND=noninteractive

    # ensure SSM agent is running
    snap install amazon-ssm-agent --classic 2>/dev/null || true
    snap start amazon-ssm-agent 2>/dev/null || true
    EOT
}

############################
# EC2 Instances
############################

resource "aws_instance" "ec2_a" {
  ami                         = local.ami_id
  instance_type               = var.ec2_instance_type
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.public_sg.id]
  iam_instance_profile        = aws_iam_instance_profile.jumphost_profile.name
  user_data                   = local.ec2_a_user_data
  associate_public_ip_address = true

  root_block_device {
    volume_size = 10
    volume_type = "gp3"
  }

  # IMDSv1 required — SSRF cannot obtain the IMDSv2 PUT token
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"
  }

  tags = { Name = "${local.prefix}-EC2a" }
}

resource "aws_instance" "ec2_b" {
  ami                    = local.ami_id
  instance_type          = var.ec2_instance_type
  subnet_id              = aws_subnet.private.id
  vpc_security_group_ids = [aws_security_group.private_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.lambda_mgmt_profile.name
  user_data              = local.ec2_b_user_data

  root_block_device {
    volume_size = 10
    volume_type = "gp3"
  }

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  tags = { Name = "${local.prefix}-EC2b" }
}

############################
# Outputs
############################

output "starting_point" {
  value = aws_instance.ec2_a.public_ip
}

output "ec2_a_instance_id" {
  value = aws_instance.ec2_a.id
}

output "ec2_b_instance_id" {
  value = aws_instance.ec2_b.id
}
