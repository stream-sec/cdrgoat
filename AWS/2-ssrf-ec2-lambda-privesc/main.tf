#terraform apply -var='attack_whitelist=["212.68.138.150/32","79.177.158.16/32","64.227.60.54/32"]' -auto-approve

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

resource "random_id" "suffix" {
  byte_length = 3
}

variable "attack_whitelist" {
  description = "User's public IP address(es)"
  type        = list(string)
}

variable "ec2_ami" {
  type    = string
  default = ""
}

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

locals {
  ami_id = var.ec2_ami != "" ? var.ec2_ami : data.aws_ami.ubuntu.id
}

locals {
  ec2_a_user_data = <<-EOT
    #!/bin/bash
    set -euxo pipefail
    export DEBIAN_FRONTEND=noninteractive
    
    # refresh package lists and install deps
    apt-get update -y
    apt-get install -y python3 python3-pip
    
    # install flask
    pip3 install --no-cache-dir flask
    
    # vulnerable flask app
    cat >/opt/app.py <<'PY'
    from flask import Flask, request
    app = Flask(__name__)
    @app.route('/')
    def index():
        return 'Vulnerable app placeholder – replace with your SSRF demo.'
    @app.route('/ssrf')
    def ssrf():
        import requests
        target = request.args.get("url")
        r = requests.get(target, timeout=5)
        return r.content, r.status_code, r.headers
    if __name__ == '__main__':
        app.run(host='0.0.0.0', port=80)
    PY
    
    nohup python3 /opt/app.py >/var/log/app.log 2>&1 &
  EOT

  ec2_b_user_data = <<-EOT
    #!/bin/bash
    echo test
  EOT
}

# --------------------------
# VPC
# --------------------------
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "StreamGoat-vpc"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "StreamGoat-igw"
  }
}

# Public Subnet
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true

  tags = {
    Name = "scenario2-public-subnet"
  }
}

# Private Subnet
resource "aws_subnet" "private" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.2.0/24"
  map_public_ip_on_launch = false

  tags = {
    Name = "StreamGoat-private-subnet"
  }
}

# Public Route Table
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "StreamGoat-public-rt"
  }
}

resource "aws_route_table_association" "public_assoc" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# --------------------------
# NAT
# --------------------------
# EIP for NAT
resource "aws_eip" "nat_eip" {
  domain = "vpc"
  tags = { Name = "StreamGoat-nat-eip" }
}

# NAT Gateway in the public subnet
resource "aws_nat_gateway" "nat" {
  subnet_id     = aws_subnet.public.id
  allocation_id = aws_eip.nat_eip.id
  tags = { Name = "StreamGoat-nat" }
}

# Private RT that sends Internet-bound traffic via NAT
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat.id
  }
  tags = { Name = "StreamGoat-private-rt" }
}

resource "aws_route_table_association" "private_assoc" {
  subnet_id      = aws_subnet.private.id
  route_table_id = aws_route_table.private.id
}
# --------------------------
# Security Groups
# --------------------------
resource "aws_security_group" "public_sg" {
  name        = "StreamGoat-public-sg"
  description = "Allow HTTP/SSH"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.attack_whitelist
  }

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = var.attack_whitelist
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "scenario2-public-sg"
  }
}

resource "aws_security_group" "private_sg" {
  name        = "StreamGoat-private-sg"
  description = "Allow SSH from public subnet"
  vpc_id      = aws_vpc.main.id

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

  tags = {
    Name = "StreamGoat-private-sg"
  }
}

# --------------------------
# EC2 Instances
# --------------------------
resource "aws_instance" "ec2_a" {
  ami                    = local.ami_id
  instance_type          = "t2.micro"
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.public_sg.id]
  user_data              = local.ec2_a_user_data
  iam_instance_profile = aws_iam_instance_profile.jumphost_privs.name

  tags = {
    Name = "StreamGoat-EC2a"
  }
}

resource "aws_instance" "ec2_b" {
  ami                    = local.ami_id
  instance_type          = "t2.micro"
  subnet_id              = aws_subnet.private.id
  vpc_security_group_ids = [aws_security_group.private_sg.id]
  user_data              = local.ec2_b_user_data
  iam_instance_profile = aws_iam_instance_profile.lambda_privs.name

  tags = {
    Name = "StreamGoat-EC2b"
  }
}

# --------------------------
# IAM Roles
# --------------------------
resource "aws_iam_role_policy_attachment" "jumphost_ssm_core" {
  role       = aws_iam_role.jumphost_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role" "jumphost_role" {
  name               = "StreamGoat-JumpHostRole"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
}

resource "aws_iam_role_policy" "jumphost_policy" {
  name   = "StreamGoat-JumpHost-Policy"
  role   = aws_iam_role.jumphost_role.id
  policy = data.aws_iam_policy_document.jumphost_policy.json
}

resource "aws_iam_instance_profile" "jumphost_privs" {
  name = "StreamGoat-JumpHost"
  role = aws_iam_role.jumphost_role.name
}

data "aws_iam_policy_document" "ec2_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "jumphost_policy" {
  statement {
    actions   = ["ec2:DescribeInstances","ssm:StartSession", "ssm:SendCommand", "ssm:DescribeSessions", "ssm:GetConnectionStatus", "ssm:DescribeInstanceProperties", "ssm:TerminateSession", "ssm:ResumeSession", "ssm:GetCommandInvocation"]
    resources = ["*"]
  }
}

# Role for EC2-B
resource "aws_iam_role_policy_attachment" "lambda_privs_ssm_core" {
  role       = aws_iam_role.lambda_privs_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role" "lambda_privs_role" {
  name               = "StreamGoat-LambdaMgmt-Role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
}

resource "aws_iam_role_policy" "lambda_privs_policy" {
  name   = "StreamGoat-LambdaMgmt-Policy"
  role   = aws_iam_role.lambda_privs_role.id
  policy = data.aws_iam_policy_document.lambda_privs_policy.json
}

resource "aws_iam_instance_profile" "lambda_privs" {
  name = "StreamGoat-LambdaMgmt"
  role = aws_iam_role.lambda_privs_role.name
}

data "aws_iam_policy_document" "lambda_privs_policy" {
  statement {
    actions   = [
                    "lambda:InvokeFunction",
                    "lambda:CreateFunction",
                    "iam:PassRole",
                    "iam:ListRoles",
                    "iam:GetRole",
                    "iam:ListRolePolicies",
                    "iam:GetRolePolicy"
                ]
    resources = ["*"]
  }
}

# Role to be assigned on Lambda AttachRolePolicy
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

resource "aws_iam_role" "for_lambda_attachrp" {
  name               = "StreamGoat-AttachRolePolicy-Role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
}

data "aws_iam_policy_document" "for_lambda_attachrp_policy" {
  statement {
    actions = [
      "iam:AttachRolePolicy"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "for_lambda_attachrp_policy" {
  name   = "StreamGoat-AttachRolePolicy-Policy"
  role   = aws_iam_role.for_lambda_attachrp.id
  policy = data.aws_iam_policy_document.for_lambda_attachrp_policy.json
}
############################
# Outputs
############################

output "starting_point" {
  value = aws_instance.ec2_a.public_ip
}
