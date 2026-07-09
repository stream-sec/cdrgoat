############################
# Terraform: AWS Attack Path Scenario 1 – RCE → IMDS → Lateral Movement → RDS
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
  default = "10.20.0.0/16"
}

variable "public_subnet_cidr" {
  type    = string
  default = "10.20.0.0/24"
}

variable "private_subnet1_cidr" {
  type    = string
  default = "10.20.10.0/24"
}

variable "private_subnet2_cidr" {
  type    = string
  default = "10.20.20.0/24"
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
  prefix = "StreamGoat-aws1"
  suffix = random_id.suffix.hex
}

############################
# Data (latest Ubuntu 24.04 AMI)
############################

data "aws_availability_zones" "available" {}

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

resource "aws_subnet" "public_a" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_cidr
  map_public_ip_on_launch = true
  availability_zone       = data.aws_availability_zones.available.names[0]
  tags                    = { Name = "${local.prefix}-public-a" }
}

resource "aws_subnet" "private_a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_subnet1_cidr
  availability_zone = data.aws_availability_zones.available.names[0]
  tags              = { Name = "${local.prefix}-private-a" }
}

resource "aws_subnet" "private_b" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_subnet2_cidr
  availability_zone = data.aws_availability_zones.available.names[1]
  tags              = { Name = "${local.prefix}-private-b" }
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
  subnet_id      = aws_subnet.public_a.id
  route_table_id = aws_route_table.public.id
}

############################
# Security Groups
############################

resource "aws_security_group" "sg_ec2_a" {
  name                   = "${local.prefix}-ec2a-sg"
  description            = "Allow HTTP and SSH from internet"
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

  tags = { Name = "${local.prefix}-sg-ec2a" }
}

resource "aws_security_group" "sg_ec2_b" {
  name                   = "${local.prefix}-ec2b-sg"
  description            = "Allow SSH from internet"
  vpc_id                 = aws_vpc.main.id
  revoke_rules_on_delete = true

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.attack_whitelist
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${local.prefix}-sg-ec2b" }
}

resource "aws_security_group" "sg_rds" {
  name                   = "${local.prefix}-rds-sg"
  description            = "Allow MySQL from EC2-B"
  vpc_id                 = aws_vpc.main.id
  revoke_rules_on_delete = true

  ingress {
    description     = "MySQL from EC2-B SG"
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.sg_ec2_b.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${local.prefix}-sg-rds" }
}

############################
# IAM for EC2-A (JumpHostPrivs)
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

resource "aws_iam_role" "ec2_a_role" {
  name               = "${local.prefix}-JumpHostPrivsRole-${local.suffix}"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
}

resource "aws_iam_role_policy" "jumphost_privs" {
  name = "${local.prefix}-JumpHostPrivs"
  role = aws_iam_role.ec2_a_role.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = ["ec2:DescribeInstances"],
        Resource = "*"
      },
      {
        Effect = "Allow",
        Action = [
          "ec2-instance-connect:SendSSHPublicKey",
          "ec2-instance-connect:SendSerialConsoleSSHPublicKey"
        ],
        Resource = aws_instance.ec2_b.arn
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ec2_a_ssm" {
  role       = aws_iam_role.ec2_a_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ec2_a_profile" {
  name = "${local.prefix}-JumpHostPrivsProfile-${local.suffix}"
  role = aws_iam_role.ec2_a_role.name
}

############################
# IAM for EC2-B (SSM access)
############################

resource "aws_iam_role" "ec2_b_role" {
  name               = "${local.prefix}-EC2bRole-${local.suffix}"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
}

resource "aws_iam_role_policy_attachment" "ec2_b_ssm" {
  role       = aws_iam_role.ec2_b_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ec2_b_profile" {
  name = "${local.prefix}-EC2bProfile-${local.suffix}"
  role = aws_iam_role.ec2_b_role.name
}

############################
# RDS MySQL (private)
############################

resource "aws_db_subnet_group" "rds" {
  name       = lower("${local.prefix}-rds-subnets-${local.suffix}")
  subnet_ids = [aws_subnet.private_a.id, aws_subnet.private_b.id]
  tags       = { Name = "${local.prefix}-rds-subnet-group" }
}

resource "random_password" "db" {
  length           = 20
  special          = true
  override_special = "_#%+-=^~.,:;!?()[]{}"
}

resource "aws_db_instance" "mysql" {
  identifier                 = lower("${local.prefix}-mysql-${local.suffix}")
  allocated_storage          = 20
  db_subnet_group_name       = aws_db_subnet_group.rds.name
  vpc_security_group_ids     = [aws_security_group.sg_rds.id]
  engine                     = "mysql"
  engine_version             = "8.0"
  instance_class             = "db.t3.micro"
  username                   = "appuser"
  password                   = random_password.db.result
  publicly_accessible        = false
  skip_final_snapshot        = true
  deletion_protection        = false
  multi_az                   = false
  backup_retention_period    = 0
  apply_immediately          = true
  storage_encrypted          = false
  auto_minor_version_upgrade = true
  tags                       = { Name = "${local.prefix}-rds" }
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
    apt-get install -y python3 python3-flask

    # create limited service user
    useradd -r -s /usr/sbin/nologin webapp

    # vulnerable flask app
    cat >/opt/app.py <<'PY'
    from flask import Flask, request
    app = Flask(__name__)
    @app.route('/')
    def index():
        return 'Vulnerable app placeholder – replace with your RCE demo. Hint: /cmd might be interesting.'
    @app.route('/cmd')
    def cmd():
        import os
        c = request.args.get('c','echo ok')
        return os.popen(c).read()
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

    apt-get update -y
    apt-get install -y mysql-client

    # expose RDS creds to shell
    cat >/etc/profile.d/rds.sh <<'ENV'
    export DB_HOST="${aws_db_instance.mysql.address}"
    export DB_USER="${aws_db_instance.mysql.username}"
    export DB_PASS="${random_password.db.result}"
    export DB_PORT="3306"
    ENV
    chmod 0644 /etc/profile.d/rds.sh
    EOT
}

############################
# EC2 Instances
############################

resource "aws_instance" "ec2_a" {
  ami                         = local.ami_id
  instance_type               = var.ec2_instance_type
  subnet_id                   = aws_subnet.public_a.id
  vpc_security_group_ids      = [aws_security_group.sg_ec2_a.id]
  iam_instance_profile        = aws_iam_instance_profile.ec2_a_profile.name
  user_data                   = local.ec2_a_user_data
  associate_public_ip_address = true

  root_block_device {
    volume_size = 10
    volume_type = "gp3"
  }

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  tags = { Name = "${local.prefix}-EC2a" }
}

resource "aws_instance" "ec2_b" {
  ami                         = local.ami_id
  instance_type               = var.ec2_instance_type
  subnet_id                   = aws_subnet.public_a.id
  vpc_security_group_ids      = [aws_security_group.sg_ec2_b.id]
  iam_instance_profile        = aws_iam_instance_profile.ec2_b_profile.name
  user_data                   = local.ec2_b_user_data
  associate_public_ip_address = true

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
