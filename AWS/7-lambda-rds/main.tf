terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }
  required_version = ">= 1.2"
}

provider "aws" {
  region = var.region
}

variable "region" {
  default = "us-east-1"
}

variable "attack_whitelist" {
  description = "User's public IP address(es)"
  type        = list(string)
}

# random suffix for resource names
resource "random_string" "sfx" {
  length  = 4
  upper   = false
  special = false
  numeric = true
}

# -------------------
# VPC & Subnets
# -------------------
resource "aws_vpc" "lab" {
  cidr_block           = "10.10.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = { Name = "streamgoat-vpc" }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.lab.id
  tags   = { Name = "streamgoat-igw" }
}

resource "aws_subnet" "public_a" {
  vpc_id            = aws_vpc.lab.id
  cidr_block        = "10.10.1.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true
  tags = { Name = "streamgoat-public-a" }
}

resource "aws_subnet" "public_b" {
  vpc_id            = aws_vpc.lab.id
  cidr_block        = "10.10.2.0/24"
  availability_zone = data.aws_availability_zones.available.names[1]
  map_public_ip_on_launch = true
  tags = { Name = "streamgoat-public-b" }
}

resource "aws_subnet" "private_a" {
  vpc_id            = aws_vpc.lab.id
  cidr_block        = "10.10.101.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]
  tags = { Name = "streamgoat-private-a" }
}

resource "aws_subnet" "private_b" {
  vpc_id            = aws_vpc.lab.id
  cidr_block        = "10.10.102.0/24"
  availability_zone = data.aws_availability_zones.available.names[1]
  tags = { Name = "streamgoat-private-b" }
}

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.lab.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
  tags = { Name = "streamgoat-rt-public" }
}

resource "aws_route_table_association" "rt_assoc_pub_a" {
  subnet_id      = aws_subnet.public_a.id
  route_table_id = aws_route_table.public.id
}
resource "aws_route_table_association" "rt_assoc_pub_b" {
  subnet_id      = aws_subnet.public_b.id
  route_table_id = aws_route_table.public.id
}

# -------------------
# Security Groups
# -------------------
resource "aws_security_group" "lambda_sg" {
  name        = "streamgoat-lambda-sg"
  description = "Allow outbound; no inbound"
  vpc_id      = aws_vpc.lab.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "streamgoat-lambda-sg" }
}

# RDS security group: allow MySQL from the lambda SG only
resource "aws_security_group" "rds_sg" {
  name        = "streamgoat-rds-sg"
  description = "Allow MySQL from Lambda"
  vpc_id      = aws_vpc.lab.id

  ingress {
    description      = "MySQL from Lambda SG"
    from_port        = 3306
    to_port          = 3306
    protocol         = "tcp"
    cidr_blocks      = concat([aws_vpc.lab.cidr_block], var.attack_whitelist)
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "streamgoat-rds-sg" }
}

# -------------------
# DB Subnet Group and RDS (private-only)
# -------------------
resource "aws_db_subnet_group" "rds_subnets" {
  name       = "streamgoat-rds-subnet-group"
  subnet_ids = [aws_subnet.public_a.id, aws_subnet.public_b.id]
  tags       = { Name = "streamgoat-rds-subnet-group" }
}


resource "random_password" "db_pwd" {
  length  = 16
  special = true
}

resource "aws_db_instance" "streamgoat_rds" {
  identifier              = "streamgoat-rds-${random_string.sfx.result}"
  allocated_storage       = 20
  engine                  = "mysql"
  engine_version          = "8.4"
  instance_class          = "db.t3.micro"
  db_name                 = "streamgoatdb"        # <-- corrected here
  username                = "streamgoat_admin"
  password                = random_password.db_pwd.result
  skip_final_snapshot     = true
  publicly_accessible     = false
  vpc_security_group_ids  = [aws_security_group.rds_sg.id]
  db_subnet_group_name    = aws_db_subnet_group.rds_subnets.name
  multi_az                = false
  tags = {
    Name = "StreamGoat-RDS-${random_string.sfx.result}"
  }

  depends_on = [aws_db_subnet_group.rds_subnets]
}

# -------------------
# IAM users and keys
# -------------------
resource "aws_iam_user" "eva" {
  name = "StreamGoat-User-eva"
}

data "aws_iam_policy_document" "eva_policy" {
  statement {
    actions = [
      "lambda:ListFunctions",
      "lambda:GetFunction",
      "lambda:ListTags"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_user_policy" "eva_user_policy" {
  name   = "StreamGoat-EvaLambdaListPolicy"
  user   = aws_iam_user.eva.name
  policy = data.aws_iam_policy_document.eva_policy.json
}

resource "aws_iam_access_key" "eva_key" {
  user = aws_iam_user.eva.name
}

# 2) StreamGoat-User-lambda — keys intended to be placed in Lambda env
resource "aws_iam_user" "lambda_user" {
  name = "StreamGoat-User-lambda"
}

# Minimal policy: allow RDS snapshot creation & describe (so the Lambda can simulate backup)
data "aws_iam_policy_document" "lambda_user_policy_doc" {
  statement {
    actions = [
      "rds:CreateDBSnapshot",
      "rds:DescribeDBInstances",
      "rds:DescribeDBSnapshots",
      "rds:RestoreDBInstanceFromDBSnapshot",
      "rds:CreateDBInstance",
      "rds:AddTagsToResource",
      "rds:ModifyDBInstance",
      "rds:DeleteDBInstance",
      "rds:DeleteDBSnapshot"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_user_policy" "lambda_user_policy" {
  name   = "StreamGoat-LambdaUser-RDSPolicy"
  user   = aws_iam_user.lambda_user.name
  policy = data.aws_iam_policy_document.lambda_user_policy_doc.json
}

resource "aws_iam_access_key" "lambda_user_key" {
  user = aws_iam_user.lambda_user.name
}

# -------------------
# Lambda role (execution role only) - minimal cloudwatch logs permission
# -------------------
data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda_exec_role" {
  name               = "streamgoat-lambda-exec-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
}


data "aws_caller_identity" "current" {}

# -------------------
# Lambda function (Python) that reads AWS credentials from env vars and attempts to snapshot the RDS
# -------------------
data "archive_file" "lambda_zip" {
  type        = "zip"
  output_path = "${path.module}/lambda_payload.zip"

  source {
    content  = <<EOF
import os
import boto3
import logging
import json
from datetime import datetime, timezone

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Use env vars that do NOT start with "AWS_"
AWS_KEY = os.environ.get("STREAMGOAT_AK")
AWS_SECRET = os.environ.get("STREAMGOAT_SK")
RDS_IDENTIFIER = os.environ.get("RDS_IDENTIFIER")
# Lambda runtime automatically provides AWS_REGION; fallback if not present
REGION = os.environ.get("AWS_REGION", "us-east-1")

def _now_ts():
    return datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")

def _boto_client():
    if not AWS_KEY or not AWS_SECRET:
        raise RuntimeError("Missing STREAMGOAT_AK/STREAMGOAT_SK in environment")
    return boto3.client(
        "rds",
        aws_access_key_id=AWS_KEY,
        aws_secret_access_key=AWS_SECRET,
        region_name=REGION
    )

def do_backup(client):
    snap_id = f"{RDS_IDENTIFIER}-snapshot-{_now_ts()}"
    logger.info("Creating snapshot %s for %s", snap_id, RDS_IDENTIFIER)
    resp = client.create_db_snapshot(
        DBSnapshotIdentifier=snap_id,
        DBInstanceIdentifier=RDS_IDENTIFIER
    )
    return {"status": "snapshot_requested", "snapshot_id": snap_id, "response": resp.get("DBSnapshot", {})}

def _get_latest_snapshot(client):
    logger.info("Looking up snapshots for %s", RDS_IDENTIFIER)
    resp = client.describe_db_snapshots(DBInstanceIdentifier=RDS_IDENTIFIER, SnapshotType="manual")
    snaps = resp.get("DBSnapshots", [])
    if not snaps:
        return None
    latest = max(snaps, key=lambda s: s.get("SnapshotCreateTime", ""))
    return latest.get("DBSnapshotIdentifier")

def do_restore(client, snapshot_id=None):
    if not snapshot_id:
        snapshot_id = _get_latest_snapshot(client)
        if not snapshot_id:
            raise RuntimeError("No manual snapshots found to restore from")
        logger.info("No snapshot_id provided; using latest: %s", snapshot_id)
    new_instance_id = f"{RDS_IDENTIFIER}-recovery-{_now_ts()}"
    try:
        desc = client.describe_db_instances(DBInstanceIdentifier=RDS_IDENTIFIER)
        inst = desc.get("DBInstances", [])[0]
        db_instance_class = inst.get("DBInstanceClass")
        db_subnet_group = inst.get("DBSubnetGroup", {}).get("DBSubnetGroupName")
    except Exception:
        db_instance_class = None
        db_subnet_group = None

    params = {
        "DBInstanceIdentifier": new_instance_id,
        "DBSnapshotIdentifier": snapshot_id
    }
    if db_instance_class:
        params["DBInstanceClass"] = db_instance_class
    if db_subnet_group:
        params["DBSubnetGroupName"] = db_subnet_group

    logger.info("Attempting restore (redacted params): %s", {k: v for k, v in params.items() if k != "DBSnapshotIdentifier"})
    resp = client.restore_db_instance_from_db_snapshot(**params)
    return {"status": "restore_started", "restored_instance": new_instance_id, "response": resp.get("DBInstance", {})}

def handler(event, context):
    logger.info("Event: %s", json.dumps(event))
    action = None
    if isinstance(event, dict):
        action = event.get("action")
    if not action and isinstance(event, str):
        action = event

    if not action:
        return {"status": "error", "error": "no action provided; must be 'backup' or 'restore'"}
    if not RDS_IDENTIFIER:
        return {"status": "error", "error": "RDS_IDENTIFIER not set in env"}

    try:
        client = _boto_client()
    except Exception as e:
        logger.exception("Failed to create boto3 client")
        return {"status": "error", "error": str(e)}

    try:
        if action.lower() == "backup":
            return do_backup(client)
        elif action.lower() == "restore":
            snapshot_id = None
            if isinstance(event, dict):
                snapshot_id = event.get("snapshot_id")
            return do_restore(client, snapshot_id=snapshot_id)
        else:
            return {"status": "error", "error": f"unknown action '{action}'"}
    except Exception as e:
        logger.exception("Operation failed")
        return {"status": "error", "error": str(e)}
EOF
    filename = "lambda_function.py"
  }
}


resource "aws_lambda_function" "streamgoat_lambda" {
  function_name = "StreamGoat-Lambda-${random_string.sfx.result}"
  filename      = data.archive_file.lambda_zip.output_path
  handler       = "lambda_function.handler"
  runtime       = "python3.10"
  role          = aws_iam_role.lambda_exec_role.arn
  source_code_hash = filebase64sha256(data.archive_file.lambda_zip.output_path)

  environment {
    variables = {
      STREAMGOAT_AK   = aws_iam_access_key.lambda_user_key.id
      STREAMGOAT_SK   = aws_iam_access_key.lambda_user_key.secret
      RDS_IDENTIFIER  = aws_db_instance.streamgoat_rds.identifier
    }
  }

  tags = {
    Name = "StreamGoat-Lambda-${random_string.sfx.result}"
  }
  
  depends_on = [
    aws_iam_access_key.lambda_user_key
  ]
}

output "streamgoat_eva_access_key_id" {
  value     = aws_iam_access_key.eva_key.id
  sensitive = true
}

output "streamgoat_eva_secret" {
  value     = aws_iam_access_key.eva_key.secret
  sensitive = true
}