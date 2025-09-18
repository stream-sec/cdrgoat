provider "aws" {
  region = "us-east-1"
}

#####################
# Networking
#####################

resource "aws_vpc" "streamgoat_vpc" {
  cidr_block = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

}

resource "aws_subnet" "streamgoat_subnet" {
  vpc_id            = aws_vpc.streamgoat_vpc.id
  cidr_block        = "10.0.0.0/24"
  availability_zone = "us-east-1a"
}

resource "aws_internet_gateway" "streamgoat_igw" {
  vpc_id = aws_vpc.streamgoat_vpc.id
}

resource "aws_route_table" "streamgoat_rt" {
  vpc_id = aws_vpc.streamgoat_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.streamgoat_igw.id
  }
}

resource "aws_route_table_association" "rt_assoc" {
  subnet_id      = aws_subnet.streamgoat_subnet.id
  route_table_id = aws_route_table.streamgoat_rt.id
}

resource "aws_security_group" "streamgoat_sg" {
  name   = "streamgoat-sg"
  vpc_id = aws_vpc.streamgoat_vpc.id

  # Only allow NFS (EFS) access within the subnet
  ingress {
    from_port   = 2049
    to_port     = 2049
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/24"]
  }

  # Required for EC2 to reach out (e.g., for SSM, updates)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

#####################
# EFS
#####################

resource "aws_efs_file_system" "streamgoat_efs" {
  creation_token = "streamgoat-efs"
  encrypted      = false
}

resource "aws_efs_mount_target" "efs_mount" {
  file_system_id  = aws_efs_file_system.streamgoat_efs.id
  subnet_id       = aws_subnet.streamgoat_subnet.id
  security_groups = [aws_security_group.streamgoat_sg.id]
}

#####################
# IAM - User Alisa
#####################

resource "aws_iam_user" "alisa" {
  name = "StreamGoat-User-Alisa"
}

resource "aws_iam_access_key" "alisa_keys" {
  user = aws_iam_user.alisa.name
}

resource "aws_iam_policy" "streamgoat_policy" {
  name        = "StreamGoat-Policy-basic"
  policy      = data.aws_iam_policy_document.policy_v1.json
}

resource "aws_iam_user_policy_attachment" "attach_policy" {
  user       = aws_iam_user.alisa.name
  policy_arn = aws_iam_policy.streamgoat_policy.arn
}


resource "null_resource" "policy_versions" {
  depends_on = [aws_iam_policy.streamgoat_policy]

  provisioner "local-exec" {
    command = "aws iam create-policy-version --policy-arn ${aws_iam_policy.streamgoat_policy.arn} --policy-document file://policies/v2.json --no-set-as-default"
  }

  provisioner "local-exec" {
    command = "aws iam create-policy-version --policy-arn ${aws_iam_policy.streamgoat_policy.arn} --policy-document file://policies/v3.json --no-set-as-default"
  }

}

data "aws_iam_policy_document" "policy_v1" {
  statement {
    effect = "Allow"
    actions = [
      "iam:GetUser",
      "iam:GetUserPolicy",
      "iam:ListUserPolicies",
      "iam:ListAttachedUserPolicies",
      "iam:ListPolicyVersions",
      "iam:SetDefaultPolicyVersion",
      "iam:GetPolicy",
      "iam:GetPolicyVersion"
    ]
    resources = [
      "*"
    ]
  }
}

#####################
# EC2 (Ubuntu)
#####################

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
}

resource "aws_iam_role" "ec2_ssm_role" {
  name = "StreamGoatEC2Role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ssm_attach" {
  role       = aws_iam_role.ec2_ssm_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "StreamGoatEC2Profile"
  role = aws_iam_role.ec2_ssm_role.name
}

resource "aws_instance" "streamgoat_ec2" {
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = "t2.micro"
  subnet_id                   = aws_subnet.streamgoat_subnet.id
  vpc_security_group_ids      = [aws_security_group.streamgoat_sg.id]
  associate_public_ip_address = true
  iam_instance_profile        = aws_iam_instance_profile.ec2_profile.name

  tags = {
    Name = "StreamGoat-EC2a"
  }

  user_data = <<-EOF
      #!/bin/bash
      sleep 120
      apt update -y
      apt install -y nfs-common
      mkdir -p /mnt/efs
      mount -t nfs4 -o nfsvers=4.1 ${aws_efs_file_system.streamgoat_efs.dns_name}:/ /mnt/efs
      echo "Sensitive data is here" > /mnt/efs/secret.txt
      sync
      sleep 5
      umount /mnt/efs
  EOF
}

#####################
# Outputs
#####################

output "leaked_access_key" {
  value     = aws_iam_access_key.alisa_keys.id
  sensitive = true
}

output "leaked_secret_key" {
  value     = aws_iam_access_key.alisa_keys.secret
  sensitive = true
}
