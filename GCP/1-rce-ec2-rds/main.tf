#gcloud auth login
#gcloud auth application-default login
#export GOOGLE_CLOUD_PROJECT="inspired-ether-475411-t1"
#terraform apply -var='attack_whitelist=["134.209.251.184/32"]' -auto-approve
terraform {
  required_version = ">= 1.1.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 4.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.0"
    }
    time = {
      source  = "hashicorp/time"
      version = ">= 0.7.0"
    }
    null = {
      source  = "hashicorp/null"
      version = ">= 3.0.0"
    }
  }
}

#########################
# Variables
#########################
variable "region" {
  description = "GCP region"
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "GCP zone"
  type        = string
  default     = "us-central1-a"
}

variable "vm_machine_type" {
  description = "Machine type for the lab VMs"
  type        = string
  default     = "e2-medium"
}

variable "attack_whitelist" {
  description = "List of CIDR(s) allowed to access the VMs (SSH/HTTP). Example: -var='attack_whitelist=[\"212.68.138.150/32\",\"79.177.158.16/32\"]'"
  type        = list(string)
  default     = []
  validation {
    condition     = length(var.attack_whitelist) > 0
    error_message = "attack_whitelist must contain at least one CIDR (e.g. [\"1.2.3.4/32\"]). Do not leave empty."
  }
}

#########################
# Provider (project omitted -> uses ADC / gcloud default)
#########################
provider "google" {
  region = var.region
  zone   = var.zone
}

# read currently-configured project from gcloud/ADC or env
data "google_client_config" "current" {}

#########################
# Enable APIs (explicit project set)
#########################
resource "google_project_service" "compute" {
  project = data.google_client_config.current.project
  service = "compute.googleapis.com"
}
resource "google_project_service" "sqladmin" {
  project = data.google_client_config.current.project
  service = "sqladmin.googleapis.com"
}
resource "google_project_service" "iam" {
  project = data.google_client_config.current.project
  service = "iam.googleapis.com"
}
resource "google_project_service" "serviceusage" {
  project = data.google_client_config.current.project
  service = "serviceusage.googleapis.com"
}

#########################
# Secrets
#########################
resource "random_password" "streamgoat_sql_user" {
  length  = 16
  special = true
}

#########################
# Service account for VM-A (attacker pivot)
#########################
resource "google_service_account" "streamgoat_vm_a_sa" {
  project      = data.google_client_config.current.project
  account_id   = "streamgoat-vm-a-sa"
  display_name = "streamgoat VM A metadata editor"
}

#########################
# Minimal custom role (compute.instances.get + compute.instances.setMetadata)
#########################
resource "google_project_iam_custom_role" "streamgoat_setmetadata_role" {
  project     = data.google_client_config.current.project
  role_id     = "streamgoat_setmetadata"
  title       = "StreamGoat SetMetadata"
  description = "Minimal role allowing instance metadata read and metadata update (get + setMetadata) for lab pivot"
  permissions = [
    "compute.instances.get",
    "compute.instances.list",
    "compute.instances.setMetadata",
  ]
}

resource "google_project_iam_member" "streamgoat_vm_a_sa_compute" {
  project = data.google_client_config.current.project
  role    = "projects/${data.google_client_config.current.project}/roles/${google_project_iam_custom_role.streamgoat_setmetadata_role.role_id}"
  member  = "serviceAccount:${google_service_account.streamgoat_vm_a_sa.email}"
}

#########################
# Network & firewall (VMs only, restricted to attack_whitelist)
#########################
resource "google_compute_network" "streamgoat_net" {
  project                 = data.google_client_config.current.project
  name                    = "streamgoat-network"
  auto_create_subnetworks = true
}

resource "google_compute_firewall" "streamgoat_allow_ssh_http" {
  project = data.google_client_config.current.project
  name    = "streamgoat-allow-ssh-http"
  network = google_compute_network.streamgoat_net.name

  allow {
    protocol = "tcp"
    ports    = ["22", "80"]
  }

  source_ranges = var.attack_whitelist
  target_tags   = ["streamgoat-public"]
}

#########################
# Cloud SQL (MySQL) - public IP open to the Internet (0.0.0.0/0)
# NOTE: intentionally public for lab (password-protected).
#########################
resource "google_sql_database_instance" "streamgoat_mysql" {
  project          = data.google_client_config.current.project
  name             = "streamgoat-mysql"
  database_version = "MYSQL_8_0"
  region           = var.region

  settings {
    tier = "db-f1-micro"

    ip_configuration {
      ipv4_enabled = true

      # Public to the world per your request; password required to connect.
      authorized_networks {
        name  = "public"
        value = "0.0.0.0/0"
      }
    }
  }

  deletion_protection = false
}

resource "google_sql_database" "streamgoat_appdb" {
  project  = data.google_client_config.current.project
  name     = "appdb"
  instance = google_sql_database_instance.streamgoat_mysql.name
}

resource "google_sql_user" "streamgoat_appuser" {
  project  = data.google_client_config.current.project
  name     = "appuser"
  instance = google_sql_database_instance.streamgoat_mysql.name
  password = random_password.streamgoat_sql_user.result
}

#########################
# Startup scripts (vulnerable app on VM-A, DB creds on VM-B)
#########################
locals {
  vm_a_startup = <<-EOT
    #!/bin/bash
    set -euxo pipefail
    export DEBIAN_FRONTEND=noninteractive
    
    apt-get update -y
    apt-get install -y python3 python3-pip python3-venv
    
    python3 -m venv /opt/venv
    /opt/venv/bin/pip install --upgrade pip
    /opt/venv/bin/pip install --no-cache-dir flask

    cat >/opt/app.py <<'PY'
    from flask import Flask, request
    app = Flask(__name__)

    @app.route('/')
    def index():
        return 'Vulnerable app placeholder – CDRGoat RCE demo.'

    @app.route('/cmd')
    def cmd():
        import os
        c = request.args.get('c','echo ok')
        return os.popen(c).read()

    if __name__ == '__main__':
        app.run(host='0.0.0.0', port=80)
    PY

    nohup /opt/venv/bin/python /opt/app.py >/var/log/app.log 2>&1 &
  EOT

  vm_b_startup = <<-EOF
    #!/bin/bash
    set -euxo pipefail
    export DEBIAN_FRONTEND=noninteractive

    apt-get update -y
    apt-get install -y default-mysql-client

    cat >/etc/profile.d/db.sh <<'ENV'
    export DB_HOST="${google_sql_database_instance.streamgoat_mysql.public_ip_address}"
    export DB_USER="${google_sql_user.streamgoat_appuser.name}"
    export DB_PASS="${random_password.streamgoat_sql_user.result}"
    export DB_PORT="3306"
    ENV
    chmod 0644 /etc/profile.d/db.sh
  EOF
}

#########################
# Compute instances (VM-A: vulnerable RCE app with minimal SA role; VM-B: holds DB creds in env)
#########################
resource "google_compute_instance" "streamgoat_vm_a" {
  project      = data.google_client_config.current.project
  name         = "streamgoat-vm-a"
  machine_type = var.vm_machine_type
  zone         = var.zone
  tags         = ["streamgoat-public"]

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
      size  = 20
    }
  }

  network_interface {
    network = google_compute_network.streamgoat_net.id
    access_config {}
  }

  metadata_startup_script = local.vm_a_startup

  service_account {
    email  = google_service_account.streamgoat_vm_a_sa.email
    scopes = ["https://www.googleapis.com/auth/compute"]
  }

  metadata = {}
}

resource "google_compute_instance" "streamgoat_vm_b" {
  project      = data.google_client_config.current.project
  name         = "streamgoat-vm-b"
  machine_type = var.vm_machine_type
  zone         = var.zone
  tags         = ["streamgoat-public"]

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
      size  = 20
    }
  }

  network_interface {
    network = google_compute_network.streamgoat_net.id
    access_config {}
  }

  metadata_startup_script = local.vm_b_startup

  metadata = {}
}

#########################
# small waits to avoid race conditions
#########################
resource "time_sleep" "wait_for_api" {
  depends_on = [
    google_project_service.compute,
    google_project_service.sqladmin,
    google_project_service.iam
  ]
  create_duration = "8s"
}

resource "null_resource" "depend" {
  depends_on = [
    google_compute_instance.streamgoat_vm_a,
    google_compute_instance.streamgoat_vm_b,
    google_sql_database_instance.streamgoat_mysql
  ]
}

#########################
# Outputs
#########################
output "streamgoat_vm_a_external_ip" {
  value = google_compute_instance.streamgoat_vm_a.network_interface[0].access_config[0].nat_ip
}