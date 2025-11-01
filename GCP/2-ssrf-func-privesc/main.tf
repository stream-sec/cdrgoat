terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  region = "us-central1"
  zone   = "us-central1-a"
}

data "google_client_config" "current" {}

#########################
# User-provided variable
#########################

variable "attack_whitelist" {
  description = "CIDRs allowed to access the VMs. Example: -var='attack_whitelist=[\"1.2.3.4/32\"]'"
  type        = list(string)
  default     = []
  validation {
    condition     = length(var.attack_whitelist) > 0
    error_message = "attack_whitelist must contain at least one CIDR (e.g. [\"1.2.3.4/32\"])."
  }
}

#########################
# Service Accounts
#########################

resource "google_service_account" "streamgoat_owner_sa" {
  account_id   = "streamgoat-owner-sa"
  display_name = "StreamGoat Owner SA"
}

resource "google_service_account" "streamgoat_vma_sa" {
  account_id   = "streamgoat-vma-sa"
  display_name = "StreamGoat VM-A Service Account"
}

resource "google_service_account" "streamgoat_vmb_sa" {
  account_id   = "streamgoat-vmb-sa"
  display_name = "StreamGoat VM-B Service Account"
}

#########################
# IAM - Custom Role
#########################

resource "google_project_iam_custom_role" "project_metadata_setter" {
  role_id     = "projectMetadataSetter"
  title       = "Project Metadata Setter"
  description = "Custom role to set project-level metadata, including SSH keys"
  project     = data.google_client_config.current.project
  permissions = [
    "compute.projects.setCommonInstanceMetadata",
    "iam.serviceAccounts.actAs"
  ]
  stage       = "GA"
}

#########################
# IAM - Owner Permissions
#########################

resource "google_project_iam_member" "owner_sa_binding" {
  project = data.google_client_config.current.project
  role    = "roles/owner"
  member  = "serviceAccount:${google_service_account.streamgoat_owner_sa.email}"
}

#########################
# IAM - VM-A Permissions
#########################

resource "google_project_iam_member" "vma_compute_viewer" {
  project = data.google_client_config.current.project
  role    = "roles/compute.viewer"
  member  = "serviceAccount:${google_service_account.streamgoat_vma_sa.email}"
}

resource "google_project_iam_member" "vma_oslogin" {
  project = data.google_client_config.current.project
  role    = "roles/compute.osLogin"
  member  = "serviceAccount:${google_service_account.streamgoat_vma_sa.email}"
}

resource "google_project_iam_member" "vma_iap_tunnel" {
  project = data.google_client_config.current.project
  role    = "roles/iap.tunnelResourceAccessor"
  member  = "serviceAccount:${google_service_account.streamgoat_vma_sa.email}"
}

resource "google_project_iam_member" "vma_project_metadata_setter" {
  project = data.google_client_config.current.project
  role    = google_project_iam_custom_role.project_metadata_setter.name
  member  = "serviceAccount:${google_service_account.streamgoat_vma_sa.email}"
}

#########################
# IAM - VM-B Permissions
#########################

resource "google_project_iam_member" "vmb_functions_viewer" {
  project = data.google_client_config.current.project
  role    = "roles/cloudfunctions.viewer"
  member  = "serviceAccount:${google_service_account.streamgoat_vmb_sa.email}"
}

resource "google_project_iam_member" "vmb_functions_invoker" {
  project = data.google_client_config.current.project
  role    = "roles/cloudfunctions.invoker"
  member  = "serviceAccount:${google_service_account.streamgoat_vmb_sa.email}"
}

resource "google_project_iam_member" "vmb_functions_developer" {
  project = data.google_client_config.current.project
  role    = "roles/cloudfunctions.developer"
  member  = "serviceAccount:${google_service_account.streamgoat_vmb_sa.email}"
}

resource "google_project_iam_member" "vmb_sa_actas" {
  project = data.google_client_config.current.project
  role    = "roles/iam.serviceAccountUser"
  member  = "serviceAccount:${google_service_account.streamgoat_vmb_sa.email}"
}

#########################
# Startup Scripts
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
    /opt/venv/bin/pip install --no-cache-dir requests

    cat >/opt/app.py <<'PY'
    #!/usr/bin/env python3
    from flask import Flask, request
    import requests
    import urllib.parse
    
    app = Flask(__name__)
    @app.route('/')
    def index():
        return 'Vulnerable app placeholder – replace with your SSRF demo.'
    @app.route('/fetch', methods=['GET'])
    def fetch():
        raw_url = request.args.get('url')
        if not raw_url:
            return "Missing url param\n", 400
    
        # Decode the URL fully
        decoded_url = urllib.parse.unquote(raw_url)
    
        # Extract header injection, if any
        injected_header = None
        headers = {}
        if '\r\n' in decoded_url:
            url_part, injected_header = decoded_url.split('\r\n', 1)
        else:
            url_part = decoded_url
    
        # Only accept one header injection line for safety
        if injected_header:
            injected_line = injected_header.strip().split('\r\n')[0]
            injected_header_name = injected_line.strip().split(': ')[0]
            injected_header_value = injected_line.strip().split(': ')[1]

            headers = {
                injected_header_name: injected_header_value
            }
    
        try:
            resp = requests.get(url_part, headers=headers, timeout=5)
            return (resp.content, resp.status_code, {'Content-Type': resp.headers.get('Content-Type', 'text/plain')})
        except Exception as e:
            return f"error: {e}\n", 500
    
    if __name__ == '__main__':
        app.run(host='0.0.0.0', port=80, debug=True)

    PY

    nohup /opt/venv/bin/python /opt/app.py >/var/log/app.log 2>&1 &
  EOT

  vm_b_startup = <<-EOT
    #!/bin/bash
    echo "[*] VM-B ready for function abuse testing."
  EOT
}

#########################
# VM-A (SSRF app)
#########################

resource "google_compute_instance" "streamgoat_vm_a" {
  name         = "streamgoat-vm-a"
  machine_type = "e2-medium"
  zone         = "us-central1-a"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  network_interface {
    network    = google_compute_network.streamgoat_vpc.id
    subnetwork = google_compute_subnetwork.streamgoat_subnet.name
    access_config {}
  }

  metadata_startup_script = local.vm_a_startup

  service_account {
    email  = google_service_account.streamgoat_vma_sa.email
    scopes = ["cloud-platform"]
  }

  tags = ["streamgoat-public"]
}

#########################
# VM-B (escalation target)
#########################

resource "google_compute_instance" "streamgoat_vm_b" {
  name         = "streamgoat-vm-b"
  machine_type = "e2-medium"
  zone         = "us-central1-a"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  network_interface {
    network    = google_compute_network.streamgoat_vpc.id
    subnetwork = google_compute_subnetwork.streamgoat_subnet.name
  }

  metadata_startup_script = local.vm_b_startup

  service_account {
    email  = google_service_account.streamgoat_vmb_sa.email
    scopes = ["cloud-platform"]
  }

  tags = ["streamgoat-public"]
}

#########################
# Firewall Rules
#########################

resource "google_compute_firewall" "allow_http" {
  name    = "allow-http"
  network = google_compute_network.streamgoat_vpc.name

  allow {
    protocol = "tcp"
    ports    = ["22", "80"]
  }

  direction     = "INGRESS"
  source_ranges = var.attack_whitelist
  target_tags   = ["streamgoat-public"]
}

resource "google_compute_firewall" "allow_iap_ssh" {
  name    = "allow-iap-ssh"
  network = google_compute_network.streamgoat_vpc.name

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  direction     = "INGRESS"
  source_ranges = ["35.235.240.0/20"]
  target_tags   = ["streamgoat-public"]
}

resource "google_compute_network" "streamgoat_vpc" {
  name                    = "streamgoat-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "streamgoat_subnet" {
  name                     = "streamgoat-subnet"
  ip_cidr_range            = "10.10.0.0/16"
  region                   = "us-central1"
  network                  = google_compute_network.streamgoat_vpc.name
  private_ip_google_access = true
}

#########################
# Outputs
#########################

output "ssrf_app_url" {
  description = "SSRF lab app endpoint"
  value       = "http://${google_compute_instance.streamgoat_vm_a.network_interface[0].access_config[0].nat_ip}"
}