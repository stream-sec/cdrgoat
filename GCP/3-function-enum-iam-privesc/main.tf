terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 4.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.0"
    }
  }

  required_version = ">= 1.2.0"
}

provider "google" {
  region = "us-central1"
  zone   = "us-central1-a"
}

data "google_client_config" "current" {}

# Generate a short random suffix for role_id to avoid conflicts with roles
resource "random_id" "role_suffix" {
  byte_length = 2
}

# Archive inline Python code into .zip
data "archive_file" "function_zip" {
  type        = "zip"
  output_path = "${path.module}/function.zip"

  source {
    content  = <<-EOT
      import random

      def get_random(request):
          return str(random.randint(1, 1000))
    EOT
    filename = "main.py"
  }

  source {
    content  = ""
    filename = "requirements.txt"
  }
}

#########################
# GCS Bucket for function upload
#########################

resource "google_storage_bucket" "function_bucket" {
  name          = "${data.google_client_config.current.project}-streamgoat-fn-bucket"
  location      = "US"
  force_destroy = true

  uniform_bucket_level_access = true
}

resource "google_storage_bucket_object" "function_object" {
  name   = "streamgoat-function.zip"
  bucket = google_storage_bucket.function_bucket.name
  source = data.archive_file.function_zip.output_path
}

#########################
# Custom role
#########################

resource "google_project_iam_custom_role" "streamgoat_maintainer_role" {
  project     = data.google_client_config.current.project
  # Append a short random suffix to avoid collisions with prior deleted roles
  role_id     = "streamgoatRoleMaintainer_${random_id.role_suffix.hex}"
  title       = "StreamGoat Function Maintainer"
  description = "Limited maintainer for Cloud Functions and IAM metadata"
  stage       = "GA"
  permissions = [
    "cloudfunctions.functions.get",
    "cloudfunctions.functions.list",
    "cloudfunctions.functions.invoke",
    "cloudfunctions.locations.list",
    "cloudfunctions.functions.update",
    "cloudfunctions.functions.sourceCodeSet",
    "iam.roles.list",
    "iam.roles.get",
    "iam.serviceAccounts.list",
    "iam.serviceAccounts.get",
    "iam.serviceAccounts.actAs",
    "storage.buckets.list",
    "storage.objects.get",
    "storage.objects.create"
  ]
}

#########################
# Service Accounts
#########################

resource "google_service_account" "maintainer" {
  account_id   = "streamgoat-sa-maintainer"
  display_name = "StreamGoat Maintainer"
}

resource "google_service_account" "developer" {
  account_id   = "streamgoat-sa-developer"
  display_name = "StreamGoat Developer"
}

resource "google_service_account" "iteng" {
  account_id   = "streamgoat-sa-iteng"
  display_name = "StreamGoat IT Engineer"
}

resource "google_service_account" "fulladmin" {
  account_id   = "streamgoat-sa-fulladmin"
  display_name = "StreamGoat Full Admin"
}

#########################
# Role Bindings: streamgoat-sa-maintainer
#########################

resource "google_project_iam_member" "maintainer_bind" {
  project = data.google_client_config.current.project
  role    = google_project_iam_custom_role.streamgoat_maintainer_role.name
  member  = "serviceAccount:${google_service_account.maintainer.email}"
}

#########################
# Role Bindings: streamgoat-sa-developer
#########################

resource "google_project_iam_member" "developer_bindings" {
  for_each = toset([
    "roles/compute.viewer",
    "roles/cloudfunctions.viewer",
    "roles/cloudfunctions.invoker",
    "roles/cloudfunctions.developer"
  ])
  project = data.google_client_config.current.project
  role    = each.key
  member  = "serviceAccount:${google_service_account.developer.email}"
}

#########################
# Role Bindings: streamgoat-sa-iteng
#########################

resource "google_project_iam_member" "iteng_bindings" {
  for_each = toset([
    "roles/compute.viewer",
    "roles/logging.viewer",
    "roles/monitoring.viewer",
    "roles/storage.admin"
  ])
  project = data.google_client_config.current.project
  role    = each.key
  member  = "serviceAccount:${google_service_account.iteng.email}"
}

#########################
# Role Bindings: streamgoat-sa-fulladmin
#########################

resource "google_project_iam_member" "fulladmin_bind" {
  project = data.google_client_config.current.project
  role    = "roles/owner"
  member  = "serviceAccount:${google_service_account.fulladmin.email}"
}

#########################
# Cloud Function Deployment
#########################

resource "google_cloudfunctions_function" "streamgoat_function" {
  name        = "streamgoat-calc-function"
  description = "Returns a random number 1–1000"
  runtime     = "python310"
  region      = "us-central1"
  available_memory_mb = 128
  source_archive_bucket = google_storage_bucket.function_bucket.name
  source_archive_object = google_storage_bucket_object.function_object.name
  entry_point = "get_random"
  trigger_http = true
  service_account_email = google_service_account.fulladmin.email
}

resource "google_cloudfunctions_function_iam_member" "allow_maintainer_invoke" {
  project        = data.google_client_config.current.project
  region         = "us-central1"
  cloud_function = google_cloudfunctions_function.streamgoat_function.name

  role   = "roles/cloudfunctions.invoker"
  member = "serviceAccount:${google_service_account.maintainer.email}"
}

# Maintainer Service Account Key
resource "google_service_account_key" "maintainer_key" {
  service_account_id = google_service_account.maintainer.name
  keepers = {
    updated_at = timestamp()
  }
}

# Outputs
output "maintainer_service_account_key_json" {
  description = "Private key for streamgoat-sa-maintainer (base64-encoded)"
  value       = google_service_account_key.maintainer_key.private_key
  sensitive   = true
}
