################################################################################
# CDRGoat - Azure Scenario 11
# RCE on App Service → MI → ACR Image Pull → Embedded Secrets → Lateral Movement
################################################################################

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.90"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 3.0.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
}

provider "azurerm" {
  features {}
}

provider "azuread" {}

################################################################################
# Variables
################################################################################

variable "location" {
  description = "Azure region for resources"
  type        = string
  default     = "francecentral"
}

variable "attack_whitelist" {
  description = "List of CIDRs allowed to reach the App Service"
  type        = list(string)
  default     = []
}

################################################################################
# Data Sources
################################################################################

data "azuread_client_config" "current" {}

data "azurerm_subscription" "current" {}

################################################################################
# Random Suffix
################################################################################

resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

################################################################################
# Resource Groups
################################################################################

resource "azurerm_resource_group" "main" {
  name     = "streamgoat-11-rg-${random_string.suffix.result}"
  location = var.location

  tags = {
    scenario = "cdrgoat-11"
    purpose  = "security-training"
  }
}

resource "azurerm_resource_group" "target" {
  name     = "streamgoat-11-target-rg-${random_string.suffix.result}"
  location = var.location

  tags = {
    scenario = "cdrgoat-11"
    purpose  = "security-training"
  }
}

################################################################################
# App Registration (credentials baked into container image)
################################################################################

resource "azuread_application" "leaked_in_image" {
  display_name = "streamgoat-11-internal-api"
  tags         = ["cdrgoat", "scenario-11"]
}

resource "azuread_application_password" "leaked_in_image" {
  application_id = azuread_application.leaked_in_image.id
  display_name   = "streamgoat-11-image-secret"
  end_date       = timeadd(timestamp(), "8760h")
}

resource "azuread_service_principal" "leaked_in_image" {
  client_id = azuread_application.leaked_in_image.client_id
  tags      = ["cdrgoat", "scenario-11"]
}

# SP gets Contributor on the target Resource Group
resource "azurerm_role_assignment" "leaked_sp_target_contributor" {
  scope                = azurerm_resource_group.target.id
  role_definition_name = "Contributor"
  principal_id         = azuread_service_principal.leaked_in_image.object_id
}

# SP gets Storage Blob Data Reader on target storage
resource "azurerm_role_assignment" "leaked_sp_storage_reader" {
  scope                = azurerm_storage_account.target.id
  role_definition_name = "Storage Blob Data Reader"
  principal_id         = azuread_service_principal.leaked_in_image.object_id
}

################################################################################
# Storage Account in target RG (exfiltration target)
################################################################################

resource "azurerm_storage_account" "target" {
  name                     = "stgoat11tgt${random_string.suffix.result}"
  resource_group_name      = azurerm_resource_group.target.name
  location                 = var.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  tags = { scenario = "cdrgoat-11" }
}

resource "azurerm_storage_container" "sensitive_data" {
  name                  = "financial-reports"
  storage_account_name  = azurerm_storage_account.target.name
  container_access_type = "private"
}

resource "azurerm_storage_blob" "financial_report" {
  name                   = "financial-report-2024.csv"
  storage_account_name   = azurerm_storage_account.target.name
  storage_container_name = azurerm_storage_container.sensitive_data.name
  type                   = "Block"
  source_content         = "quarter,revenue,profit,expenses,tax_id\nQ1,2450000,890000,1560000,EIN-12-3456789\nQ2,3100000,1250000,1850000,EIN-12-3456789\nQ3,2900000,1050000,1850000,EIN-12-3456789\nQ4,3500000,1400000,2100000,EIN-12-3456789\n"
}

################################################################################
# Azure Container Registry
################################################################################

resource "azurerm_container_registry" "main" {
  name                = "stgoat11acr${random_string.suffix.result}"
  resource_group_name = azurerm_resource_group.main.name
  location            = var.location
  sku                 = "Basic"
  admin_enabled       = true

  tags = { scenario = "cdrgoat-11" }
}

# Build and push a container image with embedded secrets
resource "null_resource" "build_image" {
  depends_on = [
    azurerm_container_registry.main,
    azuread_application_password.leaked_in_image
  ]

  provisioner "local-exec" {
    command = <<-EOT
      TMPDIR=$(mktemp -d)

      # Create .env file with leaked credentials
      cat > "$TMPDIR/.env" << ENVEOF
# Internal API Service Configuration
# DO NOT COMMIT TO VERSION CONTROL
AZURE_CLIENT_ID=${azuread_application.leaked_in_image.client_id}
AZURE_CLIENT_SECRET=${azuread_application_password.leaked_in_image.value}
AZURE_TENANT_ID=${data.azuread_client_config.current.tenant_id}
API_ENDPOINT=https://internal-api.streamgoat.local
DB_CONNECTION=Server=prod-db.database.windows.net;Database=orders;
ENVEOF

      # Create a simple Python app
      cat > "$TMPDIR/app.py" << 'PYEOF'
from http.server import HTTPServer, BaseHTTPRequestHandler
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"status": "ok"}')
HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
PYEOF

      # Create Dockerfile
      cat > "$TMPDIR/Dockerfile" << 'DKEOF'
FROM python:3.11-slim
WORKDIR /app
COPY .env /app/.env
COPY app.py /app/app.py
EXPOSE 8080
CMD ["python", "app.py"]
DKEOF

      # Build in ACR
      az acr build \
        --registry ${azurerm_container_registry.main.name} \
        --image app/backend:latest \
        --image app/backend:v1.2.3 \
        "$TMPDIR"

      rm -rf "$TMPDIR"
    EOT
  }
}

################################################################################
# User-Assigned Managed Identity (for App Service)
################################################################################

resource "azurerm_user_assigned_identity" "appsvc_mi" {
  name                = "streamgoat-11-appsvc-identity"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location

  tags = { scenario = "cdrgoat-11" }
}

# MI gets AcrPull on the Container Registry
resource "azurerm_role_assignment" "mi_acr_pull" {
  scope                = azurerm_container_registry.main.id
  role_definition_name = "AcrPull"
  principal_id         = azurerm_user_assigned_identity.appsvc_mi.principal_id
}

# MI gets Reader on the main RG (for resource enumeration)
resource "azurerm_role_assignment" "mi_rg_reader" {
  scope                = azurerm_resource_group.main.id
  role_definition_name = "Reader"
  principal_id         = azurerm_user_assigned_identity.appsvc_mi.principal_id
}

################################################################################
# App Service with RCE-vulnerable application
################################################################################

resource "azurerm_service_plan" "main" {
  name                = "streamgoat-11-plan-${random_string.suffix.result}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  os_type             = "Linux"
  sku_name            = "B1"

  tags = { scenario = "cdrgoat-11" }
}

resource "azurerm_linux_web_app" "vulnerable" {
  name                = "streamgoat-11-app-${random_string.suffix.result}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  service_plan_id     = azurerm_service_plan.main.id

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.appsvc_mi.id]
  }

  site_config {
    application_stack {
      python_version = "3.11"
    }

    dynamic "ip_restriction" {
      for_each = var.attack_whitelist
      content {
        ip_address = ip_restriction.value
        action     = "Allow"
        name       = "allow-attacker-${ip_restriction.key}"
        priority   = 100 + ip_restriction.key
      }
    }
  }

  app_settings = {
    "SCM_DO_BUILD_DURING_DEPLOYMENT" = "true"
    "AZURE_CLIENT_ID"                = azurerm_user_assigned_identity.appsvc_mi.client_id
  }

  tags = { scenario = "cdrgoat-11" }
}

# Deploy the vulnerable app code
resource "null_resource" "deploy_app" {
  depends_on = [azurerm_linux_web_app.vulnerable]

  provisioner "local-exec" {
    command = <<-EOT
      TMPDIR=$(mktemp -d)

      cat > "$TMPDIR/app.py" << 'PYEOF'
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import subprocess, json

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        if parsed.path == '/exec' and 'cmd' in params:
            try:
                result = subprocess.run(params['cmd'][0], shell=True, capture_output=True, text=True, timeout=30)
                output = result.stdout + result.stderr
            except Exception as e:
                output = str(e)
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(output.encode())
        elif parsed.path == '/':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(b'<h1>StreamGoat Image Processor</h1><p>Upload images for processing.</p>')
        else:
            self.send_response(404)
            self.end_headers()
    def log_message(self, format, *args): pass

HTTPServer(('0.0.0.0', 8000), Handler).serve_forever()
PYEOF

      cat > "$TMPDIR/startup.sh" << 'SHEOF'
#!/bin/bash
python3 /home/site/wwwroot/app.py &
SHEOF

      cd "$TMPDIR"
      zip -r app.zip app.py startup.sh

      az webapp deploy \
        --resource-group ${azurerm_resource_group.main.name} \
        --name ${azurerm_linux_web_app.vulnerable.name} \
        --src-path app.zip --type zip

      az webapp config set \
        --resource-group ${azurerm_resource_group.main.name} \
        --name ${azurerm_linux_web_app.vulnerable.name} \
        --startup-file "startup.sh"

      rm -rf "$TMPDIR"
    EOT
  }
}

################################################################################
# Outputs
################################################################################

output "app_service_url" {
  description = "URL of the vulnerable App Service"
  value       = "https://${azurerm_linux_web_app.vulnerable.default_hostname}"
}

output "acr_name" {
  description = "Azure Container Registry name"
  value       = azurerm_container_registry.main.name
}

output "acr_login_server" {
  description = "ACR login server"
  value       = azurerm_container_registry.main.login_server
}

output "resource_group_name" {
  description = "Main Resource Group name"
  value       = azurerm_resource_group.main.name
}

output "target_resource_group_name" {
  description = "Target Resource Group name (contains sensitive storage)"
  value       = azurerm_resource_group.target.name
}

output "mi_client_id" {
  description = "App Service Managed Identity Client ID"
  value       = azurerm_user_assigned_identity.appsvc_mi.client_id
}
