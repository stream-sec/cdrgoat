################################################################################
# CDRGoat - Azure Scenario 5
# SSRF on Function App → Blind SP Credential Injection via addPassword
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
  description = "List of CIDRs allowed to reach the Function App"
  type        = list(string)
  default     = []
}

################################################################################
# Data Sources
################################################################################

data "azuread_client_config" "current" {}

data "azurerm_subscription" "current" {}

# Microsoft Graph well-known service principal
data "azuread_service_principal" "msgraph" {
  client_id = "00000003-0000-0000-c000-000000000000"
}

################################################################################
# Random Suffix
################################################################################

resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

################################################################################
# Resource Group
################################################################################

resource "azurerm_resource_group" "main" {
  name     = "streamgoat-5-rg-${random_string.suffix.result}"
  location = var.location

  tags = {
    scenario = "cdrgoat-5"
    purpose  = "security-training"
  }
}

################################################################################
# User-Assigned Managed Identity (for Function App)
################################################################################

resource "azurerm_user_assigned_identity" "func_mi" {
  name                = "streamgoat-5-func-identity"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location

  tags = {
    scenario = "cdrgoat-5"
  }
}

################################################################################
# App Registrations (targets for blind enumeration)
################################################################################

resource "azuread_application" "apps" {
  for_each     = toset(["analytics", "billing", "reports", "backup", "deploy"])
  display_name = "StreamGoat-App-${each.key}"

  tags = ["cdrgoat", "scenario-5"]
}

resource "azuread_service_principal" "apps" {
  for_each  = azuread_application.apps
  client_id = each.value.client_id
  tags      = ["cdrgoat", "scenario-5"]
}

# Set the Function MI as owner of all App Registrations
resource "azuread_application_owner" "mi_owns_apps" {
  for_each        = azuread_application.apps
  application_id  = each.value.id
  owner_object_id = azurerm_user_assigned_identity.func_mi.principal_id
}

################################################################################
# Grant Function MI "Application.ReadWrite.OwnedBy" on Microsoft Graph
################################################################################

resource "azuread_app_role_assignment" "mi_app_readwrite_owned" {
  app_role_id         = [for r in data.azuread_service_principal.msgraph.app_roles : r.id if r.value == "Application.ReadWrite.OwnedBy"][0]
  principal_object_id = azurerm_user_assigned_identity.func_mi.principal_id
  resource_object_id  = data.azuread_service_principal.msgraph.object_id
}

################################################################################
# One App Registration gets Contributor on the RG (the prize)
################################################################################

resource "azurerm_role_assignment" "app_deploy_contributor" {
  scope                = azurerm_resource_group.main.id
  role_definition_name = "Contributor"
  principal_id         = azuread_service_principal.apps["deploy"].object_id
}

################################################################################
# Storage Account with sensitive data (exfiltration target)
################################################################################

resource "azurerm_storage_account" "sensitive" {
  name                     = "stgoat5data${random_string.suffix.result}"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  tags = {
    scenario = "cdrgoat-5"
  }
}

resource "azurerm_storage_container" "exports" {
  name                  = "customer-exports"
  storage_account_name  = azurerm_storage_account.sensitive.name
  container_access_type = "private"
}

resource "azurerm_storage_blob" "sample_data" {
  name                   = "customer-export-2024.csv"
  storage_account_name   = azurerm_storage_account.sensitive.name
  storage_container_name = azurerm_storage_container.exports.name
  type                   = "Block"
  source_content         = "id,name,email,ssn\n1,John Smith,john@example.com,123-45-6789\n2,Jane Doe,jane@example.com,987-65-4321\n3,Bob Wilson,bob@example.com,456-78-9012\n"
}

# Grant the "deploy" app Storage Blob Data Reader so it can exfiltrate
resource "azurerm_role_assignment" "app_deploy_storage_reader" {
  scope                = azurerm_storage_account.sensitive.id
  role_definition_name = "Storage Blob Data Reader"
  principal_id         = azuread_service_principal.apps["deploy"].object_id
}

################################################################################
# Function App with SSRF-vulnerable endpoint
################################################################################

resource "azurerm_storage_account" "func_storage" {
  name                     = "stgoat5func${random_string.suffix.result}"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  tags = {
    scenario = "cdrgoat-5"
  }
}

resource "azurerm_service_plan" "main" {
  name                = "streamgoat-5-plan-${random_string.suffix.result}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  os_type             = "Linux"
  sku_name            = "Y1"

  tags = {
    scenario = "cdrgoat-5"
  }
}

resource "azurerm_linux_function_app" "vulnerable" {
  name                       = "streamgoat-5-func-${random_string.suffix.result}"
  resource_group_name        = azurerm_resource_group.main.name
  location                   = azurerm_resource_group.main.location
  storage_account_name       = azurerm_storage_account.func_storage.name
  storage_account_access_key = azurerm_storage_account.func_storage.primary_access_key
  service_plan_id            = azurerm_service_plan.main.id

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.func_mi.id]
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
    "FUNCTIONS_WORKER_RUNTIME"       = "python"
    "AzureWebJobsFeatureFlags"       = "EnableWorkerIndexing"
    "AZURE_CLIENT_ID"                = azurerm_user_assigned_identity.func_mi.client_id
    "SCM_DO_BUILD_DURING_DEPLOYMENT" = "true"
  }

  tags = {
    scenario = "cdrgoat-5"
  }
}

################################################################################
# Deploy the SSRF-vulnerable function code
################################################################################

resource "null_resource" "deploy_function" {
  depends_on = [azurerm_linux_function_app.vulnerable]

  provisioner "local-exec" {
    command = <<-EOT
      TMPDIR=$(mktemp -d)

      cat > "$TMPDIR/function_app.py" << 'PYEOF'
import azure.functions as func
import logging
import urllib.request
import ssl
import os
import json

app = func.FunctionApp()

@app.route(route="fetch", auth_level=func.AuthLevel.ANONYMOUS)
def fetch_url(req: func.HttpRequest) -> func.HttpResponse:
    url = req.params.get('url')
    if not url:
        try:
            body = req.get_json()
            url = body.get('url')
        except:
            pass
    if not url:
        return func.HttpResponse("Pass a URL in the 'url' query parameter or JSON body", status_code=400)
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        headers = {"Metadata": "true"}
        # App uses MSI internally — identity header leaks into SSRF requests
        identity_header = os.environ.get("IDENTITY_HEADER")
        if identity_header:
            headers["X-IDENTITY-HEADER"] = identity_header
        req_obj = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req_obj, context=ctx, timeout=10) as resp:
            data = resp.read().decode("utf-8", errors="replace")
            return func.HttpResponse(data, status_code=resp.status)
    except Exception as e:
        return func.HttpResponse(f"Error: {str(e)}", status_code=502)

@app.route(route="health", auth_level=func.AuthLevel.ANONYMOUS)
def health_check(req: func.HttpRequest) -> func.HttpResponse:
    """Debug endpoint accidentally left in production — leaks environment."""
    debug_info = {
        "status": "healthy",
        "runtime": os.environ.get("FUNCTIONS_WORKER_RUNTIME"),
        "identity_endpoint": os.environ.get("IDENTITY_ENDPOINT"),
        "azure_client_id": os.environ.get("AZURE_CLIENT_ID"),
    }
    return func.HttpResponse(
        json.dumps(debug_info, indent=2),
        mimetype="application/json"
    )
PYEOF

      cat > "$TMPDIR/requirements.txt" << 'REQEOF'
azure-functions
REQEOF

      cat > "$TMPDIR/host.json" << 'HOSTEOF'
{
  "version": "2.0",
  "extensionBundle": {
    "id": "Microsoft.Azure.Functions.ExtensionBundle",
    "version": "[4.*, 5.0.0)"
  }
}
HOSTEOF

      cd "$TMPDIR"
      zip -r func.zip function_app.py requirements.txt host.json

      az functionapp deployment source config-zip \
        -g "${azurerm_resource_group.main.name}" \
        -n "${azurerm_linux_function_app.vulnerable.name}" \
        --src func.zip

      rm -rf "$TMPDIR"
    EOT
  }
}

################################################################################
# Outputs
################################################################################

output "function_app_url" {
  description = "Base URL of the vulnerable Function App"
  value       = "https://${azurerm_linux_function_app.vulnerable.default_hostname}"
}