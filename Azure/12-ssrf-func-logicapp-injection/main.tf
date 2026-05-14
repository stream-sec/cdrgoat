################################################################################
# CDRGoat - Azure Scenario 12
# SSRF on Function App → MI → Logic App Workflow Injection → Key Vault →
# Service Bus Message Theft
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
  name     = "streamgoat-12-rg-${random_string.suffix.result}"
  location = var.location

  tags = {
    scenario = "cdrgoat-12"
    purpose  = "security-training"
  }
}

################################################################################
# User-Assigned Managed Identity (for Function App)
# Has Logic App Contributor on the RG
################################################################################

resource "azurerm_user_assigned_identity" "func_mi" {
  name                = "streamgoat-12-func-identity"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location

  tags = { scenario = "cdrgoat-12" }
}

resource "azurerm_role_assignment" "func_mi_logic_contributor" {
  scope                = azurerm_resource_group.main.id
  role_definition_name = "Logic App Contributor"
  principal_id         = azurerm_user_assigned_identity.func_mi.principal_id
}

resource "azurerm_role_assignment" "func_mi_reader" {
  scope                = azurerm_resource_group.main.id
  role_definition_name = "Reader"
  principal_id         = azurerm_user_assigned_identity.func_mi.principal_id
}

################################################################################
# Service Bus Namespace + Queue
################################################################################

resource "azurerm_servicebus_namespace" "main" {
  name                = "stgoat12sb${random_string.suffix.result}"
  location            = var.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "Basic"

  tags = { scenario = "cdrgoat-12" }
}

resource "azurerm_servicebus_queue" "orders" {
  name         = "incoming-orders"
  namespace_id = azurerm_servicebus_namespace.main.id
}

# Create a SAS policy with Listen rights (stored in Key Vault)
resource "azurerm_servicebus_namespace_authorization_rule" "listen" {
  name         = "ListenPolicy"
  namespace_id = azurerm_servicebus_namespace.main.id
  listen       = true
  send         = false
  manage       = false
}

resource "azurerm_servicebus_namespace_authorization_rule" "send" {
  name         = "SendPolicy"
  namespace_id = azurerm_servicebus_namespace.main.id
  listen       = false
  send         = true
  manage       = false
}

################################################################################
# Key Vault
################################################################################

resource "azurerm_key_vault" "main" {
  name                       = "stgoat12kv${random_string.suffix.result}"
  location                   = var.location
  resource_group_name        = azurerm_resource_group.main.name
  tenant_id                  = data.azuread_client_config.current.tenant_id
  sku_name                   = "standard"
  enable_rbac_authorization  = true
  purge_protection_enabled   = false
  soft_delete_retention_days = 7

  tags = { scenario = "cdrgoat-12" }
}

# Terraform deployer can write secrets
resource "azurerm_role_assignment" "tf_kv_officer" {
  scope                = azurerm_key_vault.main.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = data.azuread_client_config.current.object_id
}

resource "null_resource" "wait_for_kv_rbac" {
  depends_on = [azurerm_role_assignment.tf_kv_officer]
  provisioner "local-exec" {
    command = "sleep 60"
  }
}

# Store Service Bus connection string with Listen rights in Key Vault
resource "azurerm_key_vault_secret" "sb_listen_connection" {
  name         = "servicebus-listen-connection"
  value        = azurerm_servicebus_namespace_authorization_rule.listen.primary_connection_string
  key_vault_id = azurerm_key_vault.main.id
  depends_on   = [null_resource.wait_for_kv_rbac]
}

# Store Service Bus Send connection string
resource "azurerm_key_vault_secret" "sb_send_connection" {
  name         = "servicebus-send-connection"
  value        = azurerm_servicebus_namespace_authorization_rule.send.primary_connection_string
  key_vault_id = azurerm_key_vault.main.id
  depends_on   = [null_resource.wait_for_kv_rbac]
}

################################################################################
# Logic App (Consumption tier)
################################################################################

resource "azurerm_logic_app_workflow" "order_processor" {
  name                = "streamgoat-12-order-processor"
  location            = var.location
  resource_group_name = azurerm_resource_group.main.name

  identity {
    type = "SystemAssigned"
  }

  tags = { scenario = "cdrgoat-12" }
}

# Logic App MI gets Key Vault Secrets User
resource "azurerm_role_assignment" "logic_kv_reader" {
  scope                = azurerm_key_vault.main.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_logic_app_workflow.order_processor.identity[0].principal_id
}

# Logic App MI gets Service Bus Data Sender
resource "azurerm_role_assignment" "logic_sb_sender" {
  scope                = azurerm_servicebus_namespace.main.id
  role_definition_name = "Azure Service Bus Data Sender"
  principal_id         = azurerm_logic_app_workflow.order_processor.identity[0].principal_id
}

# HTTP trigger
resource "azurerm_logic_app_trigger_http_request" "order_trigger" {
  name         = "order-webhook"
  logic_app_id = azurerm_logic_app_workflow.order_processor.id

  schema = <<SCHEMA
{
  "type": "object",
  "properties": {
    "orderId": { "type": "string" },
    "customer": { "type": "string" },
    "amount": { "type": "number" },
    "items": { "type": "array" }
  }
}
SCHEMA
}

# Action: Get Key Vault secret (HTTP action using MI)
resource "azurerm_logic_app_action_http" "get_kv_secret" {
  name         = "Get-ServiceBus-Secret"
  logic_app_id = azurerm_logic_app_workflow.order_processor.id

  method = "GET"
  uri    = "${azurerm_key_vault.main.vault_uri}secrets/servicebus-send-connection?api-version=7.4"

  headers = {
    "Content-Type" = "application/json"
  }

  run_after {}
}

################################################################################
# Function App with SSRF vulnerability
################################################################################

resource "azurerm_storage_account" "func_storage" {
  name                     = "stgoat12func${random_string.suffix.result}"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = var.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  tags = { scenario = "cdrgoat-12" }
}

resource "azurerm_service_plan" "main" {
  name                = "streamgoat-12-plan-${random_string.suffix.result}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  os_type             = "Linux"
  sku_name            = "Y1"

  tags = { scenario = "cdrgoat-12" }
}

resource "azurerm_linux_function_app" "vulnerable" {
  name                       = "streamgoat-12-func-${random_string.suffix.result}"
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

  tags = { scenario = "cdrgoat-12" }
}

# Deploy SSRF-vulnerable function code
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
        return func.HttpResponse("Pass a URL in the 'url' query parameter", status_code=400)
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        headers = {"Metadata": "true"}
        req_obj = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req_obj, context=ctx, timeout=10) as resp:
            data = resp.read().decode("utf-8", errors="replace")
            return func.HttpResponse(data, status_code=resp.status)
    except Exception as e:
        return func.HttpResponse(f"Error: {str(e)}", status_code=502)
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
        --src-path func.zip

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

output "logic_app_name" {
  description = "Logic App workflow name"
  value       = azurerm_logic_app_workflow.order_processor.name
}

output "logic_app_trigger_url" {
  description = "Logic App HTTP trigger URL"
  value       = azurerm_logic_app_trigger_http_request.order_trigger.callback_url
  sensitive   = true
}

output "resource_group_name" {
  description = "Resource Group name"
  value       = azurerm_resource_group.main.name
}

output "subscription_id" {
  description = "Subscription ID"
  value       = data.azurerm_subscription.current.subscription_id
}

output "tenant_id" {
  description = "Tenant ID"
  value       = data.azuread_client_config.current.tenant_id
}

output "mi_client_id" {
  description = "Function App MI Client ID"
  value       = azurerm_user_assigned_identity.func_mi.client_id
}
