################################################################################
# CDRGoat - Azure Scenario 3
# Leaked App Registration → VM Deployment → UAMI Privilege Escalation
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

################################################################################
# Data Sources
################################################################################

data "azuread_client_config" "current" {}

data "azurerm_subscription" "current" {}

################################################################################
# Random Suffix for Unique Names
################################################################################

resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

resource "random_password" "keyvault_secret" {
  length  = 32
  special = true
}

################################################################################
# Resource Group
################################################################################

resource "azurerm_resource_group" "main" {
  name     = "streamgoat-3-rg-${random_string.suffix.result}"
  location = var.location

  tags = {
    scenario = "cdrgoat-3"
    purpose  = "security-training"
  }
}

################################################################################
# App Registration (credentials will be "leaked")
################################################################################

resource "azuread_application" "leaked_app" {
  display_name = "streamgoat-3-devops-automation"

  tags = ["cdrgoat", "scenario-3", "DO-NOT-USE-IN-PRODUCTION"]
}

resource "azuread_application_password" "leaked_secret" {
  application_id = azuread_application.leaked_app.id
  display_name   = "streamgoat-3-leaked-secret"
  end_date       = timeadd(timestamp(), "8760h") # 1 year
}

resource "azuread_service_principal" "leaked_sp" {
  client_id = azuread_application.leaked_app.client_id
  tags      = ["cdrgoat", "scenario-3"]
}

################################################################################
# User-Assigned Managed Identity (overprivileged - has User Access Admin)
################################################################################

resource "azurerm_user_assigned_identity" "privileged_uami" {
  name                = "streamgoat-3-deployment-identity"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location

  tags = {
    scenario = "cdrgoat-3"
    purpose  = "deployment-automation"
  }
}

################################################################################
# Role Assignments
################################################################################

# Leaked App SP gets Contributor on Resource Group (can deploy VMs)
resource "azurerm_role_assignment" "leaked_sp_contributor" {
  scope                = azurerm_resource_group.main.id
  role_definition_name = "Contributor"
  principal_id         = azuread_service_principal.leaked_sp.object_id
}

# CRITICAL MISCONFIGURATION: UAMI has User Access Administrator at Resource Group scope
# This allows the UAMI to grant any RBAC role to any principal on resources in this RG
# Common misconfiguration: "UAMI needs to manage access for deployments in this RG"
resource "azurerm_role_assignment" "uami_user_access_admin" {
  scope                = azurerm_resource_group.main.id
  role_definition_name = "User Access Administrator"
  principal_id         = azurerm_user_assigned_identity.privileged_uami.principal_id
}

################################################################################
# Key Vault (sensitive data to exfiltrate)
################################################################################

resource "azurerm_key_vault" "sensitive" {
  name                       = "streamgoat3kv${random_string.suffix.result}"
  location                   = var.location
  resource_group_name        = azurerm_resource_group.main.name
  tenant_id                  = data.azuread_client_config.current.tenant_id
  sku_name                   = "standard"
  enable_rbac_authorization  = true
  purge_protection_enabled   = false
  soft_delete_retention_days = 7

  tags = {
    scenario = "cdrgoat-3"
  }
}

# Terraform deployer can write secrets
resource "azurerm_role_assignment" "tf_kv_officer" {
  scope                = azurerm_key_vault.sensitive.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = data.azuread_client_config.current.object_id
}

# Wait for RBAC propagation
resource "null_resource" "wait_for_kv_rbac" {
  depends_on = [azurerm_role_assignment.tf_kv_officer]
  provisioner "local-exec" {
    command = "sleep 60"
  }
}

# Store sensitive secrets
resource "azurerm_key_vault_secret" "db_connection" {
  name         = "production-database-connection-string"
  value        = "Server=prod-sql.database.windows.net;Database=customers;User Id=admin;Password=${random_password.keyvault_secret.result};"
  key_vault_id = azurerm_key_vault.sensitive.id
  depends_on   = [null_resource.wait_for_kv_rbac]
}

resource "azurerm_key_vault_secret" "api_key" {
  name         = "stripe-api-key"
  value        = "sk_live_${random_string.suffix.result}${random_password.keyvault_secret.result}"
  key_vault_id = azurerm_key_vault.sensitive.id
  depends_on   = [null_resource.wait_for_kv_rbac]
}

resource "azurerm_key_vault_secret" "admin_creds" {
  name         = "admin-service-account"
  value        = "{\"username\": \"svc_admin\", \"password\": \"${random_password.keyvault_secret.result}\"}"
  key_vault_id = azurerm_key_vault.sensitive.id
  depends_on   = [null_resource.wait_for_kv_rbac]
}

################################################################################
# Outputs (simulating "leaked" credentials)
################################################################################

output "leaked_credentials" {
  description = "Simulated leaked App Registration credentials (e.g., found in GitHub)"
  sensitive   = true
  value = {
    client_id     = azuread_application.leaked_app.client_id
    client_secret = azuread_application_password.leaked_secret.value
    tenant_id     = data.azuread_client_config.current.tenant_id
  }
}
