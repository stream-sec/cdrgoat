################################################################################
# CDRGoat - Azure Scenario 9
# Leaked SP → ARM Deployment History → Secret Extraction → SQL Database
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

# No attack_whitelist — entry point is leaked credentials, not a vulnerable app

################################################################################
# Data Sources
################################################################################

data "azuread_client_config" "current" {}

data "azurerm_subscription" "current" {}

################################################################################
# Random Suffix & Passwords
################################################################################

resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

resource "random_password" "sql_admin" {
  length           = 24
  special          = true
  override_special = "!@#$%"
}

################################################################################
# Resource Group
################################################################################

resource "azurerm_resource_group" "main" {
  name     = "streamgoat-9-rg-${random_string.suffix.result}"
  location = var.location

  tags = {
    scenario = "cdrgoat-9"
    purpose  = "security-training"
  }
}

################################################################################
# Leaked App Registration (Reader on RG — seemingly low privilege)
################################################################################

resource "azuread_application" "leaked_app" {
  display_name = "streamgoat-9-monitoring-reader"
  tags         = ["cdrgoat", "scenario-9", "DO-NOT-USE-IN-PRODUCTION"]
}

resource "azuread_application_password" "leaked_secret" {
  application_id = azuread_application.leaked_app.id
  display_name   = "streamgoat-9-leaked-secret"
  end_date       = timeadd(timestamp(), "8760h")
}

resource "azuread_service_principal" "leaked_sp" {
  client_id = azuread_application.leaked_app.client_id
  tags      = ["cdrgoat", "scenario-9"]
}

# Only Reader on the Resource Group — appears low privilege
resource "azurerm_role_assignment" "leaked_sp_reader" {
  scope                = azurerm_resource_group.main.id
  role_definition_name = "Reader"
  principal_id         = azuread_service_principal.leaked_sp.object_id
}

################################################################################
# Azure SQL Server & Database
################################################################################

resource "azurerm_mssql_server" "main" {
  name                         = "streamgoat9sql${random_string.suffix.result}"
  resource_group_name          = azurerm_resource_group.main.name
  location                     = var.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = random_password.sql_admin.result

  tags = { scenario = "cdrgoat-9" }
}

resource "azurerm_mssql_database" "main" {
  name      = "customers"
  server_id = azurerm_mssql_server.main.id
  sku_name  = "Basic"

  tags = { scenario = "cdrgoat-9" }
}

# Allow Azure services + all IPs (intentionally insecure for the lab)
resource "azurerm_mssql_firewall_rule" "allow_azure" {
  name             = "AllowAzureServices"
  server_id        = azurerm_mssql_server.main.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "0.0.0.0"
}

resource "azurerm_mssql_firewall_rule" "allow_all" {
  name             = "AllowAll"
  server_id        = azurerm_mssql_server.main.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "255.255.255.255"
}

################################################################################
# Key Vault (access denied for the leaked SP — red herring)
################################################################################

resource "azurerm_key_vault" "decoy" {
  name                       = "stgoat9kv${random_string.suffix.result}"
  location                   = var.location
  resource_group_name        = azurerm_resource_group.main.name
  tenant_id                  = data.azuread_client_config.current.tenant_id
  sku_name                   = "standard"
  enable_rbac_authorization  = true
  purge_protection_enabled   = false
  soft_delete_retention_days = 7

  tags = { scenario = "cdrgoat-9" }
}

################################################################################
# Storage Account (visible but not the target)
################################################################################

resource "azurerm_storage_account" "decoy" {
  name                     = "stgoat9store${random_string.suffix.result}"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = var.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  tags = { scenario = "cdrgoat-9" }
}

################################################################################
# ARM Template Deployment (creates the secret leak in deployment history)
#
# This simulates a previous infrastructure deployment that passed the SQL
# admin password as a parameter. Even though the parameter uses secureString,
# the OUTPUT concatenates it into a regular string — stored in plaintext
# in the ARM deployment history. Reader role can read this.
################################################################################

resource "azurerm_resource_group_template_deployment" "secret_leak" {
  name                = "initial-db-setup"
  resource_group_name = azurerm_resource_group.main.name
  deployment_mode     = "Incremental"

  parameters_content = jsonencode({
    "sqlAdminPassword" = { value = random_password.sql_admin.result }
    "sqlServerName"    = { value = azurerm_mssql_server.main.name }
    "sqlAdminUser"     = { value = "sqladmin" }
  })

  template_content = <<TEMPLATE
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "sqlAdminPassword": {
      "type": "secureString",
      "metadata": { "description": "SQL Server admin password" }
    },
    "sqlServerName": {
      "type": "string",
      "metadata": { "description": "SQL Server name" }
    },
    "sqlAdminUser": {
      "type": "string",
      "metadata": { "description": "SQL Server admin username" }
    }
  },
  "resources": [],
  "outputs": {
    "connectionString": {
      "type": "string",
      "value": "[concat('Server=tcp:', parameters('sqlServerName'), '.database.windows.net,1433;Database=customers;User Id=', parameters('sqlAdminUser'), ';Password=', parameters('sqlAdminPassword'), ';')]"
    },
    "serverFqdn": {
      "type": "string",
      "value": "[concat(parameters('sqlServerName'), '.database.windows.net')]"
    }
  }
}
TEMPLATE

  depends_on = [azurerm_mssql_server.main]
}

################################################################################
# Outputs (simulating leaked credentials)
################################################################################

output "leaked_credentials" {
  description = "Simulated leaked SP credentials"
  sensitive   = true
  value = {
    client_id     = azuread_application.leaked_app.client_id
    client_secret = azuread_application_password.leaked_secret.value
    tenant_id     = data.azuread_client_config.current.tenant_id
  }
}

output "resource_group_name" {
  description = "Resource Group name"
  value       = azurerm_resource_group.main.name
}

output "sql_server_fqdn" {
  description = "SQL Server FQDN"
  value       = azurerm_mssql_server.main.fully_qualified_domain_name
}
