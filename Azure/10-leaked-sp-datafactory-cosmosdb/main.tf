################################################################################
# CDRGoat - Azure Scenario 10
# Leaked SP → Data Factory Pipeline Injection → Cosmos DB Exfiltration
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

# No attack_whitelist — entry point is leaked credentials

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
  name     = "streamgoat-10-rg-${random_string.suffix.result}"
  location = var.location

  tags = {
    scenario = "cdrgoat-10"
    purpose  = "security-training"
  }
}

################################################################################
# Leaked App Registration
################################################################################

resource "azuread_application" "leaked_app" {
  display_name = "streamgoat-10-data-pipeline-admin"
  tags         = ["cdrgoat", "scenario-10", "DO-NOT-USE-IN-PRODUCTION"]
}

resource "azuread_application_password" "leaked_secret" {
  application_id = azuread_application.leaked_app.id
  display_name   = "streamgoat-10-leaked-secret"
  end_date       = timeadd(timestamp(), "8760h")
}

resource "azuread_service_principal" "leaked_sp" {
  client_id = azuread_application.leaked_app.client_id
  tags      = ["cdrgoat", "scenario-10"]
}

# Reader on RG (for resource enumeration)
resource "azurerm_role_assignment" "leaked_sp_reader" {
  scope                = azurerm_resource_group.main.id
  role_definition_name = "Reader"
  principal_id         = azuread_service_principal.leaked_sp.object_id
}

# Data Factory Contributor on the Data Factory
resource "azurerm_role_assignment" "leaked_sp_adf_contributor" {
  scope                = azurerm_data_factory.main.id
  role_definition_name = "Data Factory Contributor"
  principal_id         = azuread_service_principal.leaked_sp.object_id
}

# Storage Blob Data Reader on the Storage Account (to read exfiltrated data)
resource "azurerm_role_assignment" "leaked_sp_blob_reader" {
  scope                = azurerm_storage_account.main.id
  role_definition_name = "Storage Blob Data Reader"
  principal_id         = azuread_service_principal.leaked_sp.object_id
}

################################################################################
# Cosmos DB Account + Database + Container
################################################################################

resource "azurerm_cosmosdb_account" "main" {
  name                = "streamgoat10cosmos${random_string.suffix.result}"
  location            = var.location
  resource_group_name = azurerm_resource_group.main.name
  offer_type          = "Standard"
  kind                = "GlobalDocumentDB"

  capabilities {
    name = "EnableServerless"
  }

  consistency_policy {
    consistency_level = "Session"
  }

  geo_location {
    location          = var.location
    failover_priority = 0
  }

  tags = { scenario = "cdrgoat-10" }
}

resource "azurerm_cosmosdb_sql_database" "main" {
  name                = "customersdb"
  resource_group_name = azurerm_resource_group.main.name
  account_name        = azurerm_cosmosdb_account.main.name
}

resource "azurerm_cosmosdb_sql_container" "customers" {
  name                = "customers"
  resource_group_name = azurerm_resource_group.main.name
  account_name        = azurerm_cosmosdb_account.main.name
  database_name       = azurerm_cosmosdb_sql_database.main.name
  partition_key_path  = "/id"
}

# Seed sample data
resource "null_resource" "seed_cosmos_data" {
  depends_on = [azurerm_cosmosdb_sql_container.customers]

  provisioner "local-exec" {
    command = <<-EOT
      COSMOS_KEY=$(az cosmosdb keys list --name ${azurerm_cosmosdb_account.main.name} --resource-group ${azurerm_resource_group.main.name} --query primaryMasterKey -o tsv)
      COSMOS_ENDPOINT="${azurerm_cosmosdb_account.main.endpoint}"

      for i in 1 2 3 4 5; do
        az cosmosdb sql container create --account-name ${azurerm_cosmosdb_account.main.name} \
          --resource-group ${azurerm_resource_group.main.name} \
          --database-name customersdb --name customers \
          --partition-key-path /id 2>/dev/null || true

        # Use REST API to insert documents
        DATE=$(date -u '+%a, %d %b %Y %H:%M:%S GMT')
        az rest --method post \
          --url "$${COSMOS_ENDPOINT}dbs/customersdb/colls/customers/docs" \
          --headers "x-ms-date=$DATE" "x-ms-version=2018-12-31" "Content-Type=application/json" \
          --body "{\"id\":\"customer-$i\",\"name\":\"Customer $i\",\"email\":\"customer$i@example.com\",\"ssn\":\"$((100+i))-$((40+i))-$((6000+i))\",\"balance\":$((i*15000))}" \
          --resource "https://${azurerm_cosmosdb_account.main.name}.documents.azure.com" 2>/dev/null || true
      done
    EOT
  }
}

################################################################################
# Key Vault (stores Cosmos DB connection string)
################################################################################

resource "azurerm_key_vault" "main" {
  name                       = "stgoat10kv${random_string.suffix.result}"
  location                   = var.location
  resource_group_name        = azurerm_resource_group.main.name
  tenant_id                  = data.azuread_client_config.current.tenant_id
  sku_name                   = "standard"
  enable_rbac_authorization  = true
  purge_protection_enabled   = false
  soft_delete_retention_days = 7

  tags = { scenario = "cdrgoat-10" }
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

resource "azurerm_key_vault_secret" "cosmos_connection" {
  name         = "cosmos-connection-string"
  value        = azurerm_cosmosdb_account.main.primary_sql_connection_string
  key_vault_id = azurerm_key_vault.main.id
  depends_on   = [null_resource.wait_for_kv_rbac]
}

# Data Factory MI can read Key Vault secrets
resource "azurerm_role_assignment" "adf_kv_reader" {
  scope                = azurerm_key_vault.main.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_data_factory.main.identity[0].principal_id
}

################################################################################
# Storage Account (pipeline output sink)
################################################################################

resource "azurerm_storage_account" "main" {
  name                     = "stgoat10data${random_string.suffix.result}"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = var.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  tags = { scenario = "cdrgoat-10" }
}

resource "azurerm_storage_container" "backups" {
  name                  = "backups"
  storage_account_name  = azurerm_storage_account.main.name
  container_access_type = "private"
}

resource "azurerm_storage_container" "exfil" {
  name                  = "exfiltrated"
  storage_account_name  = azurerm_storage_account.main.name
  container_access_type = "private"
}

# ADF MI can write to storage
resource "azurerm_role_assignment" "adf_storage_contributor" {
  scope                = azurerm_storage_account.main.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_data_factory.main.identity[0].principal_id
}

################################################################################
# Azure Data Factory
################################################################################

resource "azurerm_data_factory" "main" {
  name                = "streamgoat10adf${random_string.suffix.result}"
  location            = var.location
  resource_group_name = azurerm_resource_group.main.name

  identity {
    type = "SystemAssigned"
  }

  tags = { scenario = "cdrgoat-10" }
}

# Linked Service: Cosmos DB (uses Key Vault for connection string)
resource "azurerm_data_factory_linked_service_key_vault" "main" {
  name            = "KeyVaultLinkedService"
  data_factory_id = azurerm_data_factory.main.id
  key_vault_id    = azurerm_key_vault.main.id
}

resource "azurerm_data_factory_linked_service_cosmosdb" "main" {
  name             = "CosmosDbLinkedService"
  data_factory_id  = azurerm_data_factory.main.id
  account_endpoint = azurerm_cosmosdb_account.main.endpoint
  account_key      = azurerm_cosmosdb_account.main.primary_key
  database         = "customersdb"
}

# Linked Service: Blob Storage
resource "azurerm_data_factory_linked_service_azure_blob_storage" "main" {
  name              = "BlobStorageLinkedService"
  data_factory_id   = azurerm_data_factory.main.id
  connection_string = azurerm_storage_account.main.primary_connection_string
}

# Dataset: Cosmos DB source
resource "azurerm_data_factory_dataset_cosmosdb_sqlapi" "customers" {
  name                = "CosmosCustomersDataset"
  data_factory_id     = azurerm_data_factory.main.id
  linked_service_name = azurerm_data_factory_linked_service_cosmosdb.main.name
  collection_name     = "customers"
}

# Dataset: Blob Storage sink
resource "azurerm_data_factory_dataset_json" "blob_sink" {
  name                = "BlobSinkDataset"
  data_factory_id     = azurerm_data_factory.main.id
  linked_service_name = azurerm_data_factory_linked_service_azure_blob_storage.main.name

  azure_blob_storage_location {
    container = azurerm_storage_container.backups.name
    path      = "daily-export"
    filename  = "customers.json"
  }

  encoding = "UTF-8"
}

# Legitimate pipeline: daily backup
resource "azurerm_data_factory_pipeline" "daily_backup" {
  name            = "daily-backup-pipeline"
  data_factory_id = azurerm_data_factory.main.id

  activities_json = jsonencode([
    {
      name = "CopyCosmosToBlob"
      type = "Copy"
      inputs = [
        { referenceName = azurerm_data_factory_dataset_cosmosdb_sqlapi.customers.name, type = "DatasetReference" }
      ]
      outputs = [
        { referenceName = azurerm_data_factory_dataset_json.blob_sink.name, type = "DatasetReference" }
      ]
      typeProperties = {
        source = {
          type = "CosmosDbSqlApiSource"
          query = "SELECT * FROM c"
        }
        sink = {
          type = "JsonSink"
          storeSettings = {
            type = "AzureBlobStorageWriteSettings"
          }
          formatSettings = {
            type = "JsonWriteSettings"
          }
        }
      }
    }
  ])
}

################################################################################
# Outputs
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

output "data_factory_name" {
  description = "Data Factory name"
  value       = azurerm_data_factory.main.name
}

output "storage_account_name" {
  description = "Storage Account name"
  value       = azurerm_storage_account.main.name
}
