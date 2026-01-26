################################################################################
# CDRGoat - Azure Scenario 2
# LFI on Function App → Storage Credential Theft → AppRoleAssignment Privesc
################################################################################

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.80"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.45"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
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
  description = "List of CIDR blocks allowed to access the Function App"
  type        = list(string)
  default     = []
}

################################################################################
# Data Sources
################################################################################

data "azuread_client_config" "current" {}

data "azuread_domains" "default" {
  only_initial = true
}

data "azurerm_subscription" "current" {}

################################################################################
# Random Suffix for Unique Names
################################################################################

resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

resource "random_password" "target_user" {
  length           = 16
  special          = true
  override_special = "!@#$%"
}

################################################################################
# Resource Group
################################################################################

resource "azurerm_resource_group" "main" {
  name     = "streamgoat-2-rg-${random_string.suffix.result}"
  location = var.location

  tags = {
    scenario = "cdrgoat-2"
    purpose  = "security-training"
  }
}

################################################################################
# Storage Account (for Function App AND backup blob)
################################################################################

resource "azurerm_storage_account" "main" {
  name                     = "streamgoat2sa${random_string.suffix.result}"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  # Security settings - no public access
  allow_nested_items_to_be_public = false
  public_network_access_enabled   = true  # Needed for function app, but blobs are private
  min_tls_version                 = "TLS1_2"

  # Note: shared_access_key_enabled must stay true for Function App runtime
  # The function app uses SAS to access its code package
  # Blobs are protected by container_access_type = "private"

  tags = {
    scenario = "cdrgoat-2"
  }
}

# Container for "backups" (contains leaked credentials)
resource "azurerm_storage_container" "backups" {
  name                  = "backups"
  storage_account_name  = azurerm_storage_account.main.name
  container_access_type = "private"
}

# Container for Function App code
resource "azurerm_storage_container" "funccode" {
  name                  = "function-releases"
  storage_account_name  = azurerm_storage_account.main.name
  container_access_type = "private"
}

################################################################################
# App Registration with AppRoleAssignment.ReadWrite.All (DANGEROUS!)
################################################################################

resource "azuread_application" "privesc" {
  display_name = "streamgoat-2-backup-service"

  # Request AppRoleAssignment.ReadWrite.All - allows assigning app roles to any SP
  required_resource_access {
    resource_app_id = "00000003-0000-0000-c000-000000000000" # Microsoft Graph

    resource_access {
      id   = "06b708a9-e830-4db3-a914-8e69da51d44f" # AppRoleAssignment.ReadWrite.All
      type = "Role"                                 # Application permission
    }
  }

  tags = ["cdrgoat", "scenario-2", "DO-NOT-USE-IN-PRODUCTION"]
}

resource "azuread_application_password" "privesc" {
  application_id = azuread_application.privesc.id
  display_name   = "streamgoat-2-backup-secret"
  end_date       = timeadd(timestamp(), "8760h") # 1 year
}

resource "azuread_service_principal" "privesc" {
  client_id = azuread_application.privesc.client_id
  tags      = ["cdrgoat", "scenario-2"]
}

# Grant admin consent for the app (requires Global Admin running terraform)
resource "azuread_app_role_assignment" "privesc_approle" {
  app_role_id         = "06b708a9-e830-4db3-a914-8e69da51d44f" # AppRoleAssignment.ReadWrite.All
  principal_object_id = azuread_service_principal.privesc.object_id
  resource_object_id  = data.azuread_service_principal.msgraph.object_id
}

data "azuread_service_principal" "msgraph" {
  client_id = "00000003-0000-0000-c000-000000000000" # Microsoft Graph
}

################################################################################
# Backup Blob with Leaked Credentials
################################################################################

resource "azurerm_storage_blob" "backup_info" {
  name                   = "app_backup_info.txt"
  storage_account_name   = azurerm_storage_account.main.name
  storage_container_name = azurerm_storage_container.backups.name
  type                   = "Block"
  source_content         = <<-EOT
    ############################################
    # Backup Service - Application Credentials
    # DO NOT SHARE - INTERNAL USE ONLY
    ############################################
    
    # Azure AD Application Details
    APP_NAME=streamgoat-2-backup-service
    CLIENT_ID=${azuread_application.privesc.client_id}
    CLIENT_SECRET=${azuread_application_password.privesc.value}
    TENANT_ID=${data.azuread_client_config.current.tenant_id}
    
    # Notes:
    # - This service account is used for automated backup operations
    # - Contact: admin@${data.azuread_domains.default.domains[0].domain_name}
  EOT
}

################################################################################
# Function App (Vulnerable to LFI/Command Injection)
################################################################################

resource "azurerm_service_plan" "main" {
  name                = "streamgoat-2-asp-${random_string.suffix.result}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  os_type             = "Linux"
  sku_name            = "B1" # Basic plan (more widely available than Consumption Y1)

  tags = {
    scenario = "cdrgoat-2"
  }
}

# Package the function app code
data "archive_file" "functionapp" {
  type        = "zip"
  source_dir  = "${path.module}/functionapp"
  output_path = "${path.module}/functionapp.zip"
}

resource "azurerm_storage_blob" "functionapp" {
  name                   = "functionapp-${data.archive_file.functionapp.output_md5}.zip"
  storage_account_name   = azurerm_storage_account.main.name
  storage_container_name = azurerm_storage_container.funccode.name
  type                   = "Block"
  source                 = data.archive_file.functionapp.output_path
}

data "azurerm_storage_account_sas" "functionapp" {
  connection_string = azurerm_storage_account.main.primary_connection_string
  https_only        = true
  start             = timestamp()
  expiry            = timeadd(timestamp(), "8760h")

  resource_types {
    service   = false
    container = false
    object    = true
  }

  services {
    blob  = true
    queue = false
    table = false
    file  = false
  }

  permissions {
    read    = true
    write   = false
    delete  = false
    list    = false
    add     = false
    create  = false
    update  = false
    process = false
    tag     = false
    filter  = false
  }
}

resource "azurerm_linux_function_app" "vulnerable" {
  name                = "streamgoat-2-func-${random_string.suffix.result}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location

  storage_account_name       = azurerm_storage_account.main.name
  storage_account_access_key = azurerm_storage_account.main.primary_access_key
  service_plan_id            = azurerm_service_plan.main.id

  identity {
    type = "SystemAssigned"
  }

  site_config {
    application_stack {
      python_version = "3.11"
    }

    # IP restrictions (whitelist for attack machine)
    ip_restriction_default_action = "Deny"

    dynamic "ip_restriction" {
      for_each = var.attack_whitelist
      content {
        ip_address = ip_restriction.value
        action     = "Allow"
        priority   = 100 + index(var.attack_whitelist, ip_restriction.value)
        name       = "allow-attacker-${index(var.attack_whitelist, ip_restriction.value)}"
      }
    }
  }

  app_settings = {
    FUNCTIONS_WORKER_RUNTIME       = "python"
    WEBSITE_RUN_FROM_PACKAGE       = "https://${azurerm_storage_account.main.name}.blob.core.windows.net/${azurerm_storage_container.funccode.name}/${azurerm_storage_blob.functionapp.name}${data.azurerm_storage_account_sas.functionapp.sas}"
    SCM_DO_BUILD_DURING_DEPLOYMENT = "false"
  }

  tags = {
    scenario = "cdrgoat-2"
  }
}

################################################################################
# Role Assignments for Function App Managed Identity
################################################################################

# Reader on Resource Group - allows enumeration
resource "azurerm_role_assignment" "func_rg_reader" {
  scope                = azurerm_resource_group.main.id
  role_definition_name = "Reader"
  principal_id         = azurerm_linux_function_app.vulnerable.identity[0].principal_id
}

# Storage Blob Data Reader - allows reading blobs from storage accounts
resource "azurerm_role_assignment" "func_blob_reader" {
  scope                = azurerm_storage_account.main.id
  role_definition_name = "Storage Blob Data Reader"
  principal_id         = azurerm_linux_function_app.vulnerable.identity[0].principal_id
}

################################################################################
# Target User (Victim for privilege escalation)
################################################################################

resource "azuread_user" "target" {
  user_principal_name = "streamgoat-jafar@${data.azuread_domains.default.domains[0].domain_name}"
  display_name        = "Jafar"
  mail_nickname       = "streamgoat-jafar"
  password            = random_password.target_user.result

  disable_password_expiration = true
  force_password_change       = false

  job_title  = "Junior Developer"
  department = "Engineering"
}

################################################################################
# Outputs
################################################################################

output "function_app_url" {
  description = "URL of the vulnerable Function App (attack entry point)"
  value       = "https://${azurerm_linux_function_app.vulnerable.default_hostname}"
}
