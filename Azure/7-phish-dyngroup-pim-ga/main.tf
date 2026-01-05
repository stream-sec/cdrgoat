terraform {
  required_version = ">= 1.6.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.110.0"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = ">= 3.0.0"
    }
    azapi = {
      source  = "azure/azapi"
      version = ">= 1.15.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.6.2"
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.4.1"
    }
  }
}

# -------------------------------------------------
# Variables
# -------------------------------------------------

variable "subscription_id" {
  type        = string
  description = "Azure Subscription ID"
}

# -------------------------------------------------
# Providers
# -------------------------------------------------

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}

provider "azuread" {}

# -------------------------------------------------
# Data sources
# -------------------------------------------------

data "azurerm_client_config" "current" {}
data "azuread_client_config" "aad" {}
data "azuread_domains" "tenant" {}

# -------------------------------------------------
# Locals
# -------------------------------------------------

locals {
  default_domain = data.azuread_domains.tenant.domains[0].domain_name

  hero_users = [
    "Peter Parker",
    "Bruce Wayne",
    "Lara Croft",
    "Tony Stark",
    "Natasha Romanoff",
    "Luke Skywalker",
    "Clark Kent",
    "Legolas Greenleaf",
    "Bruce Banner",
    "Logan Howlett"
  ]

  hero_map = {
    for n in local.hero_users :
    "streamgoat_${replace(lower(n), " ", "_")}" => n
  }

  rg_name           = "streamgoat-rg-7"
  location          = "francecentral"
  devops_group_name = "streamgoat-7-DevOPS"
}

# -------------------------------------------------
# Users
# -------------------------------------------------

resource "random_password" "user_pw" {
  for_each = local.hero_map
  length   = 20
  special  = true
}

resource "azuread_user" "heroes" {
  for_each = local.hero_map

  display_name        = each.value
  user_principal_name = "${each.key}@${local.default_domain}"
  password            = random_password.user_pw[each.key].result

  city = contains(
    ["streamgoat_bruce_wayne", "streamgoat_clark_kent"],
    each.key
  ) ? "Gotham" : "Metropolis"

  force_password_change = true
}

# -------------------------------------------------
# Custom Directory Role: StreamGoat HR Administrator
# (Requires Entra ID P2 license)
# -------------------------------------------------

resource "azuread_custom_directory_role" "streamgoat_hr_admin" {
  display_name = "StreamGoat HR Administrator"
  description  = "Custom HR role for StreamGoat lab"
  version      = "1.0"
  enabled = true

  permissions {
    allowed_resource_actions = [
      "microsoft.directory/users/contactInfo/update"
    ]
  }
}

resource "azuread_directory_role_assignment" "lara_hr_admin" {
  role_id             = azuread_custom_directory_role.streamgoat_hr_admin.object_id
  principal_object_id = azuread_user.heroes["streamgoat_lara_croft"].object_id
}

# -------------------------------------------------
# DevOPS Group
# -------------------------------------------------

resource "azuread_group" "devops" {
  display_name     = local.devops_group_name
  security_enabled = true

  types = ["DynamicMembership"]

  dynamic_membership {
    enabled = true
    rule    = "(user.city -eq \"Gotham\")"
  }
}

# -------------------------------------------------
# Resource Group
# -------------------------------------------------

resource "azurerm_resource_group" "lab" {
  name     = local.rg_name
  location = local.location
}

# -------------------------------------------------
# Storage for Function Package
# -------------------------------------------------

resource "random_string" "suffix" {
  length  = 6
  upper   = false
  special = false
}

resource "azurerm_storage_account" "funcsa" {
  name                     = "sgfuncsa${random_string.suffix.result}"
  resource_group_name      = azurerm_resource_group.lab.name
  location                 = azurerm_resource_group.lab.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2"
}

resource "azurerm_storage_container" "funcpkg" {
  name                  = "function-packages"
  storage_account_id    = azurerm_storage_account.funcsa.id
  container_access_type = "private"
}

# -------------------------------------------------
# Function ZIP
# -------------------------------------------------

data "archive_file" "funczip" {
  type        = "zip"
  source_dir  = "${path.module}/functionapp"
  output_path = "${path.module}/functionapp.zip"
}

resource "azurerm_storage_blob" "funczip" {
  name                   = "functionapp.zip"
  storage_account_name   = azurerm_storage_account.funcsa.name
  storage_container_name = azurerm_storage_container.funcpkg.name
  type                   = "Block"
  source                 = data.archive_file.funczip.output_path
}

# -------------------------------------------------
# Function App
# -------------------------------------------------

resource "azurerm_service_plan" "plan" {
  name                = "streamgoat-func-plan-${random_string.suffix.result}"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  os_type             = "Linux"
  sku_name            = "Y1"
}

resource "azurerm_linux_function_app" "func" {
  name                       = "streamgoat-people-func-${random_string.suffix.result}"
  resource_group_name        = azurerm_resource_group.lab.name
  location                   = azurerm_resource_group.lab.location
  service_plan_id            = azurerm_service_plan.plan.id
  storage_account_name       = azurerm_storage_account.funcsa.name
  storage_account_access_key = azurerm_storage_account.funcsa.primary_access_key

  identity {
    type = "SystemAssigned"
  }

  site_config {
    application_stack {
      node_version = "22"
    }
  }

  app_settings = {
    FUNCTIONS_WORKER_RUNTIME = "node"
    WEBSITE_RUN_FROM_PACKAGE = azurerm_storage_blob.funczip.url

    GRAPH_TENANT_ID     = data.azuread_client_config.aad.tenant_id
    GRAPH_CLIENT_ID     = azuread_application.devops_ppl_mgmt_test.client_id
    GRAPH_CLIENT_SECRET = azuread_application_password.devops_ppl_mgmt_secret.value
  }
}

# -------------------------------------------------
# App Registration
# -------------------------------------------------

resource "azuread_application" "devops_ppl_mgmt_test" {
  display_name = "StreamGoat DevOPS ppl mgmt test"

  required_resource_access {
    resource_app_id = "00000003-0000-0000-c000-000000000000"

    # RoleManagement.ReadWrite.Directory
    resource_access {
      id   = "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8"
      type = "Role"
    }

    # Directory.Read.All
    resource_access {
      id   = "7ab1d382-f21e-4acd-a863-ba3e13f7da61"
      type = "Role"
    }
  }
}

resource "azuread_service_principal" "devops_ppl_mgmt_test" {
  client_id = azuread_application.devops_ppl_mgmt_test.client_id
}

resource "azuread_application_password" "devops_ppl_mgmt_secret" {
  application_id = azuread_application.devops_ppl_mgmt_test.id
  display_name   = "terraform-generated"
  end_date       = timeadd(timestamp(), "240h")
}

# -------------------------------------------------
# RBAC PIM (policy-compliant)
# -------------------------------------------------

resource "azurerm_role_definition" "pim_visibility" {
  name        = "StreamGoat-PIM-Visibility"
  scope       = "/subscriptions/${var.subscription_id}"
  description = "Minimal read-only visibility into Azure RBAC PIM eligibility"

  permissions {
    actions = [
      "Microsoft.Authorization/roleEligibilityScheduleInstances/read",
      "Microsoft.Authorization/roleEligibilitySchedules/read",
      "Microsoft.Authorization/roleDefinitions/read",
      "Microsoft.Authorization/roleAssignments/read"
    ]
    not_actions = []
  }

  assignable_scopes = [
    "/subscriptions/${var.subscription_id}"
  ]
}

resource "azurerm_role_assignment" "devops_pim_visibility" {
  scope              = "/subscriptions/${var.subscription_id}"
  role_definition_id = azurerm_role_definition.pim_visibility.role_definition_resource_id
  principal_id       = azuread_group.devops.object_id
}

data "azurerm_role_definition" "contributor" {
  name  = "Contributor"
  scope = azurerm_resource_group.lab.id
}

resource "random_uuid" "pim_request_id" {}

resource "azapi_resource" "pim_contributor_eligibility" {
  type      = "Microsoft.Authorization/roleEligibilityScheduleRequests@2020-10-01-preview"
  name      = random_uuid.pim_request_id.result
  parent_id = azurerm_resource_group.lab.id

  lifecycle {
    prevent_destroy = true
  }

  body = {
    properties = {
      principalId      = azuread_group.devops.object_id
      roleDefinitionId = data.azurerm_role_definition.contributor.id
      requestType      = "AdminAssign"

      scheduleInfo = {
        startDateTime = timestamp()
        expiration = {
          type     = "AfterDuration"
          duration = "PT24H"
        }
      }

      justification = "StreamGoat lab – DevOPS PIM eligibility"
    }
  }
}

# -------------------------------------------------
# Outputs
# -------------------------------------------------

output "devops_app_client_id" {
  value = azuread_application.devops_ppl_mgmt_test.client_id
}

output "lara_croft_credentials" {
  value = {
    user_principal_name = azuread_user.heroes["streamgoat_lara_croft"].user_principal_name
    password            = random_password.user_pw["streamgoat_lara_croft"].result
  }
  sensitive = true
}
