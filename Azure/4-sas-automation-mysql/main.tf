################################################################################
# CDRGoat - Azure Scenario 4
# SAS Token → Automation Account → VM → MySQL Database Exfiltration
################################################################################

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.90"
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

data "azurerm_client_config" "current" {}

################################################################################
# Random Resources for Unique Naming
################################################################################

resource "random_id" "suffix" {
  byte_length = 4
}

resource "random_password" "vm_admin" {
  length  = 20
  special = true
}

resource "random_password" "mysql_admin" {
  length  = 20
  special = true
}

################################################################################
# Resource Group
################################################################################

resource "azurerm_resource_group" "main" {
  name     = "streamgoat-4-rg-${random_id.suffix.hex}"
  location = var.location

  tags = {
    scenario = "cdrgoat-4"
    purpose  = "security-training"
  }
}

################################################################################
# Networking
################################################################################

resource "azurerm_virtual_network" "main" {
  name                = "streamgoat-4-vnet"
  location            = var.location
  resource_group_name = azurerm_resource_group.main.name
  address_space       = ["10.4.0.0/16"]
}

resource "azurerm_subnet" "main" {
  name                 = "streamgoat-4-subnet"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.4.1.0/24"]
}

resource "azurerm_network_security_group" "main" {
  name                = "streamgoat-4-nsg"
  location            = var.location
  resource_group_name = azurerm_resource_group.main.name

  # Restrict inbound - VM accessed via Run Command only
  security_rule {
    name                       = "DenyAllInbound"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "azurerm_subnet_network_security_group_association" "main" {
  subnet_id                 = azurerm_subnet.main.id
  network_security_group_id = azurerm_network_security_group.main.id
}

################################################################################
# Storage Account (Leaked SAS Token Entry Point)
################################################################################

resource "azurerm_storage_account" "main" {
  name                            = "streamgoat4sa${random_id.suffix.hex}"
  resource_group_name             = azurerm_resource_group.main.name
  location                        = var.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = true

  tags = {
    scenario = "cdrgoat-4"
  }
}

# Container with public blob access (simulates misconfiguration)
resource "azurerm_storage_container" "automation_configs" {
  name                  = "automation-configs"
  storage_account_name  = azurerm_storage_account.main.name
  container_access_type = "blob"
}

# Automation configuration blob (contains sensitive info)
resource "azurerm_storage_blob" "automation_config" {
  name                   = "automation_config.json"
  storage_account_name   = azurerm_storage_account.main.name
  storage_container_name = azurerm_storage_container.automation_configs.name
  type                   = "Block"
  content_type           = "application/json"

  source_content = jsonencode({
    automation_account = {
      name           = azurerm_automation_account.main.name
      resource_group = azurerm_resource_group.main.name
      subscription   = data.azurerm_client_config.current.subscription_id
      identity = {
        client_id = azurerm_automation_account.main.identity[0].principal_id
        type      = "SystemAssigned"
      }
    }
    target_vm = {
      name           = azurerm_linux_virtual_machine.target.name
      resource_group = azurerm_resource_group.main.name
    }
    key_vault = {
      name = azurerm_key_vault.main.name
      url  = azurerm_key_vault.main.vault_uri
    }
    # VULNERABLE: Webhook URL exposed - allows triggering automation remotely
    maintenance_webhook = {
      url         = azurerm_automation_webhook.run_command.uri
      description = "Webhook for VM maintenance tasks"
      usage       = "POST with JSON body: {\"command\": \"<shell command>\"}"
    }
    notes = "DO NOT EXPOSE - Contains automation infrastructure details"
  })
}

# Generate SAS token for storage account (leaked via Terraform output)
data "azurerm_storage_account_sas" "leaked" {
  connection_string = azurerm_storage_account.main.primary_connection_string
  https_only        = true
  start             = timestamp()
  expiry            = timeadd(timestamp(), "168h") # 7 days

  resource_types {
    service   = true
    container = true
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
    list    = true
    add     = false
    create  = false
    update  = false
    process = false
    tag     = false
    filter  = false
  }
}

################################################################################
# Automation Account (Pivot Point)
################################################################################

resource "azurerm_automation_account" "main" {
  name                = "streamgoat-4-aa-${random_id.suffix.hex}"
  resource_group_name = azurerm_resource_group.main.name
  location            = var.location
  sku_name            = "Basic"

  identity {
    type = "SystemAssigned"
  }

  tags = {
    scenario = "cdrgoat-4"
  }
}

# Grant Automation Account Virtual Machine Contributor on Resource Group
resource "azurerm_role_assignment" "automation_vm_contributor" {
  scope                = azurerm_resource_group.main.id
  role_definition_name = "Virtual Machine Contributor"
  principal_id         = azurerm_automation_account.main.identity[0].principal_id
}

# Baseline runbook (legitimate looking)
resource "azurerm_automation_runbook" "baseline" {
  name                    = "Get-VMStatus"
  resource_group_name     = azurerm_resource_group.main.name
  automation_account_name = azurerm_automation_account.main.name
  location                = var.location
  runbook_type            = "PowerShell"
  log_progress            = true
  log_verbose             = true

  content = <<-EOT
    <#
    .SYNOPSIS
        Get VM status for monitoring
    .DESCRIPTION
        Lists all VMs in the resource group and their power states
    #>
    
    param()
    
    Connect-AzAccount -Identity
    
    $rg = Get-AutomationVariable -Name 'TargetResourceGroup'
    $vms = Get-AzVM -ResourceGroupName $rg
    
    foreach ($vm in $vms) {
        $status = Get-AzVM -ResourceGroupName $rg -Name $vm.Name -Status
        Write-Output "$($vm.Name): $($status.Statuses[1].DisplayStatus)"
    }
  EOT

  tags = {
    scenario = "cdrgoat-4"
  }
}

# Vulnerable runbook (accepts command parameter via webhook - INSECURE PATTERN)
resource "azurerm_automation_runbook" "run_command" {
  name                    = "Invoke-VMCommand"
  resource_group_name     = azurerm_resource_group.main.name
  automation_account_name = azurerm_automation_account.main.name
  location                = var.location
  runbook_type            = "PowerShell"
  log_progress            = true
  log_verbose             = true

  content = <<-EOT
    <#
    .SYNOPSIS
        Execute maintenance commands on target VM
    .DESCRIPTION
        Webhook-triggered runbook for remote VM administration.
        Accepts command parameter for flexible maintenance tasks.
    .NOTES
        WARNING: This pattern is insecure - for training purposes only
    #>
    
    param(
        [Parameter(Mandatory=$false)]
        [object]$WebhookData
    )
    
    # Authenticate using Automation Account Managed Identity
    Connect-AzAccount -Identity
    
    # Get target VM details from Automation Variables
    $resourceGroup = Get-AutomationVariable -Name 'TargetResourceGroup'
    $vmName = Get-AutomationVariable -Name 'TargetVMName'
    
    if ($WebhookData) {
        Write-Output "Webhook triggered - processing request..."
        
        # Parse the webhook payload
        $payload = $WebhookData.RequestBody | ConvertFrom-Json
        
        if ($payload.command) {
            $command = $payload.command
            Write-Output "Executing command on VM: $vmName"
            Write-Output "Command: $command"
            
            # Execute the command on the target VM via Run Command
            # VULNERABLE: No input validation - accepts arbitrary commands
            $result = Invoke-AzVMRunCommand `
                -ResourceGroupName $resourceGroup `
                -VMName $vmName `
                -CommandId 'RunShellScript' `
                -ScriptString $command
            
            Write-Output "=== Command Output ==="
            $result.Value | ForEach-Object { Write-Output $_.Message }
        }
        else {
            Write-Output "No command specified in payload. Expected format: {\"command\": \"<shell command>\"}"
        }
    }
    else {
        Write-Output "This runbook is designed to be triggered via webhook."
        Write-Output "Payload format: {\"command\": \"<shell command>\"}"
    }
  EOT

  tags = {
    scenario = "cdrgoat-4"
  }
}

# Webhook for the vulnerable runbook (URL will be leaked via storage)
resource "azurerm_automation_webhook" "run_command" {
  name                    = "maintenance-webhook"
  resource_group_name     = azurerm_resource_group.main.name
  automation_account_name = azurerm_automation_account.main.name
  runbook_name            = azurerm_automation_runbook.run_command.name
  expiry_time             = timeadd(timestamp(), "8760h") # 1 year
  enabled                 = true
}

# Automation variables
resource "azurerm_automation_variable_string" "target_rg" {
  name                    = "TargetResourceGroup"
  resource_group_name     = azurerm_resource_group.main.name
  automation_account_name = azurerm_automation_account.main.name
  value                   = azurerm_resource_group.main.name
}

resource "azurerm_automation_variable_string" "target_vm" {
  name                    = "TargetVMName"
  resource_group_name     = azurerm_resource_group.main.name
  automation_account_name = azurerm_automation_account.main.name
  value                   = azurerm_linux_virtual_machine.target.name
}

################################################################################
# Key Vault (Stores MySQL Credentials)
################################################################################

resource "azurerm_key_vault" "main" {
  name                       = "streamgoat4kv${random_id.suffix.hex}"
  location                   = var.location
  resource_group_name        = azurerm_resource_group.main.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  enable_rbac_authorization  = true
  purge_protection_enabled   = false
  soft_delete_retention_days = 7

  tags = {
    scenario = "cdrgoat-4"
  }
}

# Grant Terraform deployer Key Vault Secrets Officer
resource "azurerm_role_assignment" "tf_kv_officer" {
  scope                = azurerm_key_vault.main.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = data.azurerm_client_config.current.object_id
}

# Wait for RBAC propagation
resource "null_resource" "wait_for_kv_rbac" {
  depends_on = [azurerm_role_assignment.tf_kv_officer]
  provisioner "local-exec" {
    command = "sleep 60"
  }
}

# Store MySQL admin password in Key Vault
resource "azurerm_key_vault_secret" "mysql_password" {
  name         = "mysql-admin-password"
  value        = random_password.mysql_admin.result
  key_vault_id = azurerm_key_vault.main.id
  depends_on   = [null_resource.wait_for_kv_rbac]
}

# Store MySQL connection details
resource "azurerm_key_vault_secret" "mysql_connection" {
  name         = "mysql-connection-string"
  key_vault_id = azurerm_key_vault.main.id
  depends_on   = [null_resource.wait_for_kv_rbac]

  value = jsonencode({
    host     = azurerm_mysql_flexible_server.db.fqdn
    port     = 3306
    username = "mysqladmin"
    database = "sensitive"
  })
}

################################################################################
# Virtual Machine (Target with Key Vault Access)
################################################################################

resource "azurerm_network_interface" "target" {
  name                = "streamgoat-4-vm-nic"
  location            = var.location
  resource_group_name = azurerm_resource_group.main.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.main.id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_linux_virtual_machine" "target" {
  name                = "streamgoat-4-vm"
  resource_group_name = azurerm_resource_group.main.name
  location            = var.location
  size                = "Standard_B1s"

  admin_username                  = "azureuser"
  admin_password                  = random_password.vm_admin.result
  disable_password_authentication = false

  network_interface_ids = [azurerm_network_interface.target.id]

  identity {
    type = "SystemAssigned"
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }

  custom_data = base64encode(<<-EOF
    #!/bin/bash
    apt-get update
    apt-get install -y mysql-client curl jq
  EOF
  )
}

# Grant VM Managed Identity access to Key Vault secrets
resource "azurerm_role_assignment" "vm_kv_reader" {
  scope                = azurerm_key_vault.main.id
  role_definition_name = "Key Vault Reader"
  principal_id         = azurerm_linux_virtual_machine.target.identity[0].principal_id
}

resource "azurerm_role_assignment" "vm_kv_secrets_user" {
  scope                = azurerm_key_vault.main.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_linux_virtual_machine.target.identity[0].principal_id
}

################################################################################
# MySQL Flexible Server (Final Target)
################################################################################

resource "azurerm_mysql_flexible_server" "db" {
  name                   = "streamgoat4mysql${random_id.suffix.hex}"
  location               = var.location
  resource_group_name    = azurerm_resource_group.main.name
  administrator_login    = "mysqladmin"
  administrator_password = random_password.mysql_admin.result
  version                = "8.0.21"
  sku_name               = "B_Standard_B1ms"
  backup_retention_days  = 7

  storage {
    size_gb = 32
  }
}

# Allow Azure services (including VM) to access MySQL
# In production this would be restricted via VNet integration or Private Endpoint
resource "azurerm_mysql_flexible_server_firewall_rule" "allow_azure_services" {
  name                = "AllowAzureServices"
  resource_group_name = azurerm_resource_group.main.name
  server_name         = azurerm_mysql_flexible_server.db.name
  start_ip_address    = "0.0.0.0"
  end_ip_address      = "0.0.0.0"
}

resource "azurerm_mysql_flexible_database" "db" {
  name                = "sensitive"
  resource_group_name = azurerm_resource_group.main.name
  server_name         = azurerm_mysql_flexible_server.db.name
  charset             = "utf8mb4"
  collation           = "utf8mb4_unicode_ci"
}

################################################################################
# Output
################################################################################

output "leaked_storage_url" {
  description = "Leaked Storage URL with SAS token (attack entry point)"
  value       = "${azurerm_storage_account.main.primary_blob_endpoint}automation-configs/automation_config.json${data.azurerm_storage_account_sas.leaked.sas}"
  sensitive   = true
}

output "mysql_host" {
  description = "MySQL server FQDN (for manual testing)"
  value       = azurerm_mysql_flexible_server.db.fqdn
}

output "mysql_password" {
  description = "MySQL admin password (for manual testing)"
  value       = random_password.mysql_admin.result
  sensitive   = true
}
