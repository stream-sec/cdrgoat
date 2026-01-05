terraform {
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
      source = "hashicorp/random"
    }
  }
}

provider "azurerm" {
  features {}
}

provider "azuread" {}

data "azurerm_client_config" "current" {}

# -------------------------------------------------
# Variables
# -------------------------------------------------

variable "location" {
  type    = string
  default = "francecentral"
}

variable "attack_whitelist" {
  type = list(string)
  validation {
    condition     = length(var.attack_whitelist) > 0
    error_message = "Provide at least one IP/CIDR"
  }
}

# -------------------------------------------------
# Randoms
# -------------------------------------------------

resource "random_password" "vm_admin" {
  length  = 18
  special = true
}

resource "random_password" "mysql_admin" {
  length  = 20
  special = true
}

resource "random_id" "lab_suffix" {
  byte_length = 4
}

# -------------------------------------------------
# Azure AD – Maintenance App (Service User)
# -------------------------------------------------

resource "azuread_application" "maintenance_app" {
  display_name = "streamgoat-maintenance-app"
}

resource "azuread_service_principal" "maintenance_sp" {
  client_id = azuread_application.maintenance_app.client_id
}

resource "azuread_application_password" "maintenance_secret" {
  application_id = azuread_application.maintenance_app.id
}

# -------------------------------------------------
# Resource Group
# -------------------------------------------------

resource "azurerm_resource_group" "rg" {
  name     = "streamgoat-azure-rg"
  location = var.location
}

# -------------------------------------------------
# Networking
# -------------------------------------------------

resource "azurerm_virtual_network" "vnet" {
  name                = "streamgoat-vnet"
  location            = var.location
  resource_group_name = azurerm_resource_group.rg.name
  address_space       = ["10.0.0.0/16"]
}

resource "azurerm_subnet" "subnet" {
  name                 = "streamgoat-subnet"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = ["10.0.1.0/24"]
}

resource "azurerm_network_security_group" "nsg" {
  name                = "streamgoat-nsg"
  location            = var.location
  resource_group_name = azurerm_resource_group.rg.name

  security_rule {
    name                       = "HTTP"
    priority                   = 1002
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_address_prefixes    = var.attack_whitelist
    source_port_range          = "*"
    destination_port_range     = "80"
    destination_address_prefix = "*"
  }

}

resource "azurerm_subnet_network_security_group_association" "assoc" {
  subnet_id                 = azurerm_subnet.subnet.id
  network_security_group_id = azurerm_network_security_group.nsg.id
}

# -------------------------------------------------
# Public IPs
# -------------------------------------------------

resource "azurerm_public_ip" "vm_a_ip" {
  name                = "streamgoat-vm-a-pip"
  location            = var.location
  resource_group_name = azurerm_resource_group.rg.name
  allocation_method   = "Static"
  sku                 = "Standard"
}

# -------------------------------------------------
# NICs
# -------------------------------------------------

resource "azurerm_network_interface" "vm_a_nic" {
  name                = "streamgoat-vm-a-nic"
  location            = var.location
  resource_group_name = azurerm_resource_group.rg.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.subnet.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.vm_a_ip.id
  }
}

# -------------------------------------------------
# VM‑A (RCE Entry Point)
# -------------------------------------------------

resource "azurerm_linux_virtual_machine" "vm_a" {
  name                = "streamgoat-vm-a"
  location            = var.location
  resource_group_name = azurerm_resource_group.rg.name
  size                = "Standard_B1s"

  admin_username                  = "streamgoat"
  admin_password                  = random_password.vm_admin.result
  disable_password_authentication = false

  network_interface_ids = [azurerm_network_interface.vm_a_nic.id]

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

  custom_data = base64encode(<<EOF
#cloud-config
packages:
  - python3
  - python3-pip
  - net-tools
runcmd:
  - pip3 install flask
  - systemctl daemon-reload
  - systemctl enable --now streamgoat.service
write_files:
  - path: /opt/app.py
    permissions: "0644"
    content: |
      from flask import Flask, request
      app = Flask(__name__)
      @app.route('/')
      def index():
          return 'Vulnerable app placeholder – replace with your RCE demo.'
      @app.route('/cmd')
      def cmd():
          import os
          c = request.args.get('c','echo ok')
          return os.popen(c).read()
      if __name__ == '__main__':
          app.run(host='0.0.0.0', port=80)
  - path: /etc/systemd/system/streamgoat.service
    permissions: "0644"
    content: |
      [Service]
      ExecStart=python3 /opt/app.py >/var/log/app.log 2>&1
      WorkingDirectory=/opt
      Restart=always
      [Install]
      WantedBy=multi-user.target
EOF
  )
}

# -------------------------------------------------
# Azure SQL
# -------------------------------------------------

resource "azurerm_mysql_flexible_server" "db" {
  name                   = "streamgoatmysql${random_id.lab_suffix.hex}"
  location               = var.location
  resource_group_name    = azurerm_resource_group.rg.name
  administrator_login    = "adminstreamgoat"
  administrator_password = random_password.mysql_admin.result
  version                = "8.0.21"
  sku_name               = "B_Standard_B1ms"
  backup_retention_days  = 7

  storage {
    size_gb = 32
  }

}

resource "azurerm_mysql_flexible_database" "db" {
  name                = "sensitive"
  resource_group_name = azurerm_resource_group.rg.name
  server_name         = azurerm_mysql_flexible_server.db.name
  charset             = "utf8mb4"
  collation           = "utf8mb4_unicode_ci"
}

# -------------------------------------------------
# Key Vault (RBAC)
# -------------------------------------------------

resource "azurerm_key_vault" "kv" {
  name                      = "streamgoat-kv-${random_id.lab_suffix.hex}"
  location                  = var.location
  resource_group_name       = azurerm_resource_group.rg.name
  tenant_id                 = data.azurerm_client_config.current.tenant_id
  sku_name                  = "standard"
  enable_rbac_authorization = true
}

resource "azurerm_role_assignment" "tf_can_write_kv" {
  scope                = azurerm_key_vault.kv.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = data.azurerm_client_config.current.object_id
}

resource "null_resource" "wait_for_rbac" {
  depends_on = [azurerm_role_assignment.tf_can_write_kv]
  provisioner "local-exec" {
    command = "sleep 60"
  }
}

resource "azurerm_key_vault_secret" "client_id" {
  name         = "streamgoat-maintenance-app-client-id"
  value        = azuread_application.maintenance_app.client_id
  key_vault_id = azurerm_key_vault.kv.id
  depends_on   = [null_resource.wait_for_rbac]
}

resource "azurerm_key_vault_secret" "client_secret" {
  name         = "streamgoat-maintenance-app-client-secret"
  value        = azuread_application_password.maintenance_secret.value
  key_vault_id = azurerm_key_vault.kv.id
  depends_on   = [null_resource.wait_for_rbac]
}

resource "azurerm_role_assignment" "vm_a_kv_reader" {
  scope                = azurerm_key_vault.kv.id
  role_definition_name = "Key Vault Reader"
  principal_id         = azurerm_linux_virtual_machine.vm_a.identity[0].principal_id
}

resource "azurerm_role_assignment" "vm_a_kv_secret_reader" {
  scope                = azurerm_key_vault.kv.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_linux_virtual_machine.vm_a.identity[0].principal_id
}

resource "azurerm_role_assignment" "maintenance_mysql_reader" {
  scope                = azurerm_mysql_flexible_server.db.id
  role_definition_name = "Reader"
  principal_id         = azuread_service_principal.maintenance_sp.object_id
}

resource "azurerm_role_assignment" "maintenance_mysql_contributor" {
  scope                = azurerm_mysql_flexible_server.db.id
  role_definition_name = "Contributor"
  principal_id         = azuread_service_principal.maintenance_sp.object_id
}

# -------------------------------------------------
# Output
# -------------------------------------------------

output "vm_a_public_ip" {
  value = azurerm_public_ip.vm_a_ip.ip_address
}