################################################################################
# CDRGoat - Azure Scenario 6
# RCE on VM → Disk Snapshot Pivot → Secret Extraction from Private VM
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
  description = "List of CIDRs allowed to reach the public VM"
  type        = list(string)
  default     = []
}

################################################################################
# Data Sources
################################################################################

data "azuread_client_config" "current" {}

data "azurerm_subscription" "current" {}

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

resource "random_password" "db_password" {
  length  = 24
  special = true
}

################################################################################
# Resource Group
################################################################################

resource "azurerm_resource_group" "main" {
  name     = "streamgoat-6-rg-${random_string.suffix.result}"
  location = var.location

  tags = {
    scenario = "cdrgoat-6"
    purpose  = "security-training"
  }
}

################################################################################
# App Registration (secrets pre-seeded on backend VM disk)
################################################################################

resource "azuread_application" "backend_app" {
  display_name = "streamgoat-6-backend-automation"
  tags         = ["cdrgoat", "scenario-6"]
}

resource "azuread_application_password" "backend_secret" {
  application_id = azuread_application.backend_app.id
  display_name   = "streamgoat-6-backend-secret"
  end_date       = timeadd(timestamp(), "8760h")
}

resource "azuread_service_principal" "backend_sp" {
  client_id = azuread_application.backend_app.client_id
  tags      = ["cdrgoat", "scenario-6"]
}

# Grant the backend SP "User.ReadWrite.All" on Microsoft Graph
resource "azuread_app_role_assignment" "backend_user_readwrite" {
  app_role_id         = [for r in data.azuread_service_principal.msgraph.app_roles : r.id if r.value == "User.ReadWrite.All"][0]
  principal_object_id = azuread_service_principal.backend_sp.object_id
  resource_object_id  = data.azuread_service_principal.msgraph.object_id
}

# Create a target user for password reset demonstration
resource "azuread_user" "target_user" {
  user_principal_name = "streamgoat-victim-6@${data.azuread_client_config.current.tenant_id}.onmicrosoft.com"
  display_name        = "StreamGoat Victim 6"
  password            = "InitialP@ss${random_string.suffix.result}!"
  force_password_change_on_next_sign_in = false

  lifecycle {
    ignore_changes = [user_principal_name]
  }
}

################################################################################
# Networking
################################################################################

resource "azurerm_virtual_network" "main" {
  name                = "streamgoat-6-vnet"
  address_space       = ["10.0.0.0/16"]
  location            = var.location
  resource_group_name = azurerm_resource_group.main.name

  tags = { scenario = "cdrgoat-6" }
}

resource "azurerm_subnet" "public" {
  name                 = "public-subnet"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.1.0/24"]
}

resource "azurerm_subnet" "private" {
  name                 = "private-subnet"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.2.0/24"]
}

# Public subnet NSG — allow HTTP (8080) + SSH from whitelist
resource "azurerm_network_security_group" "public_nsg" {
  name                = "streamgoat-6-public-nsg"
  location            = var.location
  resource_group_name = azurerm_resource_group.main.name

  dynamic "security_rule" {
    for_each = var.attack_whitelist
    content {
      name                       = "AllowHTTP-${security_rule.key}"
      priority                   = 100 + security_rule.key
      direction                  = "Inbound"
      access                     = "Allow"
      protocol                   = "Tcp"
      source_port_range          = "*"
      destination_port_range     = "8080"
      source_address_prefix      = security_rule.value
      destination_address_prefix = "*"
    }
  }

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

  tags = { scenario = "cdrgoat-6" }
}

# Private subnet NSG — deny all inbound
resource "azurerm_network_security_group" "private_nsg" {
  name                = "streamgoat-6-private-nsg"
  location            = var.location
  resource_group_name = azurerm_resource_group.main.name

  security_rule {
    name                       = "DenyAllInbound"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  tags = { scenario = "cdrgoat-6" }
}

resource "azurerm_subnet_network_security_group_association" "public" {
  subnet_id                 = azurerm_subnet.public.id
  network_security_group_id = azurerm_network_security_group.public_nsg.id
}

resource "azurerm_subnet_network_security_group_association" "private" {
  subnet_id                 = azurerm_subnet.private.id
  network_security_group_id = azurerm_network_security_group.private_nsg.id
}

################################################################################
# User-Assigned Managed Identity (Contributor on RG)
################################################################################

resource "azurerm_user_assigned_identity" "vm_mi" {
  name                = "streamgoat-6-vm-identity"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location

  tags = { scenario = "cdrgoat-6" }
}

resource "azurerm_role_assignment" "vm_mi_contributor" {
  scope                = azurerm_resource_group.main.id
  role_definition_name = "Contributor"
  principal_id         = azurerm_user_assigned_identity.vm_mi.principal_id
}

################################################################################
# Public VM (RCE-vulnerable web app)
################################################################################

resource "azurerm_public_ip" "public_vm" {
  name                = "streamgoat-6-public-ip"
  location            = var.location
  resource_group_name = azurerm_resource_group.main.name
  allocation_method   = "Static"
  sku                 = "Standard"

  tags = { scenario = "cdrgoat-6" }
}

resource "azurerm_network_interface" "public_vm" {
  name                = "streamgoat-6-public-nic"
  location            = var.location
  resource_group_name = azurerm_resource_group.main.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.public.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.public_vm.id
  }

  tags = { scenario = "cdrgoat-6" }
}

resource "azurerm_linux_virtual_machine" "public_vm" {
  name                            = "streamgoat-public-vm"
  resource_group_name             = azurerm_resource_group.main.name
  location                        = var.location
  size                            = "Standard_B1s"
  admin_username                  = "azureuser"
  disable_password_authentication = true
  network_interface_ids           = [azurerm_network_interface.public_vm.id]

  admin_ssh_key {
    username   = "azureuser"
    public_key = tls_private_key.vm_ssh.public_key_openssh
  }

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.vm_mi.id]
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

  custom_data = base64encode(<<-CLOUDINIT
#!/bin/bash
apt-get update && apt-get install -y python3 python3-pip
cat > /opt/vuln_app.py << 'PYEOF'
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import subprocess, json

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        if parsed.path == '/cmd' and 'c' in params:
            try:
                result = subprocess.run(params['c'][0], shell=True, capture_output=True, text=True, timeout=30)
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
            self.wfile.write(b'<h1>StreamGoat App</h1><p>Status: Running</p>')
        else:
            self.send_response(404)
            self.end_headers()
    def log_message(self, format, *args): pass

HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
PYEOF
nohup python3 /opt/vuln_app.py &
CLOUDINIT
  )

  tags = { scenario = "cdrgoat-6" }
}

resource "tls_private_key" "vm_ssh" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

################################################################################
# Private VM (backend with secrets on disk)
################################################################################

resource "azurerm_network_interface" "private_vm" {
  name                = "streamgoat-6-private-nic"
  location            = var.location
  resource_group_name = azurerm_resource_group.main.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.private.id
    private_ip_address_allocation = "Dynamic"
  }

  tags = { scenario = "cdrgoat-6" }
}

resource "azurerm_linux_virtual_machine" "private_vm" {
  name                            = "streamgoat-backend-vm"
  resource_group_name             = azurerm_resource_group.main.name
  location                        = var.location
  size                            = "Standard_B1s"
  admin_username                  = "adminuser"
  disable_password_authentication = true
  network_interface_ids           = [azurerm_network_interface.private_vm.id]

  admin_ssh_key {
    username   = "adminuser"
    public_key = tls_private_key.vm_ssh.public_key_openssh
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
    name                 = "streamgoat-backend-osdisk"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }

  custom_data = base64encode(<<-CLOUDINIT
#!/bin/bash
# Simulate secrets left on the backend VM filesystem
mkdir -p /home/adminuser/.ssh /opt/app

# Dummy SSH private key
cat > /home/adminuser/.ssh/id_rsa << 'SSHEOF'
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAIEA0Z3IakVMIxMfFQJ2gMOg3B3THFK6kS3VqLpMQLhHHiZ0YPpNGh
ZVFAdSVEJnBQOauIExampleDummyKeyNotReallyUsableForAnything0Z3IakVMIxMfFQ
J2gMOg3B3THFK6kS3VqLpMQLhHHiZ0YPpNGhZVFAdSVEJnBQOauIFT1gSh4EF4dMLaD
-----END OPENSSH PRIVATE KEY-----
SSHEOF
chmod 600 /home/adminuser/.ssh/id_rsa

# Application .env with SP credentials
cat > /opt/app/.env << ENVEOF
# Backend automation service credentials
CLIENT_ID=${azuread_application.backend_app.client_id}
CLIENT_SECRET=${azuread_application_password.backend_secret.value}
TENANT_ID=${data.azuread_client_config.current.tenant_id}
ENVEOF
chmod 600 /opt/app/.env

# Database config
cat > /opt/app/config.json << 'CFGEOF'
{
  "database": {
    "host": "prod-sql-backend.database.windows.net",
    "port": 1433,
    "name": "customers_db",
    "user": "app_svc_account",
    "password": "${random_password.db_password.result}"
  },
  "redis": {
    "host": "prod-redis.redis.cache.windows.net",
    "port": 6380,
    "key": "aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpP="
  }
}
CFGEOF
chmod 600 /opt/app/config.json

chown -R adminuser:adminuser /home/adminuser/.ssh /opt/app
CLOUDINIT
  )

  tags = { scenario = "cdrgoat-6" }
}

################################################################################
# Outputs
################################################################################

output "public_vm_ip" {
  description = "Public IP of the vulnerable VM"
  value       = azurerm_public_ip.public_vm.ip_address
}

output "resource_group_name" {
  description = "Resource Group name"
  value       = azurerm_resource_group.main.name
}

output "subscription_id" {
  description = "Azure Subscription ID"
  value       = data.azurerm_subscription.current.subscription_id
}

output "tenant_id" {
  description = "Azure AD Tenant ID"
  value       = data.azuread_client_config.current.tenant_id
}

output "mi_client_id" {
  description = "VM Managed Identity Client ID (for IMDS token requests)"
  value       = azurerm_user_assigned_identity.vm_mi.client_id
}
