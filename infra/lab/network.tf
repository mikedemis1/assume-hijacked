# One VNet for the lab: subnets (this file), NSGs (nsg.tf) and the private DNS zone for
# PostgreSQL. It is created and destroyed with the rest of the lab; there is no hub, no
# peering and no firewall for now (the outbound-control decision is taken at the Azure step).

locals {
  # Address plan (VNet /16):
  #   10.20.0.0/24   snet-aks-system
  #   10.20.1.0/24   snet-aks-sandbox
  #   10.20.2.0/26   snet-pe
  subnets = {
    snet-aks-system  = cidrsubnet(var.vnet_address_space, 8, 0)
    snet-aks-sandbox = cidrsubnet(var.vnet_address_space, 8, 1)
    snet-pe          = cidrsubnet(var.vnet_address_space, 10, 8)
  }

  aks_subnet_names = ["snet-aks-system", "snet-aks-sandbox"]
  aks_prefixes     = [for n in local.aks_subnet_names : local.subnets[n]]

  # Node subnets plus the overlay pod range. Azure CNI Overlay does not encapsulate pod
  # traffic, so subnet NSGs see pod IPs and must allow node<->pod and pod<->pod traffic
  # (learn.microsoft.com/azure/aks/concepts-network-azure-cni-overlay, "Network security
  # groups"). Pods leaving the cluster are SNATed to the node IP, so the PE rules keep using
  # the node prefixes only.
  aks_cluster_prefixes = concat(local.aks_prefixes, [var.aks_pod_cidr])

  aks_subnet_ids = { for n in local.aks_subnet_names : n => azurerm_subnet.subnet[n].id }
}

resource "azurerm_virtual_network" "vnet" {
  name                = "vnet-assume-hijacked"
  location            = var.location
  resource_group_name = data.azurerm_resource_group.lab.name
  address_space       = [var.vnet_address_space]
  tags                = var.tags
}

resource "azurerm_subnet" "subnet" {
  #checkov:skip=CKV2_AZURE_31: false positive: azurerm_subnet_network_security_group_association.subnet in nsg.tf attaches an NSG to every subnet, but its for_each is only known at plan time
  for_each = local.subnets

  name                 = each.key
  resource_group_name  = data.azurerm_resource_group.lab.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = [each.value]

  # NSG rules apply to private endpoints only when this is Enabled.
  private_endpoint_network_policies = each.key == "snet-pe" ? "Enabled" : "Disabled"

  # The Key Vaults in rg-base accept only these subnets (infra/base spoke_subnet_ids).
  service_endpoints = contains(local.aks_subnet_names, each.key) ? ["Microsoft.KeyVault"] : []
}

# ---------------------------------------------------------------- private DNS for PostgreSQL

resource "azurerm_private_dns_zone" "postgres" {
  name                = "privatelink.postgres.database.azure.com"
  resource_group_name = data.azurerm_resource_group.lab.name
  tags                = var.tags
}

# Names resolve from every subnet of the VNet, AKS included.
resource "azurerm_private_dns_zone_virtual_network_link" "postgres" {
  name                  = "link-vnet"
  resource_group_name   = data.azurerm_resource_group.lab.name
  private_dns_zone_name = azurerm_private_dns_zone.postgres.name
  virtual_network_id    = azurerm_virtual_network.vnet.id
  registration_enabled  = false
  tags                  = var.tags
}
