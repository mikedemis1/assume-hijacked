# rg-net: hub and spoke VNets, peering, subnets, private DNS zones (this file), NSGs (nsg.tf),
# DNS security policy (dns-policy.tf).
#
# The resource group is created EMPTY by infra/base (ruling R15). This stack only reads it.
# A destroy of this stack removes its contents, never the group.

data "azurerm_resource_group" "net" {
  name = var.resource_group_name
}

locals {
  # Address plan (hub /24, spoke /16):
  #   hub   10.10.0.0/26   AzureFirewallSubnet
  #         10.10.0.64/26  AzureFirewallManagementSubnet (Firewall Basic needs it)
  #   spoke 10.20.0.0/24   snet-aks-system
  #         10.20.1.0/24   snet-aks-sandbox
  #         10.20.2.0/26   snet-pe
  hub_subnets = {
    # Azure requires these exact names. Azure-managed: an NSG cannot be attached.
    AzureFirewallSubnet           = cidrsubnet(var.hub_address_space, 2, 0)
    AzureFirewallManagementSubnet = cidrsubnet(var.hub_address_space, 2, 1)
  }

  spoke_subnets = {
    snet-aks-system  = cidrsubnet(var.spoke_address_space, 8, 0)
    snet-aks-sandbox = cidrsubnet(var.spoke_address_space, 8, 1)
    snet-pe          = cidrsubnet(var.spoke_address_space, 10, 8)
  }

  aks_subnet_names = ["snet-aks-system", "snet-aks-sandbox"]
  aks_prefixes     = [for n in local.aks_subnet_names : local.spoke_subnets[n]]

  private_dns_zones = {
    postgres = "privatelink.postgres.database.azure.com"
    vault    = "privatelink.vaultcore.azure.net"
  }
}

# ---------------------------------------------------------------- VNets and subnets

resource "azurerm_virtual_network" "hub" {
  name                = "vnet-hub"
  location            = var.location
  resource_group_name = data.azurerm_resource_group.net.name
  address_space       = [var.hub_address_space]
  tags                = var.tags
}

resource "azurerm_virtual_network" "spoke" {
  name                = "vnet-spoke"
  location            = var.location
  resource_group_name = data.azurerm_resource_group.net.name
  address_space       = [var.spoke_address_space]
  tags                = var.tags
}

resource "azurerm_subnet" "hub" {
  for_each = local.hub_subnets

  name                 = each.key
  resource_group_name  = data.azurerm_resource_group.net.name
  virtual_network_name = azurerm_virtual_network.hub.name
  address_prefixes     = [each.value]
}

resource "azurerm_subnet" "spoke" {
  for_each = local.spoke_subnets

  name                 = each.key
  resource_group_name  = data.azurerm_resource_group.net.name
  virtual_network_name = azurerm_virtual_network.spoke.name
  address_prefixes     = [each.value]

  # NSG rules apply to private endpoints only when this is Enabled.
  private_endpoint_network_policies = each.key == "snet-pe" ? "Enabled" : "Disabled"

  # The Key Vaults in rg-base accept only these subnets (infra/base spoke_subnet_ids).
  service_endpoints = contains(local.aks_subnet_names, each.key) ? ["Microsoft.KeyVault"] : []
}

# ---------------------------------------------------------------- peering (both directions)
#
# No gateway transit: there is no VPN or ExpressRoute gateway. Forwarded traffic is allowed
# so that spoke traffic sent to the firewall in the hub (route table in infra/lab) is accepted.

resource "azurerm_virtual_network_peering" "hub_to_spoke" {
  name                         = "peer-hub-to-spoke"
  resource_group_name          = data.azurerm_resource_group.net.name
  virtual_network_name         = azurerm_virtual_network.hub.name
  remote_virtual_network_id    = azurerm_virtual_network.spoke.id
  allow_virtual_network_access = true
  allow_forwarded_traffic      = true
  allow_gateway_transit        = false
  use_remote_gateways          = false
}

resource "azurerm_virtual_network_peering" "spoke_to_hub" {
  name                         = "peer-spoke-to-hub"
  resource_group_name          = data.azurerm_resource_group.net.name
  virtual_network_name         = azurerm_virtual_network.spoke.name
  remote_virtual_network_id    = azurerm_virtual_network.hub.id
  allow_virtual_network_access = true
  allow_forwarded_traffic      = true
  allow_gateway_transit        = false
  use_remote_gateways          = false
}

# ---------------------------------------------------------------- private DNS zones

resource "azurerm_private_dns_zone" "this" {
  for_each = local.private_dns_zones

  name                = each.value
  resource_group_name = data.azurerm_resource_group.net.name
  tags                = var.tags
}

# Linked to BOTH VNets: names resolve from the spoke (AKS) and from the hub.
resource "azurerm_private_dns_zone_virtual_network_link" "hub" {
  for_each = local.private_dns_zones

  name                  = "link-hub"
  resource_group_name   = data.azurerm_resource_group.net.name
  private_dns_zone_name = azurerm_private_dns_zone.this[each.key].name
  virtual_network_id    = azurerm_virtual_network.hub.id
  registration_enabled  = false
  tags                  = var.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "spoke" {
  for_each = local.private_dns_zones

  name                  = "link-spoke"
  resource_group_name   = data.azurerm_resource_group.net.name
  private_dns_zone_name = azurerm_private_dns_zone.this[each.key].name
  virtual_network_id    = azurerm_virtual_network.spoke.id
  registration_enabled  = false
  tags                  = var.tags
}
