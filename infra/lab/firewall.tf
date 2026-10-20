# Egress wall: Azure Firewall Basic in the hub, application rules only, and a route table that
# sends every packet from the two AKS subnets to it. Everything here has
# count = enable_firewall ? 1 : 0; with the firewall off, AKS uses its load balancer for egress.
#
# Placement: the firewall resource itself is created in rg-net, because Azure requires the
# firewall and its virtual network in the same resource group ("Are there any Azure firewall
# resource group restrictions?", learn.microsoft.com/azure/firewall/firewall-faq). It still
# belongs to THIS state, so the nightly lab destroy removes it. Policy, public IPs and route
# table live in rg-lab (the FAQ allows the public IP elsewhere; a policy is its own resource).
#
# Basic SKU (learn.microsoft.com/azure/firewall/choose-firewall-sku): application FQDN rules
# and FQDN tags yes; DNS proxy and web categories no; threat intelligence in Alert mode only.
# Basic always needs the management subnet and a management public IP (forced tunnelling NIC).
#
# Rule sources are the subnet prefixes, never "*". Application rules see the node IP (overlay
# pods are SNATed to their node), so "from the system subnet" means any pod on the system pool.

locals {
  firewall_count = var.enable_firewall ? 1 : 0
  all_aks        = [for n in local.aks_subnet_names : local.aks_prefixes[n]]
  system_only    = [local.aks_prefixes["snet-aks-system"]]

  # name -> rule. Both pools pull images and run node agents; only the system pool runs
  # llm-gateway, so only it may reach the model API.
  egress_rules = {
    aks-platform = {
      sources   = local.all_aks
      fqdn_tags = ["AzureKubernetesService"]
      fqdns     = []
      http      = true # the tag covers a few package endpoints on port 80
    }
    entra-login = {
      sources   = local.all_aks
      fqdn_tags = []
      fqdns     = ["login.microsoftonline.com"]
      http      = false
    }
    # ACR Basic has no dedicated data endpoint: image layers come from the registry's blob
    # storage under *.blob.core.windows.net. That wildcard is wider than wanted (any storage
    # account); Premium's <registry>.<region>.data.azurecr.io would remove it.
    acr = {
      sources   = local.all_aks
      fqdn_tags = []
      fqdns     = [local.base.acr_login_server, "*.blob.core.windows.net"]
      http      = false
    }
    mcr = {
      sources   = local.all_aks
      fqdn_tags = []
      fqdns     = ["mcr.microsoft.com", "*.data.mcr.microsoft.com", "mcr-0001.mcr-msedge.net"]
      http      = false
    }
    # Azure Monitor agent (container logs). FQDN list: learn.microsoft.com/azure/aks/outbound-rules-control-egress
    azure-monitor = {
      sources   = local.all_aks
      fqdn_tags = []
      fqdns = [
        "dc.services.visualstudio.com",
        "*.ods.opinsights.azure.com",
        "*.oms.opinsights.azure.com",
        "*.monitoring.azure.com",
        "global.handler.control.monitor.azure.com",
        "${var.location}.handler.control.monitor.azure.com",
        "${var.location}.ingest.monitor.azure.com",
      ]
      http = false
    }
    gitlab-agent = {
      sources   = local.all_aks
      fqdn_tags = []
      fqdns     = ["kas.gitlab.com"]
      http      = false
    }
  }

  llm_rules = var.anthropic_enabled ? {
    anthropic-api = {
      sources   = local.system_only
      fqdn_tags = []
      fqdns     = ["api.anthropic.com"]
      http      = false
    }
  } : {}
}

resource "azurerm_public_ip" "firewall_data" {
  count = local.firewall_count

  name                = "pip-afw-data"
  resource_group_name = data.azurerm_resource_group.lab.name
  location            = var.location
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = var.tags
}

resource "azurerm_public_ip" "firewall_management" {
  count = local.firewall_count

  name                = "pip-afw-management"
  resource_group_name = data.azurerm_resource_group.lab.name
  location            = var.location
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = var.tags
}

resource "azurerm_firewall_policy" "egress" {
  #checkov:skip=CKV_AZURE_220: IDPS needs the Premium SKU; the lab uses Basic
  count = local.firewall_count

  name                     = "afwp-egress"
  resource_group_name      = data.azurerm_resource_group.lab.name
  location                 = var.location
  sku                      = "Basic"
  threat_intelligence_mode = "Alert" # the only mode Basic supports
  tags                     = var.tags
}

resource "azurerm_firewall_policy_rule_collection_group" "egress" {
  count = local.firewall_count

  name               = "egress"
  firewall_policy_id = azurerm_firewall_policy.egress[0].id
  priority           = 100

  application_rule_collection {
    name     = "cluster-egress"
    priority = 100
    action   = "Allow"

    dynamic "rule" {
      for_each = local.egress_rules

      content {
        name                  = rule.key
        source_addresses      = rule.value.sources
        destination_fqdn_tags = rule.value.fqdn_tags
        destination_fqdns     = rule.value.fqdns

        protocols {
          type = "Https"
          port = 443
        }

        dynamic "protocols" {
          for_each = rule.value.http ? [1] : []

          content {
            type = "Http"
            port = 80
          }
        }
      }
    }
  }

  dynamic "application_rule_collection" {
    for_each = length(local.llm_rules) > 0 ? [1] : []
    content {
      name     = "llm-egress"
      priority = 200
      action   = "Allow"

      dynamic "rule" {
        for_each = local.llm_rules

        content {
          name                  = rule.key
          source_addresses      = rule.value.sources
          destination_fqdn_tags = rule.value.fqdn_tags
          destination_fqdns     = rule.value.fqdns

          protocols {
            type = "Https"
            port = 443
          }
        }
      }
    }
  }
}

resource "azurerm_firewall" "hub" {
  #checkov:skip=CKV_AZURE_216: Basic supports threat intelligence in Alert mode only
  count = local.firewall_count

  name                = "afw-hub"
  resource_group_name = local.net.resource_group_name # same group as vnet-hub (Azure rule)
  location            = var.location
  sku_name            = "AZFW_VNet"
  sku_tier            = "Basic"
  firewall_policy_id  = azurerm_firewall_policy.egress[0].id

  ip_configuration {
    name                 = "data"
    subnet_id            = local.net.hub_subnet_ids["AzureFirewallSubnet"]
    public_ip_address_id = azurerm_public_ip.firewall_data[0].id
  }

  management_ip_configuration {
    name                 = "management"
    subnet_id            = local.net.hub_subnet_ids["AzureFirewallManagementSubnet"]
    public_ip_address_id = azurerm_public_ip.firewall_management[0].id
  }

  tags = var.tags
}

# ---------------------------------------------------------------- route table

resource "azurerm_route_table" "aks" {
  count = local.firewall_count

  name                          = "rt-aks-egress"
  resource_group_name           = data.azurerm_resource_group.lab.name
  location                      = var.location
  bgp_route_propagation_enabled = false
  tags                          = var.tags
}

# Everything leaves through the firewall.
resource "azurerm_route" "default_to_firewall" {
  count = local.firewall_count

  name                   = "default-to-firewall"
  resource_group_name    = data.azurerm_resource_group.lab.name
  route_table_name       = azurerm_route_table.aks[0].name
  address_prefix         = "0.0.0.0/0"
  next_hop_type          = "VirtualAppliance"
  next_hop_in_ip_address = azurerm_firewall.hub[0].ip_configuration[0].private_ip_address
}

# Return path for traffic that reaches the firewall's public IP from outside (AKS docs: avoids
# asymmetric routing).
resource "azurerm_route" "firewall_ip_to_internet" {
  count = local.firewall_count

  name                = "firewall-public-ip-to-internet"
  resource_group_name = data.azurerm_resource_group.lab.name
  route_table_name    = azurerm_route_table.aks[0].name
  address_prefix      = "${azurerm_public_ip.firewall_data[0].ip_address}/32"
  next_hop_type       = "Internet"
}

resource "azurerm_subnet_route_table_association" "aks" {
  for_each = var.enable_firewall ? local.aks_subnet_ids : {}

  subnet_id      = each.value
  route_table_id = azurerm_route_table.aks[0].id

  # The routes must be in the table before a subnet uses it.
  depends_on = [azurerm_route.default_to_firewall, azurerm_route.firewall_ip_to_internet]
}
