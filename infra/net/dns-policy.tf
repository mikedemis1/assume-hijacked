# Azure DNS security policy ("DNS resolver policy"): filters and logs every DNS query of the
# VNets it is linked to. Second DNS layer next to the per-pod Cilium DNS rules (design D9).
#
# WHY azapi: azurerm 4.81.0 has no resource for these objects (checked in the provider
# schema; upstream request https://github.com/hashicorp/terraform-provider-azurerm/issues/28597).
# Everything in THIS file uses azapi, nothing else in the stack does. When azurerm gains the
# resources, move them and drop the azapi provider from versions.tf.
#
# API version: 2025-05-01 (stable) on all four types. Checked on learn.microsoft.com, ARM
# template reference, Microsoft.Network/2025-05-01 pages for dnsResolverPolicies,
# dnsResolverPolicies/dnsSecurityRules, dnsResolverPolicies/virtualNetworkLinks and
# dnsResolverDomainLists. The managed threat-intel list exists only in
# 2025-10-01-preview, so it is not used here.
#
# Behaviour (docs: learn.microsoft.com/azure/dns/dns-security-policy):
#   - Rules run by priority (100-65000, lower first); the first match decides.
#   - A domain matches its subdomains (DNS hierarchy).
#   - Allow: resolve and log. Alert: resolve and log an alert. Block: refuse and log.
#   - A VNet can be linked to one policy only; policy and VNet must be in the same region.
#
# Rules:
#   100   Allow  the allowlist domain list
#   1000  Alert  (var.dns_block_mode = false) or Block (true)  the list with ".", all domains
# With Alert, everything resolves and everything off the allowlist is logged as an alert.

locals {
  dns_api_version = "2025-05-01"
}

resource "azapi_resource" "dns_policy" {
  type      = "Microsoft.Network/dnsResolverPolicies@${local.dns_api_version}"
  name      = "dnsp-assume-hijacked"
  parent_id = data.azurerm_resource_group.net.id
  location  = var.location
  tags      = var.tags

  body = {
    properties = {}
  }
}

resource "azapi_resource" "dns_domains_allowlist" {
  type      = "Microsoft.Network/dnsResolverDomainLists@${local.dns_api_version}"
  name      = "dl-allowlist"
  parent_id = data.azurerm_resource_group.net.id
  location  = var.location
  tags      = var.tags

  body = {
    properties = {
      domains = var.dns_allowed_domains
    }
  }
}

resource "azapi_resource" "dns_domains_all" {
  type      = "Microsoft.Network/dnsResolverDomainLists@${local.dns_api_version}"
  name      = "dl-all-domains"
  parent_id = data.azurerm_resource_group.net.id
  location  = var.location
  tags      = var.tags

  body = {
    properties = {
      domains = ["."]
    }
  }
}

# Writes to one policy are serialized with depends_on: parallel writes to the same parent
# can fail with a conflict.
resource "azapi_resource" "dns_rule_allow" {
  type      = "Microsoft.Network/dnsResolverPolicies/dnsSecurityRules@${local.dns_api_version}"
  name      = "allow-allowlist"
  parent_id = azapi_resource.dns_policy.id
  location  = var.location
  tags      = var.tags

  body = {
    properties = {
      priority             = 100
      action               = { actionType = "Allow" }
      dnsSecurityRuleState = "Enabled"
      dnsResolverDomainLists = [
        { id = azapi_resource.dns_domains_allowlist.id },
      ]
    }
  }
}

resource "azapi_resource" "dns_rule_catch_all" {
  type      = "Microsoft.Network/dnsResolverPolicies/dnsSecurityRules@${local.dns_api_version}"
  name      = "catch-all"
  parent_id = azapi_resource.dns_policy.id
  location  = var.location
  tags      = var.tags

  body = {
    properties = {
      priority             = 1000
      action               = { actionType = var.dns_block_mode ? "Block" : "Alert" }
      dnsSecurityRuleState = "Enabled"
      dnsResolverDomainLists = [
        { id = azapi_resource.dns_domains_all.id },
      ]
    }
  }

  depends_on = [azapi_resource.dns_rule_allow]
}

# One link per VNet. A link cannot be changed after creation.
resource "azapi_resource" "dns_link_hub" {
  type      = "Microsoft.Network/dnsResolverPolicies/virtualNetworkLinks@${local.dns_api_version}"
  name      = "link-hub"
  parent_id = azapi_resource.dns_policy.id
  location  = var.location
  tags      = var.tags

  body = {
    properties = {
      virtualNetwork = { id = azurerm_virtual_network.hub.id }
    }
  }

  depends_on = [azapi_resource.dns_rule_catch_all]
}

resource "azapi_resource" "dns_link_spoke" {
  type      = "Microsoft.Network/dnsResolverPolicies/virtualNetworkLinks@${local.dns_api_version}"
  name      = "link-spoke"
  parent_id = azapi_resource.dns_policy.id
  location  = var.location
  tags      = var.tags

  body = {
    properties = {
      virtualNetwork = { id = azurerm_virtual_network.spoke.id }
    }
  }

  depends_on = [azapi_resource.dns_link_hub]
}

# The query log is the evidence ("no DNS tunnel, and the refusal is in KQL"). Category
# DnsResponse -> table DNSQueryLogs (learn.microsoft.com, supported logs for
# Microsoft.Network/dnsResolverPolicies).
resource "azurerm_monitor_diagnostic_setting" "dns_policy" {
  count = var.log_analytics_workspace_id == null ? 0 : 1

  name                       = "dns-queries-to-log-analytics"
  target_resource_id         = azapi_resource.dns_policy.id
  log_analytics_workspace_id = var.log_analytics_workspace_id

  enabled_log {
    category = "DnsResponse"
  }
}
