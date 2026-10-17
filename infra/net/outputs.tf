output "resource_group_name" {
  description = "Name of rg-net (created by infra/base)."
  value       = data.azurerm_resource_group.net.name
}

output "hub_vnet_id" {
  description = "Hub VNet (Azure Firewall)."
  value       = azurerm_virtual_network.hub.id
}

output "spoke_vnet_id" {
  description = "Spoke VNet (AKS, private endpoints)."
  value       = azurerm_virtual_network.spoke.id
}

output "hub_vnet_name" {
  description = "Hub VNet name."
  value       = azurerm_virtual_network.hub.name
}

output "spoke_vnet_name" {
  description = "Spoke VNet name."
  value       = azurerm_virtual_network.spoke.name
}

output "hub_subnet_ids" {
  description = "Hub subnet IDs by name (AzureFirewallSubnet, AzureFirewallManagementSubnet)."
  value       = { for name, s in azurerm_subnet.hub : name => s.id }
}

output "spoke_subnet_ids" {
  description = "Spoke subnet IDs by name (snet-aks-system, snet-aks-sandbox, snet-pe)."
  value       = { for name, s in azurerm_subnet.spoke : name => s.id }
}

output "spoke_subnet_address_prefixes" {
  description = "Spoke subnet address prefixes by name. infra/lab uses them as firewall rule sources."
  value       = local.spoke_subnets
}

output "aks_pod_cidr" {
  description = "Overlay pod range the AKS NSG rules allow. infra/lab uses it as the cluster's pod_cidr, so the two cannot drift."
  value       = var.aks_pod_cidr
}

output "aks_subnet_ids" {
  description = "The two AKS subnets as a list: the value for infra/base `spoke_subnet_ids` (Key Vault firewall)."
  value       = [for n in local.aks_subnet_names : azurerm_subnet.spoke[n].id]
}

output "private_dns_zone_ids" {
  description = "Private DNS zone IDs: postgres, vault."
  value       = { for k, z in azurerm_private_dns_zone.this : k => z.id }
}

output "private_dns_zone_names" {
  description = "Private DNS zone names: postgres, vault."
  value       = { for k, z in azurerm_private_dns_zone.this : k => z.name }
}

output "dns_policy_id" {
  description = "DNS security policy linked to both VNets."
  value       = azapi_resource.dns_policy.id
}

output "dns_block_mode" {
  description = "false: the catch-all DNS rule only alerts. true: it blocks everything off the allowlist."
  value       = var.dns_block_mode
}
