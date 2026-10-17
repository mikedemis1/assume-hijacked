# Plan-only tests with mocked providers: nothing here reaches Azure.
# Run from infra/net:  terraform init -backend=false && terraform test

mock_provider "azurerm" {}
mock_provider "azapi" {}

# rg-net is created by infra/base. This stack reads it.
override_data {
  target = data.azurerm_resource_group.net
  values = {
    id       = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net"
    name     = "rg-net"
    location = "northeurope"
  }
}

# Fixed IDs so tests can compare what is linked to what.
override_resource {
  target          = azurerm_virtual_network.hub
  override_during = plan
  values          = { id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet-hub" }
}

override_resource {
  target          = azurerm_virtual_network.spoke
  override_during = plan
  values          = { id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet-spoke" }
}

override_resource {
  target          = azapi_resource.dns_policy
  override_during = plan
  values          = { id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/dnsResolverPolicies/dnsp" }
}

override_resource {
  target          = azapi_resource.dns_domains_allowlist
  override_during = plan
  values          = { id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/dnsResolverDomainLists/dl-allowlist" }
}

override_resource {
  target          = azapi_resource.dns_domains_all
  override_during = plan
  values          = { id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/dnsResolverDomainLists/dl-all-domains" }
}

# Per-instance IDs for the for_each resources, so "this subnet uses that NSG" can be checked.
override_resource {
  target          = azurerm_network_security_group.spoke["snet-aks-system"]
  override_during = plan
  values          = { id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/nsg-snet-aks-system" }
}

override_resource {
  target          = azurerm_network_security_group.spoke["snet-aks-sandbox"]
  override_during = plan
  values          = { id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/nsg-snet-aks-sandbox" }
}

override_resource {
  target          = azurerm_network_security_group.spoke["snet-pe"]
  override_during = plan
  values          = { id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/nsg-snet-pe" }
}

override_resource {
  target          = azurerm_subnet.spoke["snet-aks-system"]
  override_during = plan
  values          = { id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet-spoke/subnets/snet-aks-system" }
}

override_resource {
  target          = azurerm_subnet.spoke["snet-aks-sandbox"]
  override_during = plan
  values          = { id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet-spoke/subnets/snet-aks-sandbox" }
}

override_resource {
  target          = azurerm_subnet.spoke["snet-pe"]
  override_during = plan
  values          = { id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet-spoke/subnets/snet-pe" }
}

override_resource {
  target          = azurerm_subnet.hub["AzureFirewallSubnet"]
  override_during = plan
  values          = { id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet-hub/subnets/AzureFirewallSubnet" }
}

override_resource {
  target          = azurerm_subnet.hub["AzureFirewallManagementSubnet"]
  override_during = plan
  values          = { id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet-hub/subnets/AzureFirewallManagementSubnet" }
}

variables {
  subscription_id = "11111111-2222-3333-4444-555555555555"
  tenant_id       = "66666666-7777-8888-9999-000000000000"
}

# ---------------------------------------------------------------- resource group

run "resource_group_is_read_not_created" {
  command = plan

  assert {
    condition     = data.azurerm_resource_group.net.name == "rg-net"
    error_message = "The stack must read rg-net (created by infra/base)."
  }

  assert {
    condition = alltrue([
      azurerm_virtual_network.hub.resource_group_name == "rg-net",
      azurerm_virtual_network.spoke.resource_group_name == "rg-net",
      azapi_resource.dns_policy.parent_id == data.azurerm_resource_group.net.id,
    ])
    error_message = "Everything must live in the group that was read."
  }
}

# ---------------------------------------------------------------- address plan and subnets

run "address_plan_and_subnet_names" {
  command = plan

  assert {
    condition     = one(azurerm_virtual_network.hub.address_space) == "10.10.0.0/24" && one(azurerm_virtual_network.spoke.address_space) == "10.20.0.0/16"
    error_message = "Hub is 10.10.0.0/24 and spoke is 10.20.0.0/16 by default."
  }

  assert {
    condition     = azurerm_subnet.hub["AzureFirewallSubnet"].address_prefixes == tolist(["10.10.0.0/26"]) && azurerm_subnet.hub["AzureFirewallManagementSubnet"].address_prefixes == tolist(["10.10.0.64/26"])
    error_message = "The two firewall subnets must be /26 and must not overlap."
  }

  assert {
    condition     = toset(keys(azurerm_subnet.hub)) == toset(["AzureFirewallSubnet", "AzureFirewallManagementSubnet"])
    error_message = "Azure requires these exact names for the firewall subnets, and the hub holds nothing else."
  }

  assert {
    condition     = toset(keys(azurerm_subnet.spoke)) == toset(["snet-aks-system", "snet-aks-sandbox", "snet-pe"])
    error_message = "The spoke needs exactly the AKS system, AKS sandbox and private endpoint subnets."
  }

  assert {
    condition = (
      azurerm_subnet.spoke["snet-aks-system"].address_prefixes == tolist(["10.20.0.0/24"])
      && azurerm_subnet.spoke["snet-aks-sandbox"].address_prefixes == tolist(["10.20.1.0/24"])
      && azurerm_subnet.spoke["snet-pe"].address_prefixes == tolist(["10.20.2.0/26"])
    )
    error_message = "Spoke subnets moved: C3 and the NSG rules rely on these ranges."
  }
}

run "aks_subnets_have_the_key_vault_service_endpoint" {
  command = plan

  assert {
    condition = alltrue([
      for n in ["snet-aks-system", "snet-aks-sandbox"] :
      contains(azurerm_subnet.spoke[n].service_endpoints, "Microsoft.KeyVault")
    ])
    error_message = "The Key Vaults in rg-base allow only subnets with the Microsoft.KeyVault service endpoint."
  }

  assert {
    condition     = length(azurerm_subnet.spoke["snet-pe"].service_endpoints) == 0
    error_message = "The private endpoint subnet needs no service endpoint."
  }
}

run "address_spaces_must_have_the_expected_size" {
  command = plan

  variables {
    hub_address_space   = "10.10.0.0/23"
    spoke_address_space = "10.20.0.0/17"
  }

  expect_failures = [var.hub_address_space, var.spoke_address_space]
}

# ---------------------------------------------------------------- NSGs

run "no_subnet_without_an_nsg_except_the_azure_managed_ones" {
  command = plan

  # Every spoke subnet is associated.
  assert {
    condition     = toset(keys(azurerm_subnet_network_security_group_association.spoke)) == toset(keys(azurerm_subnet.spoke))
    error_message = "Every spoke subnet needs an NSG association."
  }

  assert {
    condition = alltrue([
      for k, a in azurerm_subnet_network_security_group_association.spoke :
      a.network_security_group_id == "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/nsg-${k}" && a.subnet_id == "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet-spoke/subnets/${k}"
    ])
    error_message = "Each subnet must be associated with its own NSG."
  }

  # Azure cannot attach an NSG to the firewall subnets: they are exempt, explicitly, by name.
  assert {
    condition     = toset(local.nsg_exempt_subnets) == toset(["AzureFirewallSubnet", "AzureFirewallManagementSubnet"])
    error_message = "Only the two Azure Firewall subnets may be exempt from NSGs."
  }

  # Hub subnets = exactly the exempt ones, so nothing else in the hub escapes unprotected.
  assert {
    condition     = toset(keys(azurerm_subnet.hub)) == toset(local.nsg_exempt_subnets)
    error_message = "The hub must hold only the exempt firewall subnets."
  }
}

run "private_endpoint_subnet_has_network_policies_enabled" {
  command = plan

  assert {
    condition     = azurerm_subnet.spoke["snet-pe"].private_endpoint_network_policies == "Enabled"
    error_message = "NSG rules apply to private endpoints only when network policies are Enabled."
  }
}

run "every_nsg_denies_inbound_from_the_internet_and_everything_else" {
  command = plan

  assert {
    condition = alltrue([
      for k, nsg in azurerm_network_security_group.spoke :
      length([for r in nsg.security_rule : r if r.direction == "Inbound" && r.access == "Deny" && contains(r.source_address_prefixes, "Internet")]) == 1
    ])
    error_message = "Each NSG needs an explicit deny rule for inbound traffic from the Internet."
  }

  assert {
    condition = alltrue([
      for k, nsg in azurerm_network_security_group.spoke :
      length([for r in nsg.security_rule : r if r.direction == "Inbound" && r.access == "Deny" && contains(r.source_address_prefixes, "*") && r.priority == 4096]) == 1
    ])
    error_message = "Each NSG needs a final deny-all inbound rule."
  }

  assert {
    condition = alltrue([
      for k, nsg in azurerm_network_security_group.spoke :
      length([for r in nsg.security_rule : r if r.direction == "Outbound" && r.access == "Deny" && contains(r.destination_address_prefixes, "*") && r.priority == 4096]) == 1
    ])
    error_message = "Each NSG needs a final deny-all outbound rule."
  }

  # No allow rule may take traffic from the Internet or from anywhere.
  assert {
    condition = alltrue([
      for k, nsg in azurerm_network_security_group.spoke : alltrue([
        for r in nsg.security_rule :
        !(r.direction == "Inbound" && r.access == "Allow" && (contains(r.source_address_prefixes, "Internet") || contains(r.source_address_prefixes, "*") || contains(r.source_address_prefixes, "0.0.0.0/0")))
      ])
    ])
    error_message = "No NSG may allow inbound traffic from the Internet or from any source."
  }
}

run "private_endpoint_subnet_accepts_only_5432_and_443_from_the_aks_subnets" {
  command = plan

  assert {
    condition = length([
      for r in azurerm_network_security_group.spoke["snet-pe"].security_rule : r
      if r.direction == "Inbound" && r.access == "Allow"
    ]) == 2
    error_message = "The PE subnet has exactly two inbound allow rules: PostgreSQL and HTTPS."
  }

  assert {
    condition = toset(flatten([
      for r in azurerm_network_security_group.spoke["snet-pe"].security_rule :
      r.destination_port_ranges if r.direction == "Inbound" && r.access == "Allow"
    ])) == toset(["5432", "443"])
    error_message = "Only ports 5432 and 443 may reach the private endpoints."
  }

  assert {
    condition = alltrue([
      for r in azurerm_network_security_group.spoke["snet-pe"].security_rule :
      toset(r.source_address_prefixes) == toset(["10.20.0.0/24", "10.20.1.0/24"])
      if r.direction == "Inbound" && r.access == "Allow"
    ])
    error_message = "Only the two AKS subnets may reach the private endpoints."
  }

  assert {
    condition = alltrue([
      for r in azurerm_network_security_group.spoke["snet-pe"].security_rule :
      r.protocol == "Tcp"
      if r.direction == "Inbound" && r.access == "Allow"
    ])
    error_message = "The PE allow rules are TCP only."
  }
}

run "only_the_system_pool_may_reach_entra" {
  command = plan

  assert {
    condition = length([
      for r in azurerm_network_security_group.spoke["snet-aks-system"].security_rule : r
      if r.direction == "Outbound" && r.access == "Allow" && contains(r.destination_address_prefixes, "AzureActiveDirectory") && contains(r.destination_port_ranges, "443")
    ]) == 1
    error_message = "The system subnet (LLM gateway, console, db-migrate) needs an outbound rule to the AzureActiveDirectory tag on 443."
  }

  assert {
    condition = length([
      for k in ["snet-aks-sandbox", "snet-pe"] : k
      if length([
        for r in azurerm_network_security_group.spoke[k].security_rule : r
        if contains(r.destination_address_prefixes, "AzureActiveDirectory")
      ]) > 0
    ]) == 0
    error_message = "The sandbox and PE subnets must have no Entra rule: tools and agents never sign in."
  }

  assert {
    condition = length([
      for r in azurerm_network_security_group.spoke["snet-aks-sandbox"].security_rule : r
      if r.direction == "Outbound" && r.access == "Allow" && contains(r.destination_address_prefixes, "Internet")
    ]) == 0
    error_message = "The sandbox subnet must have no outbound rule to the general Internet."
  }
}

run "aks_subnets_reach_the_private_endpoints_on_5432_and_443" {
  command = plan

  assert {
    condition = alltrue([
      for k in ["snet-aks-system", "snet-aks-sandbox"] :
      length([
        for r in azurerm_network_security_group.spoke[k].security_rule : r
        if r.direction == "Outbound" && r.access == "Allow" && contains(r.destination_address_prefixes, "10.20.2.0/26") && contains(r.destination_port_ranges, "5432")
      ]) == 1
      && length([
        for r in azurerm_network_security_group.spoke[k].security_rule : r
        if r.direction == "Outbound" && r.access == "Allow" && contains(r.destination_address_prefixes, "10.20.2.0/26") && contains(r.destination_port_ranges, "443")
      ]) == 1
    ])
    error_message = "Both AKS subnets must be able to reach the PE subnet on 5432 and 443 (control: the allowed path still works)."
  }
}

run "nsg_priorities_are_unique_per_direction" {
  command = plan

  assert {
    condition = alltrue([
      for k, nsg in azurerm_network_security_group.spoke : alltrue([
        for d in ["Inbound", "Outbound"] :
        length([for r in nsg.security_rule : r.priority if r.direction == d])
        == length(distinct([for r in nsg.security_rule : r.priority if r.direction == d]))
      ])
    ])
    error_message = "Two rules with the same priority and direction in one NSG are refused by Azure."
  }
}

# ---------------------------------------------------------------- peering

run "peering_goes_both_ways_without_gateways" {
  command = plan

  assert {
    condition     = azurerm_virtual_network_peering.hub_to_spoke.remote_virtual_network_id == azurerm_virtual_network.spoke.id && azurerm_virtual_network_peering.hub_to_spoke.virtual_network_name == "vnet-hub"
    error_message = "Hub to spoke peering is missing."
  }

  assert {
    condition     = azurerm_virtual_network_peering.spoke_to_hub.remote_virtual_network_id == azurerm_virtual_network.hub.id && azurerm_virtual_network_peering.spoke_to_hub.virtual_network_name == "vnet-spoke"
    error_message = "Spoke to hub peering is missing."
  }

  assert {
    condition = alltrue([
      for p in [azurerm_virtual_network_peering.hub_to_spoke, azurerm_virtual_network_peering.spoke_to_hub] :
      p.allow_virtual_network_access && p.allow_forwarded_traffic && !p.allow_gateway_transit && !p.use_remote_gateways
    ])
    error_message = "Peering must allow VNet access and forwarded traffic (firewall) and use no gateways."
  }
}

# ---------------------------------------------------------------- private DNS zones

run "private_dns_zones_are_linked_to_both_vnets" {
  command = plan

  assert {
    condition     = azurerm_private_dns_zone.this["postgres"].name == "privatelink.postgres.database.azure.com" && azurerm_private_dns_zone.this["vault"].name == "privatelink.vaultcore.azure.net"
    error_message = "Zone names must be the Azure privatelink names for PostgreSQL and Key Vault."
  }

  assert {
    condition = alltrue([
      for k in ["postgres", "vault"] :
      azurerm_private_dns_zone_virtual_network_link.hub[k].virtual_network_id == azurerm_virtual_network.hub.id
      && azurerm_private_dns_zone_virtual_network_link.spoke[k].virtual_network_id == azurerm_virtual_network.spoke.id
    ])
    error_message = "Each private DNS zone must be linked to the hub AND the spoke VNet."
  }

  assert {
    condition = alltrue([
      for l in concat(values(azurerm_private_dns_zone_virtual_network_link.hub), values(azurerm_private_dns_zone_virtual_network_link.spoke)) :
      !l.registration_enabled
    ])
    error_message = "Private link zones must not auto-register VMs."
  }
}

# ---------------------------------------------------------------- DNS security policy

run "dns_policy_is_linked_to_both_vnets" {
  command = plan

  assert {
    condition = (
      azapi_resource.dns_link_hub.parent_id == azapi_resource.dns_policy.id
      && azapi_resource.dns_link_spoke.parent_id == azapi_resource.dns_policy.id
      && azapi_resource.dns_link_hub.body.properties.virtualNetwork.id == azurerm_virtual_network.hub.id
      && azapi_resource.dns_link_spoke.body.properties.virtualNetwork.id == azurerm_virtual_network.spoke.id
    )
    error_message = "The DNS security policy must be linked to the hub VNet and the spoke VNet."
  }

  assert {
    condition = alltrue([
      for r in [azapi_resource.dns_policy, azapi_resource.dns_domains_allowlist, azapi_resource.dns_domains_all, azapi_resource.dns_rule_allow, azapi_resource.dns_rule_catch_all, azapi_resource.dns_link_hub, azapi_resource.dns_link_spoke] :
      endswith(r.type, "@2025-05-01")
    ])
    error_message = "All DNS policy objects use the stable API version 2025-05-01 (checked in the ARM reference)."
  }
}

run "dns_catch_all_rule_alerts_by_default" {
  command = plan

  assert {
    condition     = jsonencode(azapi_resource.dns_domains_all.body.properties.domains) == jsonencode(["."])
    error_message = "The catch-all domain list must contain only \".\" (all domains)."
  }

  assert {
    condition = (
      azapi_resource.dns_rule_catch_all.body.properties.dnsResolverDomainLists[0].id == azapi_resource.dns_domains_all.id
      && azapi_resource.dns_rule_catch_all.body.properties.action.actionType == "Alert"
      && azapi_resource.dns_rule_catch_all.body.properties.dnsSecurityRuleState == "Enabled"
    )
    error_message = "By default the rule for \".\" must be enabled and set to Alert, not Block."
  }

  assert {
    condition     = output.dns_block_mode == false
    error_message = "The output must show the mode."
  }
}

run "dns_block_mode_switches_the_catch_all_rule_to_block" {
  command = plan

  variables {
    dns_block_mode = true
  }

  assert {
    condition     = azapi_resource.dns_rule_catch_all.body.properties.action.actionType == "Block"
    error_message = "dns_block_mode = true must switch the rule for \".\" to Block."
  }

  # Control: the allowlist rule stays Allow, so the allowed names still resolve.
  assert {
    condition     = azapi_resource.dns_rule_allow.body.properties.action.actionType == "Allow"
    error_message = "The allowlist rule must stay Allow in block mode."
  }
}

run "dns_allowlist_exists_and_wins_over_the_catch_all" {
  command = plan

  assert {
    condition     = length(azapi_resource.dns_domains_allowlist.body.properties.domains) >= 1 && contains(azapi_resource.dns_domains_allowlist.body.properties.domains, "azurecr.io.")
    error_message = "The allowlist domain list must exist and contain the default Azure domains."
  }

  assert {
    condition = (
      azapi_resource.dns_rule_allow.body.properties.dnsResolverDomainLists[0].id == azapi_resource.dns_domains_allowlist.id
      && azapi_resource.dns_rule_allow.body.properties.action.actionType == "Allow"
      && azapi_resource.dns_rule_allow.body.properties.priority < azapi_resource.dns_rule_catch_all.body.properties.priority
    )
    error_message = "The Allow rule on the allowlist must have a lower priority number (runs first) than the catch-all."
  }

  assert {
    condition     = !contains(azapi_resource.dns_domains_allowlist.body.properties.domains, ".")
    error_message = "The allowlist must never contain \".\": that would allow everything."
  }
}

run "dns_allowlist_must_be_valid" {
  command = plan

  variables {
    dns_allowed_domains = ["azurecr.io"]
  }

  expect_failures = [var.dns_allowed_domains]
}

run "dns_allowlist_cannot_be_the_root_domain" {
  command = plan

  variables {
    dns_allowed_domains = ["."]
  }

  expect_failures = [var.dns_allowed_domains]
}

run "dns_query_log_only_with_a_workspace" {
  command = plan

  assert {
    condition     = length(azurerm_monitor_diagnostic_setting.dns_policy) == 0
    error_message = "Without a workspace there is no diagnostic setting."
  }
}

run "dns_query_log_goes_to_the_workspace" {
  command = plan

  variables {
    log_analytics_workspace_id = "/subscriptions/s/resourceGroups/rg-base/providers/Microsoft.OperationalInsights/workspaces/law"
  }

  assert {
    condition = (
      length(azurerm_monitor_diagnostic_setting.dns_policy) == 1
      && azurerm_monitor_diagnostic_setting.dns_policy[0].target_resource_id == azapi_resource.dns_policy.id
      && one(azurerm_monitor_diagnostic_setting.dns_policy[0].enabled_log).category == "DnsResponse"
    )
    error_message = "The DNS policy must send its DnsResponse log to the workspace."
  }
}

# ---------------------------------------------------------------- outputs and region

run "outputs_give_c3_what_it_needs" {
  command = plan

  assert {
    condition     = toset(keys(output.spoke_subnet_ids)) == toset(["snet-aks-system", "snet-aks-sandbox", "snet-pe"]) && toset(keys(output.hub_subnet_ids)) == toset(["AzureFirewallSubnet", "AzureFirewallManagementSubnet"])
    error_message = "Subnet ID outputs must cover every subnet by name."
  }

  assert {
    condition     = length(output.aks_subnet_ids) == 2
    error_message = "aks_subnet_ids must hold the two AKS subnets (input for infra/base)."
  }

  assert {
    condition     = toset(keys(output.private_dns_zone_ids)) == toset(["postgres", "vault"])
    error_message = "Private DNS zone IDs must be published for postgres and vault."
  }

  assert {
    condition     = output.hub_vnet_id == azurerm_virtual_network.hub.id && output.spoke_vnet_id == azurerm_virtual_network.spoke.id
    error_message = "VNet IDs must be published."
  }
}

run "only_north_europe_is_accepted" {
  command = plan

  variables {
    location = "westeurope"
  }

  expect_failures = [var.location]
}
