# Plan-only tests with mocked providers: nothing here reaches Azure or Entra.
# Run from infra/lab:  terraform init -backend=false && terraform test
#
# The base state is replaced with override_data, in the shape of its real outputs.
# Computed values the assertions compare are fixed with override_resource (plan phase).

mock_provider "azurerm" {}

run "postgres_errors_do_not_log_health_arguments" {
  command = plan
  assert {
    condition = tomap({ for name, setting in azurerm_postgresql_flexible_server_configuration.privacy : name => setting.value }) == tomap({
      log_min_error_statement           = "panic"
      log_parameter_max_length          = "0"
      log_parameter_max_length_on_error = "0"
      log_statement                     = "none"
      log_min_duration_statement        = "-1"
      log_min_duration_sample           = "-1"
    })
    error_message = "Statement and bind-parameter logging must not disclose health-related arguments."
  }
}

variables {
  subscription_id            = "11111111-2222-3333-4444-555555555555"
  tenant_id                  = "66666666-7777-8888-9999-000000000000"
  state_storage_account_name = "stahtestexample01"
  api_authorized_ip_ranges   = ["203.0.113.10/32"]
  alert_email                = "owner@example.com"
  capabilities_dir           = "tests/fixtures/capabilities"
}

# ---------------------------------------------------------------- inputs from base

override_data {
  target = data.azurerm_resource_group.lab
  values = {
    id       = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-lab"
    name     = "rg-lab"
    location = "swedencentral"
  }
}

override_data {
  target = data.terraform_remote_state.base
  values = {
    outputs = {
      acr_id                     = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-base/providers/Microsoft.ContainerRegistry/registries/acrahtest"
      acr_login_server           = "acrahtest.azurecr.io"
      log_analytics_workspace_id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-base/providers/Microsoft.OperationalInsights/workspaces/log-assume-hijacked"
      key_vaults = {
        kv-db-migrate = {
          name = "kv-db-migrate-a1b2c3"
          id   = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-base/providers/Microsoft.KeyVault/vaults/kv-db-migrate-a1b2c3"
          uri  = "https://kv-db-migrate-a1b2c3.vault.azure.net/"
        }
        kv-tool-lookup-account = {
          name = "kv-tool-lookup-a-d4e5f6"
          id   = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-base/providers/Microsoft.KeyVault/vaults/kv-tool-lookup-a-d4e5f6"
          uri  = "https://kv-tool-lookup-a-d4e5f6.vault.azure.net/"
        }
        kv-llm-gateway = {
          name = "kv-llm-gateway-778899"
          id   = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-base/providers/Microsoft.KeyVault/vaults/kv-llm-gateway-778899"
          uri  = "https://kv-llm-gateway-778899.vault.azure.net/"
        }
      }
    }
  }
}

# ---------------------------------------------------------------- fixed computed values

# Network resources: fixed ids so the assertions can compare them.
override_resource {
  target          = azurerm_virtual_network.vnet
  override_during = plan
  values = {
    id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-lab/providers/Microsoft.Network/virtualNetworks/vnet-assume-hijacked"
  }
}

override_resource {
  target          = azurerm_subnet.subnet["snet-aks-system"]
  override_during = plan
  values = {
    id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-lab/providers/Microsoft.Network/virtualNetworks/vnet-assume-hijacked/subnets/snet-aks-system"
  }
}

override_resource {
  target          = azurerm_subnet.subnet["snet-aks-sandbox"]
  override_during = plan
  values = {
    id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-lab/providers/Microsoft.Network/virtualNetworks/vnet-assume-hijacked/subnets/snet-aks-sandbox"
  }
}

override_resource {
  target          = azurerm_subnet.subnet["snet-pe"]
  override_during = plan
  values = {
    id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-lab/providers/Microsoft.Network/virtualNetworks/vnet-assume-hijacked/subnets/snet-pe"
  }
}

override_resource {
  target          = azurerm_private_dns_zone.postgres
  override_during = plan
  values = {
    id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-lab/providers/Microsoft.Network/privateDnsZones/privatelink.postgres.database.azure.com"
  }
}

override_resource {
  target          = azurerm_kubernetes_cluster.this
  override_during = plan
  values = {
    id              = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-lab/providers/Microsoft.ContainerService/managedClusters/aks-assume-hijacked"
    oidc_issuer_url = "https://swedencentral.oic.prod-aks.azure.com/66666666-7777-8888-9999-000000000000/cluster/"
  }
}

override_resource {
  target          = azurerm_postgresql_flexible_server.this
  override_during = plan
  values = {
    id   = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-lab/providers/Microsoft.DBforPostgreSQL/flexibleServers/psql-ah-test"
    fqdn = "psql-ah-test.postgres.database.azure.com"
  }
}

override_resource {
  target          = module.workload_identity["db-migrate"].azurerm_user_assigned_identity.this
  override_during = plan
  values = {
    id           = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-lab/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-db-migrate"
    principal_id = "aaaaaaaa-0000-0000-0000-00000000db01"
    client_id    = "bbbbbbbb-0000-0000-0000-00000000db01"
  }
}

override_resource {
  target          = azurerm_user_assigned_identity.aks_kubelet
  override_during = plan
  values = {
    id           = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-lab/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-aks-kubelet"
    principal_id = "aaaaaaaa-0000-0000-0000-0000000000c1"
    client_id    = "bbbbbbbb-0000-0000-0000-0000000000c1"
  }
}

override_resource {
  target          = azurerm_user_assigned_identity.aks_control_plane
  override_during = plan
  values = {
    id           = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-lab/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-aks-control-plane"
    principal_id = "aaaaaaaa-0000-0000-0000-0000000000c0"
    client_id    = "bbbbbbbb-0000-0000-0000-0000000000c0"
  }
}

override_resource {
  target          = azurerm_monitor_action_group.owner
  override_during = plan
  values = {
    id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-lab/providers/Microsoft.Insights/actionGroups/ag-assume-hijacked"
  }
}

# ---------------------------------------------------------------- resource group

run "lab_uses_rg_lab_without_creating_it" {
  command = plan

  assert {
    condition     = azurerm_kubernetes_cluster.this.resource_group_name == "rg-lab" && azurerm_postgresql_flexible_server.this.resource_group_name == "rg-lab"
    error_message = "The lab must deploy into the rg-lab read through the data source."
  }

  assert {
    condition     = data.azurerm_resource_group.lab.name == var.resource_group_name
    error_message = "rg-lab must be read, not created: destroying the lab must never remove the group."
  }
}

# ---------------------------------------------------------------- node pools

run "system_pool_has_two_or_more_nodes_and_is_not_b_series" {
  command = plan

  assert {
    condition     = azurerm_kubernetes_cluster.this.default_node_pool[0].node_count >= 2
    error_message = "The system pool must have at least 2 nodes."
  }

  assert {
    condition     = !startswith(lower(azurerm_kubernetes_cluster.this.default_node_pool[0].vm_size), "standard_b")
    error_message = "The system pool must not use a burstable B-series size."
  }

  assert {
    condition     = azurerm_kubernetes_cluster.this.default_node_pool[0].vm_size == "Standard_D4s_v6"
    error_message = "The node size is Standard_D4s_v6 (the only size the base policy allows)."
  }

  assert {
    condition     = azurerm_kubernetes_cluster.this.default_node_pool[0].only_critical_addons_enabled == true
    error_message = "The system pool must carry the CriticalAddonsOnly=true:NoSchedule taint."
  }

  assert {
    condition     = azurerm_kubernetes_cluster.this.default_node_pool[0].os_sku == "AzureLinux"
    error_message = "The system pool runs Azure Linux."
  }

  assert {
    condition     = azurerm_kubernetes_cluster.this.default_node_pool[0].vnet_subnet_id == azurerm_subnet.subnet["snet-aks-system"].id
    error_message = "The system pool belongs in snet-aks-system."
  }
}

run "one_node_system_pool_is_refused" {
  command = plan

  variables {
    system_node_count = 1
  }

  expect_failures = [var.system_node_count]
}

run "b_series_size_is_refused" {
  command = plan

  variables {
    node_vm_size = "Standard_B4ms"
  }

  expect_failures = [var.node_vm_size]
}

run "sandbox_pool_uses_kata_on_azure_linux" {
  command = plan

  assert {
    condition     = azurerm_kubernetes_cluster_node_pool.sandbox.workload_runtime == "KataVmIsolation"
    error_message = "The sandbox pool must run the Kata VM isolation runtime."
  }

  assert {
    condition     = azurerm_kubernetes_cluster_node_pool.sandbox.os_sku == "AzureLinux"
    error_message = "Kata on AKS needs Azure Linux."
  }

  assert {
    condition     = azurerm_kubernetes_cluster_node_pool.sandbox.mode == "User" && azurerm_kubernetes_cluster_node_pool.sandbox.node_count == 1
    error_message = "The sandbox pool is a user pool with one node by default."
  }

  assert {
    condition     = azurerm_kubernetes_cluster_node_pool.sandbox.vnet_subnet_id == azurerm_subnet.subnet["snet-aks-sandbox"].id
    error_message = "The sandbox pool belongs in snet-aks-sandbox."
  }
}

run "sandbox_pool_can_be_parked_at_zero" {
  command = plan

  variables {
    sandbox_node_count = 0
  }

  assert {
    condition     = azurerm_kubernetes_cluster_node_pool.sandbox.node_count == 0
    error_message = "sandbox_node_count = 0 must park the pool."
  }
}

# ---------------------------------------------------------------- cluster access and network

run "cluster_has_local_accounts_disabled_and_entra_rbac" {
  command = plan

  assert {
    condition     = azurerm_kubernetes_cluster.this.local_account_disabled == true
    error_message = "Local accounts must be disabled."
  }

  assert {
    condition     = azurerm_kubernetes_cluster.this.azure_active_directory_role_based_access_control[0].azure_rbac_enabled == true && azurerm_kubernetes_cluster.this.role_based_access_control_enabled == true
    error_message = "Access must go through Entra with Azure RBAC."
  }

  assert {
    condition     = azurerm_kubernetes_cluster.this.run_command_enabled == false
    error_message = "Run command bypasses the API authorized ranges; it must be off."
  }

  assert {
    condition     = azurerm_kubernetes_cluster.this.oidc_issuer_enabled == true && azurerm_kubernetes_cluster.this.workload_identity_enabled == true
    error_message = "OIDC issuer and workload identity must be on."
  }

  assert {
    condition     = azurerm_kubernetes_cluster.this.sku_tier == "Free"
    error_message = "The cluster runs on the Free tier."
  }

  assert {
    condition     = length(azurerm_kubernetes_cluster.this.microsoft_defender) == 0
    error_message = "Defender is off by default."
  }
}

run "defender_switch_turns_the_profile_on" {
  command = plan

  variables {
    defender_enabled = true
  }

  assert {
    condition     = length(azurerm_kubernetes_cluster.this.microsoft_defender) == 1
    error_message = "defender_enabled = true must add the Defender profile."
  }
}

run "cluster_network_is_cilium_overlay_with_acns" {
  command = plan

  assert {
    condition = (
      azurerm_kubernetes_cluster.this.network_profile[0].network_plugin == "azure"
      && azurerm_kubernetes_cluster.this.network_profile[0].network_plugin_mode == "overlay"
      && azurerm_kubernetes_cluster.this.network_profile[0].network_data_plane == "cilium"
      && azurerm_kubernetes_cluster.this.network_profile[0].network_policy == "cilium"
    )
    error_message = "The cluster uses Azure CNI overlay with the Cilium data plane and policy engine."
  }

  assert {
    condition     = azurerm_kubernetes_cluster.this.network_profile[0].advanced_networking[0].security_enabled == true
    error_message = "ACNS security (Cilium FQDN and L7 policy) must be on: the per-pod DNS rules need it."
  }

  assert {
    condition     = azurerm_kubernetes_cluster.this.network_profile[0].pod_cidr == var.aks_pod_cidr
    error_message = "The pod range must be the one the AKS NSGs allow."
  }
}

run "api_server_admits_only_listed_ranges" {
  command = plan

  assert {
    condition     = toset(azurerm_kubernetes_cluster.this.api_server_access_profile[0].authorized_ip_ranges) == toset(["203.0.113.10/32"])
    error_message = "Authorized ranges must be exactly the variable."
  }
}

run "open_api_server_is_refused" {
  command = plan

  variables {
    api_authorized_ip_ranges = ["0.0.0.0/0"]
  }

  expect_failures = [var.api_authorized_ip_ranges]
}

run "empty_api_range_list_is_refused" {
  command = plan

  variables {
    api_authorized_ip_ranges = []
  }

  expect_failures = [var.api_authorized_ip_ranges]
}

# ---------------------------------------------------------------- network and egress

run "one_vnet_with_three_subnets_and_no_firewall" {
  command = plan

  assert {
    condition     = azurerm_virtual_network.vnet.address_space == toset(["10.20.0.0/16"])
    error_message = "The lab has one VNet, 10.20.0.0/16."
  }

  assert {
    condition = (
      azurerm_subnet.subnet["snet-aks-system"].address_prefixes == tolist(["10.20.0.0/24"])
      && azurerm_subnet.subnet["snet-aks-sandbox"].address_prefixes == tolist(["10.20.1.0/24"])
      && azurerm_subnet.subnet["snet-pe"].address_prefixes == tolist(["10.20.2.0/26"])
      && length(azurerm_subnet.subnet) == 3
    )
    error_message = "Three subnets: system, sandbox, private endpoints."
  }

  assert {
    condition     = azurerm_subnet.subnet["snet-pe"].private_endpoint_network_policies == "Enabled"
    error_message = "NSG rules must apply to the private endpoint subnet."
  }

  # The Key Vaults in rg-base accept only the AKS subnets, through this service endpoint.
  assert {
    condition = (
      azurerm_subnet.subnet["snet-aks-system"].service_endpoints == toset(["Microsoft.KeyVault"])
      && azurerm_subnet.subnet["snet-aks-sandbox"].service_endpoints == toset(["Microsoft.KeyVault"])
    )
    error_message = "Both AKS subnets need the Microsoft.KeyVault service endpoint."
  }

  assert {
    condition     = azurerm_kubernetes_cluster.this.network_profile[0].outbound_type == "loadBalancer"
    error_message = "With no firewall, AKS egress uses its load balancer."
  }
}

run "every_subnet_has_an_nsg_that_ends_in_deny_all" {
  command = plan

  assert {
    condition     = toset(keys(azurerm_subnet_network_security_group_association.subnet)) == toset(["snet-aks-system", "snet-aks-sandbox", "snet-pe"])
    error_message = "Every subnet is attached to an NSG."
  }

  assert {
    condition = alltrue([
      for k, n in azurerm_network_security_group.subnet :
      anytrue([for r in n.security_rule : r.direction == "Inbound" && r.access == "Deny" && r.priority == 4096 && r.source_address_prefix == "*"])
    ])
    error_message = "Every NSG must end with an inbound deny-all rule."
  }

  assert {
    condition = alltrue([
      for k, n in azurerm_network_security_group.subnet :
      anytrue([for r in n.security_rule : r.direction == "Outbound" && r.access == "Deny" && r.priority == 4096 && r.destination_address_prefix == "*"])
    ])
    error_message = "Every NSG must end with an outbound deny-all rule."
  }

  # The private endpoint subnet only takes traffic from the AKS subnets.
  assert {
    condition = alltrue([
      for r in azurerm_network_security_group.subnet["snet-pe"].security_rule :
      r.access == "Deny" || (r.direction == "Inbound" && r.source_address_prefixes == toset(["10.20.0.0/24", "10.20.1.0/24"]))
    ])
    error_message = "snet-pe may only be reached from the two AKS subnets."
  }
}

run "service_range_overlapping_the_pod_range_is_refused" {
  command = plan

  variables {
    service_cidr = "10.244.128.0/17"
  }

  expect_failures = [azurerm_kubernetes_cluster.this]
}

# ---------------------------------------------------------------- PostgreSQL

run "postgres_is_private_b1ms_17_with_password_and_entra" {
  command = plan

  assert {
    condition     = azurerm_postgresql_flexible_server.this.public_network_access_enabled == false
    error_message = "PostgreSQL public network access must be disabled."
  }

  assert {
    condition     = azurerm_postgresql_flexible_server.this.sku_name == "B_Standard_B1ms" && azurerm_postgresql_flexible_server.this.version == "17"
    error_message = "PostgreSQL is B1ms, version 17."
  }

  assert {
    condition = (
      azurerm_postgresql_flexible_server.this.authentication[0].active_directory_auth_enabled == true
      && azurerm_postgresql_flexible_server.this.authentication[0].password_auth_enabled == true
    )
    error_message = "Both Entra and password authentication must be on."
  }

  assert {
    condition     = azurerm_postgresql_flexible_server_active_directory_administrator.db_migrate.object_id == "aaaaaaaa-0000-0000-0000-00000000db01" && azurerm_postgresql_flexible_server_active_directory_administrator.db_migrate.principal_name == "id-db-migrate"
    error_message = "The Entra administrator must be the db-migrate workload identity."
  }

  assert {
    condition = (
      azurerm_private_endpoint.postgres.subnet_id == azurerm_subnet.subnet["snet-pe"].id
      && azurerm_private_endpoint.postgres.private_service_connection[0].subresource_names == tolist(["postgresqlServer"])
      && azurerm_private_endpoint.postgres.private_dns_zone_group[0].private_dns_zone_ids == tolist([azurerm_private_dns_zone.postgres.id])
    )
    error_message = "The server is reached through a private endpoint in snet-pe registered in the postgres private DNS zone."
  }

  assert {
    condition = (
      azurerm_private_dns_zone.postgres.name == "privatelink.postgres.database.azure.com"
      && azurerm_private_dns_zone_virtual_network_link.postgres.virtual_network_id == azurerm_virtual_network.vnet.id
      && azurerm_private_dns_zone_virtual_network_link.postgres.private_dns_zone_name == azurerm_private_dns_zone.postgres.name
    )
    error_message = "The postgres private DNS zone must be linked to the lab VNet."
  }
}

run "postgres_allow_lists_pgcrypto" {
  command = plan

  assert {
    condition = (
      azurerm_postgresql_flexible_server_configuration.extensions.name == "azure.extensions"
      && contains(split(",", upper(azurerm_postgresql_flexible_server_configuration.extensions.value)), "PGCRYPTO")
      && azurerm_postgresql_flexible_server_configuration.extensions.server_id == azurerm_postgresql_flexible_server.this.id
    )
    error_message = "pgcrypto must be allow-listed (azure.extensions): db/sql/05-lease.sql creates it."
  }
}

run "extension_list_without_pgcrypto_is_refused" {
  command = plan

  variables {
    postgres_extensions = ["CITEXT"]
  }

  expect_failures = [var.postgres_extensions]
}

run "postgres_admin_password_never_reaches_the_state" {
  command = plan

  assert {
    condition     = azurerm_postgresql_flexible_server.this.administrator_password == null
    error_message = "The stored administrator_password must stay empty: only the write-only argument may carry it."
  }

  assert {
    condition     = azurerm_postgresql_flexible_server.this.administrator_password_wo == null && azurerm_postgresql_flexible_server.this.administrator_password_wo_version == 1
    error_message = "The password goes through administrator_password_wo (null in plan and state), versioned for rotation."
  }
}

# ---------------------------------------------------------------- identities from manifests

run "identities_come_from_the_manifests" {
  command = plan

  assert {
    condition     = toset(keys(module.workload_identity)) == toset(["db-migrate", "tool-lookup-account", "llm-gateway"])
    error_message = "One workload identity per manifest with an azure.identity."
  }

  assert {
    condition = (
      module.workload_identity["tool-lookup-account"].subject == "system:serviceaccount:ah-tools:tool-lookup-account"
      && module.workload_identity["db-migrate"].subject == "system:serviceaccount:ah-core:db-migrate"
      && module.workload_identity["llm-gateway"].subject == "system:serviceaccount:ah-agent:llm-gateway"
    )
    error_message = "Each identity trusts exactly its component's ServiceAccount in the chart's namespace."
  }

  assert {
    condition     = output.unassigned_azure_roles == ["llm-gateway: Storage Blob Data Reader on storage-resource"]
    error_message = "Roles outside Key Vault must be reported, not assigned."
  }
}

run "key_vault_roles_use_the_physical_vault_ids_from_base" {
  command = plan

  assert {
    condition = (
      module.workload_identity["tool-lookup-account"].role_assignments["kv-tool-lookup-account/Key Vault Secrets User"].scope_id
      == data.terraform_remote_state.base.outputs.key_vaults["kv-tool-lookup-account"].id
    )
    error_message = "Vault roles must be scoped to the physical vault ID from the base output, never to the scope string."
  }

  assert {
    condition = alltrue(flatten([
      for c, m in module.workload_identity : [
        for k, a in m.role_assignments : startswith(a.scope_id, "/subscriptions/") && strcontains(a.scope_id, "/providers/Microsoft.KeyVault/vaults/")
      ]
    ]))
    error_message = "Every vault role must target a Key Vault resource ID."
  }

  assert {
    condition     = output.component_key_vaults["tool-lookup-account"] == "kv-tool-lookup-a-d4e5f6" && output.component_key_vaults["db-migrate"] == "kv-db-migrate-a1b2c3"
    error_message = "The chart gets the physical vault name of each component's own vault."
  }
}

run "workload_vault_missing_in_base_is_refused" {
  command = plan

  override_data {
    target = data.terraform_remote_state.base
    values = {
      outputs = {
        acr_id                     = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-base/providers/Microsoft.ContainerRegistry/registries/acrahtest"
        acr_login_server           = "acrahtest.azurecr.io"
        log_analytics_workspace_id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-base/providers/Microsoft.OperationalInsights/workspaces/log-assume-hijacked"
        key_vaults = {
          kv-db-migrate = {
            name = "kv-db-migrate-a1b2c3"
            id   = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-base/providers/Microsoft.KeyVault/vaults/kv-db-migrate-a1b2c3"
            uri  = "https://kv-db-migrate-a1b2c3.vault.azure.net/"
          }
        }
      }
    }
  }

  expect_failures = [terraform_data.manifest_checks]
}

run "vault_rbac_is_derived_officer_for_db_migrate_user_for_own_vault" {
  command = plan

  assert {
    condition = (
      toset(keys(module.workload_identity["db-migrate"].role_assignments)) == toset(["kv-db-migrate/Key Vault Secrets User", "kv-tool-lookup-account/Key Vault Secrets Officer"])
      && module.workload_identity["db-migrate"].role_assignments["kv-tool-lookup-account/Key Vault Secrets Officer"].scope_id == data.terraform_remote_state.base.outputs.key_vaults["kv-tool-lookup-account"].id
    )
    error_message = "db-migrate gets Secrets Officer on the vault of every component with a DB role (here tool-lookup-account), plus Secrets User on its own vault, nothing else."
  }

  assert {
    condition = (
      toset(keys(module.workload_identity["tool-lookup-account"].role_assignments)) == toset(["kv-tool-lookup-account/Key Vault Secrets User"])
      && toset(keys(module.workload_identity["llm-gateway"].role_assignments)) == toset(["kv-llm-gateway/Key Vault Secrets User"])
    )
    error_message = "Each workload gets Secrets User on its own vault only."
  }

  assert {
    condition = alltrue(flatten([
      for c, m in module.workload_identity : [
        for k, a in m.role_assignments : a.role != "Key Vault Secrets Officer" || c == "db-migrate"
      ]
    ]))
    error_message = "Only db-migrate may hold Secrets Officer."
  }
}

run "manifest_asking_for_another_components_vault_is_refused" {
  command = plan

  variables {
    capabilities_dir = "tests/fixtures/capabilities-foreign-vault"
  }

  expect_failures = [terraform_data.manifest_checks]
}

run "manifest_asking_for_secrets_officer_is_refused" {
  command = plan

  variables {
    capabilities_dir = "tests/fixtures/capabilities-officer"
  }

  expect_failures = [terraform_data.manifest_checks]
}

run "db_migrate_officer_outside_db_components_is_refused" {
  command = plan

  variables {
    capabilities_dir = "tests/fixtures/capabilities-officer-scope"
  }

  expect_failures = [terraform_data.manifest_checks]
}

run "component_without_a_namespace_is_refused" {
  command = plan

  variables {
    service_account_namespaces = {
      "db-migrate" = "ah-core"
    }
  }

  expect_failures = [terraform_data.manifest_checks]
}

run "cluster_identities_get_their_roles_before_the_cluster" {
  command = plan

  assert {
    condition     = azurerm_role_assignment.aks_kubelet_acr_pull.role_definition_name == "AcrPull" && azurerm_role_assignment.aks_kubelet_acr_pull.scope == data.terraform_remote_state.base.outputs.acr_id
    error_message = "The kubelet identity pulls from the registry with AcrPull."
  }

  assert {
    condition     = toset([for a in azurerm_role_assignment.aks_control_plane_subnets : a.scope]) == toset([azurerm_subnet.subnet["snet-aks-system"].id, azurerm_subnet.subnet["snet-aks-sandbox"].id])
    error_message = "The control plane gets Network Contributor on exactly the two AKS subnets."
  }

  assert {
    condition     = azurerm_kubernetes_cluster.this.kubelet_identity[0].user_assigned_identity_id == azurerm_user_assigned_identity.aks_kubelet.id
    error_message = "The cluster must use the kubelet identity that holds AcrPull."
  }
}

# ---------------------------------------------------------------- logs and alerts

run "diagnostic_settings_send_audit_logs_to_the_workspace" {
  command = plan

  assert {
    condition     = contains([for l in azurerm_monitor_diagnostic_setting.aks.enabled_log : l.category], "kube-audit-admin")
    error_message = "AKS audit logs must be collected."
  }

  assert {
    condition     = contains([for l in azurerm_monitor_diagnostic_setting.postgres.enabled_log : l.category], "PostgreSQLLogs")
    error_message = "PostgreSQL logs must be collected."
  }

  assert {
    condition     = toset(keys(azurerm_monitor_diagnostic_setting.key_vault)) == toset(keys(data.terraform_remote_state.base.outputs.key_vaults))
    error_message = "Every workload vault gets an audit diagnostic setting."
  }

  assert {
    condition = alltrue(concat(
      [azurerm_monitor_diagnostic_setting.aks.log_analytics_workspace_id == data.terraform_remote_state.base.outputs.log_analytics_workspace_id],
      [azurerm_monitor_diagnostic_setting.postgres.log_analytics_workspace_id == data.terraform_remote_state.base.outputs.log_analytics_workspace_id],
      [for d in azurerm_monitor_diagnostic_setting.key_vault : d.log_analytics_workspace_id == data.terraform_remote_state.base.outputs.log_analytics_workspace_id],
    ))
    error_message = "All diagnostics go to the base workspace."
  }
}

run "container_logs_are_collected_from_the_app_namespaces_only" {
  command = plan

  assert {
    condition     = jsondecode(azurerm_monitor_data_collection_rule.container_logs.data_sources[0].extension[0].extension_json).dataCollectionSettings.namespaceFilteringMode == "Include"
    error_message = "Container logs must be filtered to the listed namespaces."
  }

  assert {
    condition     = alltrue([for ns in jsondecode(azurerm_monitor_data_collection_rule.container_logs.data_sources[0].extension[0].extension_json).dataCollectionSettings.namespaces : startswith(ns, "ah-")])
    error_message = "Only the ah-* namespaces are collected."
  }

  assert {
    condition     = azurerm_monitor_data_collection_rule_association.container_logs.target_resource_id == azurerm_kubernetes_cluster.this.id
    error_message = "The collection rule must be attached to the cluster."
  }
}

run "two_log_alerts_reach_the_owner" {
  command = plan

  assert {
    condition     = toset(keys(azurerm_monitor_scheduled_query_rules_alert_v2.this)) == toset(["heartbeat-missing", "attack-events"])
    error_message = "The two alert rules must exist."
  }

  assert {
    condition = alltrue([
      for k, a in azurerm_monitor_scheduled_query_rules_alert_v2.this :
      a.action[0].action_groups == tolist([azurerm_monitor_action_group.owner.id]) && a.scopes == tolist([data.terraform_remote_state.base.outputs.log_analytics_workspace_id])
    ])
    error_message = "Every rule queries the base workspace and notifies the owner's action group."
  }

  assert {
    condition     = azurerm_monitor_action_group.owner.email_receiver[0].email_address == "owner@example.com"
    error_message = "Alerts go to the address from the variable."
  }

  assert {
    condition = (
      strcontains(azurerm_monitor_scheduled_query_rules_alert_v2.this["heartbeat-missing"].criteria[0].query, "KubePodInventory")
      && strcontains(azurerm_monitor_scheduled_query_rules_alert_v2.this["attack-events"].criteria[0].query, "ContainerLogV2")
      && strcontains(azurerm_monitor_scheduled_query_rules_alert_v2.this["attack-events"].criteria[0].query, "\"blocked\"")
    )
    error_message = "Each rule must query its table."
  }
}

run "alert_address_must_be_an_email" {
  command = plan

  variables {
    alert_email = "not-an-address"
  }

  expect_failures = [var.alert_email]
}

# ---------------------------------------------------------------- region

run "only_north_europe_is_accepted" {
  command = plan

  variables {
    location = "westeurope"
  }

  expect_failures = [var.location]
}

# ---------------------------------------------------------------- optional components

run "optional_component_has_no_identity_by_default" {
  command = plan

  variables {
    capabilities_dir           = "tests/fixtures/capabilities-optional"
    service_account_namespaces = { "db-migrate" = "ah-core", "demo" = "ah-demo" }
  }

  assert {
    condition     = toset(keys(module.workload_identity)) == toset(["db-migrate", "tool-lookup-account"])
    error_message = "A manifest marked optional must yield no identity or federated credential unless it is enabled."
  }

  assert {
    condition     = !contains(keys(module.workload_identity["db-migrate"].role_assignments), "kv-demo/Key Vault Secrets Officer")
    error_message = "db-migrate must not get Officer on the vault of a disabled optional component."
  }
}

run "optional_component_gets_its_identity_when_enabled" {
  command = plan

  variables {
    capabilities_dir           = "tests/fixtures/capabilities-optional"
    optional_components        = ["demo"]
    service_account_namespaces = { "db-migrate" = "ah-core", "demo" = "ah-demo" }
  }

  override_data {
    target = data.terraform_remote_state.base
    values = {
      outputs = {
        acr_id                     = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-base/providers/Microsoft.ContainerRegistry/registries/acrahtest"
        acr_login_server           = "acrahtest.azurecr.io"
        log_analytics_workspace_id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-base/providers/Microsoft.OperationalInsights/workspaces/log-assume-hijacked"
        key_vaults = {
          kv-db-migrate = {
            name = "kv-db-migrate-a1b2c3"
            id   = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-base/providers/Microsoft.KeyVault/vaults/kv-db-migrate-a1b2c3"
            uri  = "https://kv-db-migrate-a1b2c3.vault.azure.net/"
          }
          kv-tool-lookup-account = {
            name = "kv-tool-lookup-a-d4e5f6"
            id   = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-base/providers/Microsoft.KeyVault/vaults/kv-tool-lookup-a-d4e5f6"
            uri  = "https://kv-tool-lookup-a-d4e5f6.vault.azure.net/"
          }
          kv-demo = {
            name = "kv-demo-aabbcc"
            id   = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-base/providers/Microsoft.KeyVault/vaults/kv-demo-aabbcc"
            uri  = "https://kv-demo-aabbcc.vault.azure.net/"
          }
        }
      }
    }
  }

  assert {
    condition     = toset(keys(module.workload_identity)) == toset(["db-migrate", "tool-lookup-account", "demo"])
    error_message = "An enabled optional component gets its identity."
  }

  assert {
    condition     = module.workload_identity["demo"].subject == "system:serviceaccount:ah-demo:demo"
    error_message = "The enabled component's federated credential trusts exactly its ServiceAccount."
  }

  assert {
    condition     = toset(keys(module.workload_identity["demo"].role_assignments)) == toset(["kv-demo/Key Vault Secrets User"])
    error_message = "The enabled component gets Secrets User on its own vault and nothing else."
  }

  assert {
    condition     = contains(keys(module.workload_identity["db-migrate"].role_assignments), "kv-demo/Key Vault Secrets Officer")
    error_message = "db-migrate gets Officer on the vault of an enabled optional component with a database role."
  }
}

run "an_unknown_optional_component_is_refused" {
  command = plan

  variables {
    capabilities_dir    = "tests/fixtures/capabilities-optional"
    optional_components = ["dmeo"]
  }

  expect_failures = [terraform_data.manifest_checks]
}
