# Plan-only tests with mocked providers: nothing here reaches Azure or Entra.
# Run from infra/base:  terraform init -backend=false && terraform test

mock_provider "azurerm" {}
mock_provider "azuread" {}

variables {
  subscription_id            = "11111111-2222-3333-4444-555555555555"
  tenant_id                  = "66666666-7777-8888-9999-000000000000"
  state_storage_account_name = "stahtestexample01"
  acr_name                   = "acrahtestexample"
  budget_notification_emails = ["owner@example.com"]
  capabilities_dir           = "tests/fixtures/capabilities"
}

# ---------------------------------------------------------------- budgets

run "budgets_have_the_agreed_amounts" {
  command = plan

  assert {
    condition     = azurerm_consumption_budget_subscription.monthly["soft"].amount == 20
    error_message = "The early-warning budget must be 20."
  }

  assert {
    condition     = azurerm_consumption_budget_subscription.monthly["hard"].amount == 50
    error_message = "The upper budget must be 50."
  }

  assert {
    condition     = azurerm_consumption_budget_subscription.monthly["soft"].time_grain == "Monthly"
    error_message = "Budgets must reset monthly."
  }
}

run "budgets_notify_on_actual_and_forecast" {
  command = plan

  assert {
    condition = alltrue([
      for k, b in azurerm_consumption_budget_subscription.monthly :
      length([for n in b.notification : n if n.threshold_type == "Actual"]) >= 1
      && length([for n in b.notification : n if n.threshold_type == "Forecasted"]) >= 1
    ])
    error_message = "Every budget needs at least one Actual and one Forecasted notification."
  }

  assert {
    condition = alltrue([
      for k, b in azurerm_consumption_budget_subscription.monthly :
      alltrue([for n in b.notification : contains(n.contact_emails, "owner@example.com")])
    ])
    error_message = "Notifications must go to the address from the variable."
  }
}

run "budget_without_recipient_is_refused" {
  command = plan

  variables {
    budget_notification_emails = []
  }

  expect_failures = [var.budget_notification_emails]
}

# ---------------------------------------------------------------- policy

run "policy_allows_only_north_europe" {
  command = plan

  assert {
    condition     = jsondecode(azurerm_subscription_policy_assignment.allowed_locations.parameters).listOfAllowedLocations.value == ["northeurope"]
    error_message = "Allowed locations must be exactly northeurope."
  }

  assert {
    condition     = jsondecode(azurerm_subscription_policy_assignment.allowed_rg_locations.parameters).listOfAllowedLocations.value == ["northeurope"]
    error_message = "Resource groups must be limited to northeurope as well."
  }
}

run "policy_denies_firewall_standard_and_premium" {
  command = plan

  assert {
    condition = (
      jsondecode(azurerm_policy_definition.deny_firewall_skus.policy_rule).then.effect == "deny"
      && contains(jsondecode(azurerm_policy_definition.deny_firewall_skus.policy_rule).if.allOf[1].in, "Standard")
      && contains(jsondecode(azurerm_policy_definition.deny_firewall_skus.policy_rule).if.allOf[1].in, "Premium")
    )
    error_message = "The firewall rule must deny Standard and Premium."
  }
}

run "policy_denies_vm_sizes_outside_allowlist" {
  command = plan

  assert {
    condition     = jsondecode(azurerm_subscription_policy_assignment.deny_vm_sizes.parameters).listOfAllowedSizes.value == ["Standard_D4als_v6"]
    error_message = "Only the AKS node size may be allowed by default."
  }

  assert {
    condition     = jsondecode(azurerm_policy_definition.deny_vm_sizes.policy_rule).then.effect == "deny"
    error_message = "VM sizes outside the list must be denied, not audited."
  }
}

run "policy_denies_public_access_for_postgres_and_key_vault" {
  command = plan

  assert {
    condition     = jsondecode(azurerm_subscription_policy_assignment.postgres_no_public_access.parameters).effect.value == "Deny"
    error_message = "PostgreSQL public access must be denied."
  }

  assert {
    condition     = jsondecode(azurerm_subscription_policy_assignment.keyvault_no_public_access.parameters).effect.value == "Deny"
    error_message = "Key Vault public access must be denied."
  }
}

# ---------------------------------------------------------------- registry, storage, logs

run "registry_is_basic_with_admin_off" {
  command = plan

  assert {
    condition     = azurerm_container_registry.acr.admin_enabled == false
    error_message = "ACR admin user must be disabled."
  }

  assert {
    condition     = azurerm_container_registry.acr.sku == "Basic"
    error_message = "ACR must be the Basic SKU."
  }
}

run "state_storage_is_locked_down" {
  command = plan

  assert {
    condition     = azurerm_storage_account.state.min_tls_version == "TLS1_2"
    error_message = "TLS 1.2 minimum."
  }

  assert {
    condition     = azurerm_storage_account.state.allow_nested_items_to_be_public == false
    error_message = "No public blob access."
  }

  assert {
    condition     = azurerm_storage_account.state.shared_access_key_enabled == false
    error_message = "Shared keys must be off; access is Entra only."
  }

  assert {
    condition     = azurerm_storage_account.state.default_to_oauth_authentication == true
    error_message = "OAuth must be the default authentication."
  }

  assert {
    condition     = azurerm_storage_container.state.container_access_type == "private"
    error_message = "The state container must be private."
  }
}

run "log_analytics_has_retention_and_daily_cap" {
  command = plan

  assert {
    condition     = azurerm_log_analytics_workspace.evidence.retention_in_days == 30
    error_message = "Retention must be 30 days."
  }

  assert {
    condition     = azurerm_log_analytics_workspace.evidence.daily_quota_gb == 0.5
    error_message = "The daily cap must be 0.5 GB."
  }
}

# ---------------------------------------------------------------- key vaults from manifests

run "one_vault_per_kv_scope_in_the_manifests" {
  command = plan

  assert {
    condition     = toset(keys(azurerm_key_vault.workload)) == toset(["kv-tool-gateway", "kv-tool-lookup-account"])
    error_message = "Expected one vault per distinct kv- scope: two vaults, not one per manifest and not one per grant."
  }

  assert {
    condition     = length(output.key_vault_grants) == 4
    error_message = "Expected four grants (two Secrets User, two Secrets Officer)."
  }
}

run "vaults_use_rbac_and_deny_by_default" {
  command = plan

  variables {
    spoke_subnet_ids = ["/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet-spoke/subnets/snet-aks"]
  }

  assert {
    condition     = alltrue([for k, v in azurerm_key_vault.workload : v.rbac_authorization_enabled == true])
    error_message = "Every vault must use Azure RBAC, not access policies."
  }

  assert {
    condition     = alltrue([for k, v in azurerm_key_vault.workload : v.network_acls[0].default_action == "Deny"])
    error_message = "Every vault firewall must default to Deny."
  }

  assert {
    condition = alltrue([
      for k, v in azurerm_key_vault.workload :
      length(v.network_acls[0].virtual_network_subnet_ids) == 1 && v.network_acls[0].bypass == "None"
    ])
    error_message = "Only the spoke subnet may pass, and no trusted-service bypass."
  }

  assert {
    condition     = alltrue([for k, v in azurerm_key_vault.workload : v.purge_protection_enabled == false])
    error_message = "Lab vaults run without purge protection (documented choice)."
  }
}

run "no_manifests_means_no_vaults" {
  command = plan

  variables {
    capabilities_dir = "tests/fixtures/empty"
  }

  assert {
    condition     = length(azurerm_key_vault.workload) == 0
    error_message = "Without manifests there must be no vaults."
  }
}

run "vault_name_longer_than_24_characters_is_refused" {
  command = plan

  variables {
    capabilities_dir = "tests/fixtures/capabilities-bad-name"
  }

  expect_failures = [azurerm_key_vault.workload]
}

# ---------------------------------------------------------------- CI identities

run "ci_credentials_are_bound_to_the_gitlab_project" {
  command = plan

  assert {
    condition     = azuread_application_federated_identity_credential.ci_apply_main.issuer == "https://gitlab.com"
    error_message = "ci-apply must trust gitlab.com."
  }

  assert {
    condition     = azuread_application_federated_identity_credential.ci_apply_main.subject == "project_path:michail-demis/assume-hijacked:ref_type:branch:ref:main"
    error_message = "ci-apply must be limited to the main branch of the project."
  }

  assert {
    condition     = azuread_application_federated_identity_credential.ci_push_main.subject == "project_path:michail-demis/assume-hijacked:ref_type:branch:ref:main"
    error_message = "ci-push must be limited to the main branch of the project."
  }

  assert {
    condition     = strcontains(azuread_application_flexible_federated_identity_credential.ci_plan_any_branch.claims_matching_expression, "project_path:michail-demis/assume-hijacked:ref_type:branch:ref:*")
    error_message = "ci-plan must match any branch of this project only."
  }

  assert {
    condition     = azuread_application_flexible_federated_identity_credential.ci_plan_any_branch.issuer == "https://gitlab.com"
    error_message = "ci-plan must trust gitlab.com."
  }
}

run "ci_roles_are_least_privilege" {
  command = plan

  assert {
    condition     = azurerm_role_assignment.ci_plan_reader.role_definition_name == "Reader"
    error_message = "ci-plan must be Reader."
  }

  assert {
    condition     = azurerm_role_assignment.ci_push_acr.role_definition_name == "AcrPush"
    error_message = "ci-push must be AcrPush."
  }

  assert {
    condition     = length(azurerm_role_assignment.ci_apply_contributor) == 0
    error_message = "ci-apply gets no Contributor until rg-lab and rg-net exist."
  }
}

run "ci_apply_can_assign_only_listed_roles" {
  command = plan

  variables {
    grant_ci_apply_on_lab_and_net = true
  }

  assert {
    condition     = toset(keys(azurerm_role_assignment.ci_apply_contributor)) == toset(["lab", "net"])
    error_message = "Contributor on rg-lab and rg-net."
  }

  assert {
    condition     = alltrue([for k, r in azurerm_role_assignment.ci_apply_contributor : endswith(r.scope, "/resourceGroups/rg-lab") || endswith(r.scope, "/resourceGroups/rg-net")])
    error_message = "Contributor scopes must be exactly the two resource groups."
  }

  assert {
    condition     = alltrue([for k, r in azurerm_role_assignment.ci_apply_rbac_admin_lab : r.role_definition_name == "Role Based Access Control Administrator" && r.condition_version == "2.0"])
    error_message = "Role assignment rights must carry a version 2.0 condition."
  }

  # Allowed: AcrPull and Key Vault Secrets User.
  assert {
    condition = alltrue([
      for k, r in azurerm_role_assignment.ci_apply_rbac_admin_lab :
      strcontains(r.condition, "7f951dda-4ed3-4680-a7ca-43fe172d538d") && strcontains(r.condition, "4633458b-17de-408a-b874-0445c86b69e6")
    ])
    error_message = "AcrPull and Key Vault Secrets User must be assignable."
  }

  # Not allowed: Owner, Contributor, User Access Administrator, RBAC Administrator itself.
  assert {
    condition = alltrue([
      for k, r in azurerm_role_assignment.ci_apply_rbac_admin_lab :
      !strcontains(r.condition, "8e3af657-a8ff-443c-a75c-2fe8c4bcb635")
      && !strcontains(r.condition, "b24988ac-6180-42a0-ab88-20f7382dd24c")
      && !strcontains(r.condition, "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9")
      && !strcontains(r.condition, "f58310d9-a9f6-439a-9e8d-f62e7b41a168")
    ])
    error_message = "Owner, Contributor, User Access Administrator and RBAC Administrator must not be assignable."
  }

  assert {
    condition     = toset(keys(azurerm_role_assignment.ci_apply_rbac_admin_base)) == toset(["acr", "kv-tool-gateway", "kv-tool-lookup-account"])
    error_message = "Constrained role-assignment rights are also needed on the registry and each vault."
  }
}

# ---------------------------------------------------------------- inputs

run "other_regions_are_refused" {
  command = plan

  variables {
    location = "westeurope"
  }

  expect_failures = [var.location]
}
