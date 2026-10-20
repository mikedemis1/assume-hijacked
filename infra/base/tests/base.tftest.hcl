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

run "policy_denies_postgres_public_access" {
  command = plan

  assert {
    condition     = jsondecode(azurerm_subscription_policy_assignment.postgres_no_public_access.parameters).effect.value == "Deny"
    error_message = "PostgreSQL public access must be denied."
  }

  assert {
    condition     = endswith(azurerm_subscription_policy_assignment.postgres_no_public_access.policy_definition_id, "5e1de0e3-42cb-4ebc-a86d-61d0c619ca48")
    error_message = "Wrong built-in definition for the PostgreSQL rule."
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
  # TLS version and a private container are checked by Trivy (AZU-0011, AZU-0007) in the lint job.
  command = plan

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
    spoke_subnet_ids = ["/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-lab/providers/Microsoft.Network/virtualNetworks/vnet-assume-hijacked/subnets/snet-aks-system"]
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

run "physical_vault_names_are_valid_unique_and_published" {
  command = plan

  assert {
    condition = alltrue([
      for scope, n in azurerm_key_vault.workload :
      length(n.name) >= 3 && length(n.name) <= 24 && can(regex("^[a-z][a-z0-9]*(-[a-z0-9]+)*$", n.name)) && !strcontains(n.name, "--")
    ])
    error_message = "Vault names must be 3-24 characters, lowercase letters/digits/single hyphens, starting with a letter."
  }

  assert {
    condition     = startswith(azurerm_key_vault.workload["kv-tool-lookup-account"].name, "kv-tool-lookup-ac-") && length(azurerm_key_vault.workload["kv-tool-lookup-account"].name) == 24
    error_message = "Name must be the readable prefix (17 characters) plus a 6-character hash."
  }

  assert {
    condition     = length(distinct([for scope, n in azurerm_key_vault.workload : n.name])) == length(azurerm_key_vault.workload)
    error_message = "Two scopes must never share a physical name."
  }

  assert {
    condition     = toset(keys(output.key_vaults)) == toset(["kv-tool-gateway", "kv-tool-lookup-account"])
    error_message = "key_vaults output must be keyed by the logical scope name."
  }

  assert {
    condition     = alltrue([for scope, v in output.key_vaults : v.name == output.key_vault_names[scope]])
    error_message = "The key_vaults output and the name map must agree."
  }
}

run "awkward_and_long_scopes_still_give_valid_distinct_names" {
  command = plan

  variables {
    capabilities_dir = "tests/fixtures/capabilities-awkward-names"
  }

  assert {
    condition     = length(azurerm_key_vault.workload) == 4
    error_message = "Four scopes, four vaults."
  }

  assert {
    condition = alltrue([
      for scope, n in azurerm_key_vault.workload :
      length(n.name) >= 3 && length(n.name) <= 24 && can(regex("^[a-z][a-z0-9]*(-[a-z0-9]+)*$", n.name)) && !strcontains(n.name, "--")
    ])
    error_message = "Long scopes, doubled hyphens, underscores, dots and a trailing hyphen must all end as valid names."
  }

  # The two long scopes share their first 17 characters; only the hash tells them apart.
  assert {
    condition     = azurerm_key_vault.workload["kv-this-name-is-far-too-long-for-azure"].name != azurerm_key_vault.workload["kv-this-name-is-far-too-long-for-azure-too"].name
    error_message = "Scopes with the same prefix must still get different names."
  }

  assert {
    condition     = length(distinct([for scope, n in azurerm_key_vault.workload : n.name])) == 4
    error_message = "All four names must differ."
  }
}

run "vault_names_depend_on_the_subscription" {
  command = plan

  variables {
    subscription_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
  }

  # The same scope gets another name in another subscription (the name is a global
  # DNS name; two owners of this repository must not collide).
  assert {
    condition     = output.key_vault_names["kv-tool-gateway"] != "kv-tool-gateway-${substr(sha256("11111111-2222-3333-4444-555555555555/kv-tool-gateway"), 0, 6)}"
    error_message = "Another subscription must produce another hash."
  }
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
    condition     = azurerm_role_assignment.ci_apply_monitoring_base.role_definition_name == "Monitoring Contributor"
    error_message = "ci-apply needs Monitoring Contributor on rg-base (diagnostic settings on the vaults, alert rules on the workspace)."
  }
}

run "rg_lab_exists_as_an_empty_shell" {
  command = plan

  assert {
    condition     = azurerm_resource_group.lab.name == "rg-lab" && azurerm_resource_group.lab.location == "northeurope"
    error_message = "Base must create rg-lab in North Europe so ci-apply's grants survive a lab destroy."
  }
}

run "ci_apply_gets_contributor_on_lab_unconditionally" {
  command = plan

  assert {
    condition     = toset(keys(azurerm_role_assignment.ci_apply_contributor)) == toset(["lab"])
    error_message = "Contributor on rg-lab only."
  }

  assert {
    condition     = azurerm_role_assignment.ci_apply_contributor["lab"].scope == "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-lab"
    error_message = "The Contributor scope must be exactly rg-lab."
  }

  assert {
    condition     = alltrue([for k, r in azurerm_role_assignment.ci_apply_contributor : r.role_definition_name == "Contributor"])
    error_message = "The role on rg-lab must be Contributor."
  }
}

# Every RBAC-administrator grant of ci-apply (rg-lab, the registry, each vault)
# must carry the same version 2.0 condition. Deleting it would hand out unlimited
# role-assignment rights, so each grant is checked, not just one group of them.
run "every_ci_apply_rbac_admin_grant_is_conditioned_to_the_short_role_list" {
  command = plan

  assert {
    condition     = toset(concat(keys(azurerm_role_assignment.ci_apply_rbac_admin_lab), keys(azurerm_role_assignment.ci_apply_rbac_admin_base))) == toset(["lab", "acr", "kv-tool-gateway", "kv-tool-lookup-account"])
    error_message = "RBAC administrator is expected on rg-lab, the registry and each vault."
  }

  assert {
    condition = alltrue([
      for k, r in merge(azurerm_role_assignment.ci_apply_rbac_admin_lab, azurerm_role_assignment.ci_apply_rbac_admin_base) :
      r.role_definition_name == "Role Based Access Control Administrator" && r.condition_version == "2.0" && r.condition != null && r.condition != ""
    ])
    error_message = "Every role-assignment grant must carry a version 2.0 condition."
  }

  # Allowed: AcrPull, Key Vault Secrets User.
  assert {
    condition = alltrue([
      for k, r in merge(azurerm_role_assignment.ci_apply_rbac_admin_lab, azurerm_role_assignment.ci_apply_rbac_admin_base) :
      strcontains(r.condition, "7f951dda-4ed3-4680-a7ca-43fe172d538d") && strcontains(r.condition, "4633458b-17de-408a-b874-0445c86b69e6")
    ])
    error_message = "AcrPull and Key Vault Secrets User must be assignable."
  }

  # Checked on write and on delete.
  assert {
    condition = alltrue([
      for k, r in merge(azurerm_role_assignment.ci_apply_rbac_admin_lab, azurerm_role_assignment.ci_apply_rbac_admin_base) :
      strcontains(r.condition, "roleAssignments/write") && strcontains(r.condition, "roleAssignments/delete")
    ])
    error_message = "The condition must cover role assignment writes and deletes."
  }

  # Not allowed: Owner, Contributor, User Access Administrator, RBAC Administrator itself.
  assert {
    condition = alltrue([
      for k, r in merge(azurerm_role_assignment.ci_apply_rbac_admin_lab, azurerm_role_assignment.ci_apply_rbac_admin_base) :
      !strcontains(r.condition, "8e3af657-a8ff-443c-a75c-2fe8c4bcb635")
      && !strcontains(r.condition, "b24988ac-6180-42a0-ab88-20f7382dd24c")
      && !strcontains(r.condition, "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9")
      && !strcontains(r.condition, "f58310d9-a9f6-439a-9e8d-f62e7b41a168")
    ])
    error_message = "Owner, Contributor, User Access Administrator and RBAC Administrator must not be assignable."
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

# ---------------------------------------------------------------- optional components

run "optional_component_has_no_vault_by_default" {
  command = plan

  variables {
    capabilities_dir = "tests/fixtures/capabilities-optional"
  }

  assert {
    condition     = toset(keys(azurerm_key_vault.workload)) == toset(["kv-tool-lookup-account"])
    error_message = "A manifest marked optional must yield no vault unless it is enabled."
  }
}

run "optional_component_gets_a_vault_when_enabled" {
  command = plan

  variables {
    capabilities_dir    = "tests/fixtures/capabilities-optional"
    optional_components = ["demo"]
  }

  assert {
    condition     = toset(keys(azurerm_key_vault.workload)) == toset(["kv-tool-lookup-account", "kv-demo"])
    error_message = "An enabled optional component gets its vault."
  }
}
