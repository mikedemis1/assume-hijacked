# rg-lab: the part of the lab that is destroyed every night and rebuilt on demand.
#   main.tf        inputs: rg-lab, the base and net states, the capability manifests
#   identities.tf  workload identities (module) and the two AKS identities, with their roles
#   aks.tf         the cluster: system pool + Kata sandbox pool
#   postgres.tf    PostgreSQL flexible server behind a private endpoint
#   firewall.tf    Azure Firewall Basic, its policy and the route table (count = enable_firewall)
#   monitoring.tf  diagnostic settings, container log collection, log alert rules
#
# The resource group is created EMPTY by infra/base (ruling R15). This stack only reads it.
#
# How the lab gets the values of base and net
# -------------------------------------------
# terraform_remote_state on the same azurerm backend, not hand-copied IDs and not lookups by
# name. Reasons:
#   - The Key Vault physical names are derived (prefix + hash) in infra/base. Its key_vaults
#     output is the single source for scope -> {name, id, uri}; a by-name lookup would have to
#     repeat the hash rule.
#   - Nothing to copy by hand after each base/net apply, so nothing goes stale.
#   - ci-plan already has Storage Blob Data Reader on the state account (infra/base), so plan
#     on any branch can read it. Neither state holds a secret (by design, see postgres.tf).
#   - terraform test replaces both data sources with override_data, so the tests need no Azure.
# Cost of the choice: base and net must be applied (and their state migrated to the backend)
# before the lab can plan. That is the real order anyway.

data "azurerm_resource_group" "lab" {
  name = var.resource_group_name
}

data "terraform_remote_state" "base" {
  backend = "azurerm"

  config = {
    resource_group_name  = var.state_resource_group_name
    storage_account_name = var.state_storage_account_name
    container_name       = var.state_container_name
    key                  = var.base_state_key
    use_azuread_auth     = true
    subscription_id      = var.subscription_id
    tenant_id            = var.tenant_id
  }
}

data "terraform_remote_state" "net" {
  backend = "azurerm"

  config = {
    resource_group_name  = var.state_resource_group_name
    storage_account_name = var.state_storage_account_name
    container_name       = var.state_container_name
    key                  = var.net_state_key
    use_azuread_auth     = true
    subscription_id      = var.subscription_id
    tenant_id            = var.tenant_id
  }
}

locals {
  base = data.terraform_remote_state.base.outputs
  net  = data.terraform_remote_state.net.outputs

  # scope ("kv-tool-gateway") -> {name, id, uri}. Never use the scope itself as a vault name.
  key_vaults = local.base.key_vaults

  aks_subnet_names = ["snet-aks-system", "snet-aks-sandbox"]
  aks_subnet_ids   = { for n in local.aks_subnet_names : n => local.net.spoke_subnet_ids[n] }
  aks_prefixes     = { for n in local.aks_subnet_names : n => local.net.spoke_subnet_address_prefixes[n] }

  # ------------------------------------------------------------ capability manifests (R8)
  capabilities_dir = coalesce(var.capabilities_dir, "${path.module}/../../security/capabilities")

  manifests = {
    for f in fileset(local.capabilities_dir, "*.json") :
    trimsuffix(f, ".json") => jsondecode(file("${local.capabilities_dir}/${f}"))
  }

  # Components that use an Azure identity, keyed by component name.
  identity_manifests = {
    for k, m in local.manifests : m.component => m
    if try(m.azure.identity, null) != null && try(m.azure.identity, "") != ""
  }

  namespaces = {
    for c, m in local.identity_manifests : c => lookup(
      var.service_account_namespaces, c,
      startswith(c, "tool-") && c != "tool-gateway" ? "ah-tools" : null
    )
  }

  # Placed components get an identity; the others are reported by the check below.
  placed    = { for c, m in local.identity_manifests : c => m if local.namespaces[c] != null }
  unplaced  = sort([for c, ns in local.namespaces : c if ns == null])
  all_roles = flatten([for c, m in local.identity_manifests : [for r in try(m.azure.roles, []) : merge(r, { component = c })]])

  # ------------------------------------------------------------ Key Vault RBAC (ruling R18)
  #
  # The vault roles are DERIVED here, not copied from the manifests:
  #   - every workload identity: Key Vault Secrets User on its OWN vault (scope kv-<component>)
  #     and on no other vault;
  #   - the db-migrate identity (var.db_admin_component): Key Vault Secrets Officer on the vault
  #     of every component that has a database role. db-migrate generates each role's password
  #     on every deploy, runs ALTER ROLE ... PASSWORD and writes secret db-password-<role> into
  #     that vault.
  # The manifests may still list vault roles (lane A writes them); a listed role that the rule
  # above would not grant stops the plan (manifest_checks), so a manifest cannot widen access.
  own_vault = { for c in keys(local.placed) : c => "kv-${c}" }

  db_components = sort([
    for k, m in local.manifests : m.component
    if try(m.db.role, null) != null && m.component != var.db_admin_component
  ])
  missing_db_vaults = [for c in local.db_components : "kv-${c}" if !contains(keys(local.key_vaults), "kv-${c}")]

  vault_roles     = [for r in local.all_roles : r if startswith(r.scope, "kv-")]
  non_vault_roles = [for r in local.all_roles : r if !startswith(r.scope, "kv-")]

  # Manifest vault roles that break the rule: Officer for anyone but db-migrate, Secrets User on
  # a vault that is not the component's own, or any other vault role.
  vault_role_violations = [
    for r in local.vault_roles : "${r.component}: ${r.role} on ${r.scope}"
    if !(
      (r.role == "Key Vault Secrets User" && r.scope == "kv-${r.component}")
      || (r.role == "Key Vault Secrets Officer" && r.component == var.db_admin_component)
    )
  ]

  # Officer grants listed for db-migrate must stay inside the derived set.
  officer_scope_violations = [
    for r in local.vault_roles : "${r.component}: ${r.role} on ${r.scope}"
    if r.role == "Key Vault Secrets Officer" && r.component == var.db_admin_component && !contains([for c in local.db_components : "kv-${c}"], r.scope)
  ]

  identity_grants = {
    for c, m in local.placed : c => merge(
      contains(keys(local.key_vaults), local.own_vault[c]) ? {
        "${local.own_vault[c]}/Key Vault Secrets User" = {
          role     = "Key Vault Secrets User"
          scope_id = local.key_vaults[local.own_vault[c]].id
        }
      } : {},
      c == var.db_admin_component ? {
        for d in local.db_components : "kv-${d}/Key Vault Secrets Officer" => {
          role     = "Key Vault Secrets Officer"
          scope_id = local.key_vaults["kv-${d}"].id
        } if contains(keys(local.key_vaults), "kv-${d}")
      } : {},
    )
  }
}

# Plan-time checks on the manifests. A failure here names the manifest problem instead of
# letting a half-built identity set through.
resource "terraform_data" "manifest_checks" {
  input = sort(keys(local.placed))

  lifecycle {
    precondition {
      condition     = length(local.unplaced) == 0
      error_message = "No namespace is known for: ${join(", ", local.unplaced)}. Add them to service_account_namespaces."
    }

    precondition {
      condition     = length(local.missing_db_vaults) == 0
      error_message = "Components with a database role have no Key Vault in infra/base: ${join(", ", local.missing_db_vaults)}. Their manifests need a kv-<component> scope; apply infra/base first."
    }

    precondition {
      condition     = length(local.vault_role_violations) == 0
      error_message = "Vault roles outside the rule (Secrets User on the own vault; Secrets Officer only for ${var.db_admin_component}): ${join("; ", local.vault_role_violations)}."
    }

    precondition {
      condition     = length(local.officer_scope_violations) == 0
      error_message = "${var.db_admin_component} may hold Secrets Officer only on vaults of components with a database role: ${join("; ", local.officer_scope_violations)}."
    }

    precondition {
      condition     = contains(keys(local.placed), var.db_admin_component)
      error_message = "No manifest with an Azure identity for ${var.db_admin_component}: the PostgreSQL Entra administrator needs one."
    }
  }
}
