# One Key Vault per workload that holds secrets (decision: D15).
#
# The list of vaults is not written here. It comes from the capability manifests
# (security/capabilities/*.json): every distinct `azure.roles[].scope` that starts
# with "kv-" is the LOGICAL name of a vault. A new secret-holding component
# therefore gets its vault by adding a manifest, not by editing Terraform.
#
# Vault names are global DNS names (<name>.vault.azure.net), so the physical name is
# derived from the logical one: a readable prefix plus a short hash of the
# subscription ID and the scope. The result is deterministic (same scope, same name,
# also after a rebuild), always 3-24 characters, lowercase letters, digits and single
# hyphens, and starts with a letter. The logical-to-physical map is published in the
# key_vaults output; infra/lab looks vaults up by logical name there.
#
# The role assignments that let each workload identity read its vault are made by
# infra/lab (the identities live in rg-lab). This file publishes the needed grants
# through the key_vault_grants output.

locals {
  capabilities_dir = coalesce(var.capabilities_dir, "${path.module}/../../security/capabilities")

  manifests = {
    for f in fileset(local.capabilities_dir, "*.json") :
    trimsuffix(f, ".json") => jsondecode(file("${local.capabilities_dir}/${f}"))
  }

  vault_grants = flatten([
    for key, m in local.manifests : [
      for r in try(m.azure.roles, []) : {
        vault     = r.scope
        role      = r.role
        identity  = m.azure.identity
        component = m.component
      } if startswith(r.scope, "kv-")
    ]
  ])

  key_vault_scopes = toset([for g in local.vault_grants : g.vault])

  # Prefix: lowercase, every run of other characters becomes one hyphen, hyphens trimmed
  # at both ends, at most 17 characters (24 minus hyphen minus 6 hash characters).
  # Trimming after the cut keeps the name free of "--" and of a trailing hyphen.
  key_vault_prefixes = {
    for s in local.key_vault_scopes :
    s => trim(substr(trim(replace(lower(s), "/[^a-z0-9]+/", "-"), "-"), 0, 17), "-")
  }

  key_vault_physical_names = {
    for s, p in local.key_vault_prefixes :
    s => "${p}-${substr(sha256("${var.subscription_id}/${s}"), 0, 6)}"
  }
}

resource "azurerm_key_vault" "workload" {
  #checkov:skip=CKV_AZURE_42: lab: no purge protection, so a vault name can be reused in the same week (see below)
  #checkov:skip=CKV_AZURE_110: lab: no purge protection, so a vault name can be reused in the same week (see below)
  #checkov:skip=CKV_AZURE_189: public endpoint behind the vault firewall (default Deny, spoke subnets only); no private endpoint per vault
  #checkov:skip=CKV2_AZURE_32: a private endpoint per workload vault costs money every month; the vault firewall is the wall in the lab
  for_each = local.key_vault_scopes

  name                = local.key_vault_physical_names[each.key]
  resource_group_name = azurerm_resource_group.base.name
  location            = azurerm_resource_group.base.location
  tenant_id           = var.tenant_id
  sku_name            = "standard"

  rbac_authorization_enabled = true # roles, not access policies; Secrets User at vault scope

  # Lab setting, on purpose: soft delete keeps the name for 7 days, but there is no
  # purge protection, so a vault can be purged and the name reused in the same week.
  # A production vault would set purge_protection_enabled = true (it cannot be undone).
  purge_protection_enabled   = false
  soft_delete_retention_days = 7

  # Service-endpoint pattern: the vault stays reachable on its public endpoint, but the
  # firewall denies everything except the spoke subnets (and any listed IP).
  # The "firewall enabled or public access disabled" built-in policy in policy.tf checks
  # exactly this.
  public_network_access_enabled = true

  network_acls {
    default_action             = "Deny"
    bypass                     = "None"
    virtual_network_subnet_ids = var.spoke_subnet_ids
    ip_rules                   = var.key_vault_allowed_ip_ranges
  }

  tags = merge(var.tags, { workload = each.key })

  lifecycle {
    precondition {
      condition     = can(regex("^[a-z][a-z0-9]*(-[a-z0-9]+)*$", local.key_vault_physical_names[each.key])) && length(local.key_vault_physical_names[each.key]) >= 3 && length(local.key_vault_physical_names[each.key]) <= 24
      error_message = "Derived vault name is not valid: 3-24 characters, lowercase letters, digits and single hyphens, starting with a letter."
    }

    precondition {
      condition     = length(distinct(values(local.key_vault_physical_names))) == length(local.key_vault_physical_names)
      error_message = "Two vault scopes map to the same physical name. Rename one scope in its capability manifest."
    }
  }
}
