# One Key Vault per workload that holds secrets (decision: D15).
#
# The list of vaults is not written here. It comes from the capability manifests
# (security/capabilities/*.json): every distinct `azure.roles[].scope` that starts
# with "kv-" becomes a vault with exactly that name. A new secret-holding component
# therefore gets its vault by adding a manifest, not by editing Terraform.
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

  key_vault_names = toset([for g in local.vault_grants : g.vault])
}

resource "azurerm_key_vault" "workload" {
  for_each = local.key_vault_names

  name                = each.key
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
  # The "firewall enabled" built-in policy in policy.tf checks exactly this.
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
      condition     = length(each.key) >= 3 && length(each.key) <= 24 && can(regex("^[a-zA-Z][a-zA-Z0-9-]*[a-zA-Z0-9]$", each.key))
      error_message = "Key Vault names are 3-24 characters: letters, digits and hyphens, starting with a letter. Fix the scope in the capability manifest."
    }
  }
}
