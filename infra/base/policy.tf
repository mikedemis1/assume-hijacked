# Azure Policy at subscription scope: guardrails for the resource layer.
# In-cluster rules are a different layer (ValidatingAdmissionPolicy, lane B).
#
# Built-in definitions are referenced by their fixed GUIDs (checked against
# github.com/Azure/azure-policy, built-in-policies/policyDefinitions):
#   e56962a6-4747-49cd-b67b-bf8b01975c4c  Allowed locations
#   e765b5de-1225-4ba3-bd56-1ac6695af988  Allowed locations for resource groups
#   5e1de0e3-42cb-4ebc-a86d-61d0c619ca48  Public network access should be disabled for PostgreSQL flexible servers
#   55615ac9-af46-4a59-874e-391cc3dfb490  Key Vault should have firewall enabled or public network access disabled
# The Key Vault policy is the "firewall enabled" one, not the "disable public network
# access" one, because our vaults use the service-endpoint pattern (public endpoint
# on, firewall deny, spoke subnets allowed).
#
# The Firewall SKU and VM size rules are custom: no built-in definition denies a SKU
# list, and the built-in VM size policy skips VM scale sets, which is what AKS uses.

locals {
  builtin_policy_ids = {
    allowed_locations    = "/providers/Microsoft.Authorization/policyDefinitions/e56962a6-4747-49cd-b67b-bf8b01975c4c"
    allowed_rg_locations = "/providers/Microsoft.Authorization/policyDefinitions/e765b5de-1225-4ba3-bd56-1ac6695af988"
    postgres_no_public   = "/providers/Microsoft.Authorization/policyDefinitions/5e1de0e3-42cb-4ebc-a86d-61d0c619ca48"
    keyvault_firewall    = "/providers/Microsoft.Authorization/policyDefinitions/55615ac9-af46-4a59-874e-391cc3dfb490"
  }
}

resource "azurerm_policy_definition" "deny_firewall_skus" {
  name         = "deny-firewall-standard-premium"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Deny Azure Firewall Standard and Premium"
  description  = "Only Azure Firewall Basic is allowed. Standard and Premium cost three to ten times more."

  metadata = jsonencode({ category = "Network" })

  policy_rule = jsonencode({
    if = {
      allOf = [
        { field = "type", equals = "Microsoft.Network/azureFirewalls" },
        { field = "Microsoft.Network/azureFirewalls/sku.tier", in = ["Standard", "Premium"] },
      ]
    }
    then = { effect = "deny" }
  })
}

resource "azurerm_policy_definition" "deny_vm_sizes" {
  name         = "deny-vm-sizes-outside-allowlist"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Deny VM and scale set sizes outside the allowlist"
  description  = "Virtual machines and VM scale sets (AKS nodes) may only use the listed sizes."

  metadata = jsonencode({ category = "Compute" })

  parameters = jsonencode({
    listOfAllowedSizes = {
      type     = "Array"
      metadata = { displayName = "Allowed VM sizes" }
    }
  })

  policy_rule = jsonencode({
    if = {
      anyOf = [
        {
          allOf = [
            { field = "type", equals = "Microsoft.Compute/virtualMachines" },
            { field = "Microsoft.Compute/virtualMachines/sku.name", notIn = "[parameters('listOfAllowedSizes')]" },
          ]
        },
        {
          allOf = [
            { field = "type", equals = "Microsoft.Compute/virtualMachineScaleSets" },
            { field = "Microsoft.Compute/virtualMachineScaleSets/sku.name", notIn = "[parameters('listOfAllowedSizes')]" },
          ]
        },
      ]
    }
    then = { effect = "deny" }
  })
}

resource "azurerm_subscription_policy_assignment" "allowed_locations" {
  name                 = "allowed-locations"
  display_name         = "Allowed locations"
  subscription_id      = local.subscription_scope
  policy_definition_id = local.builtin_policy_ids.allowed_locations

  parameters = jsonencode({
    listOfAllowedLocations = { value = var.allowed_locations }
  })
}

resource "azurerm_subscription_policy_assignment" "allowed_rg_locations" {
  name                 = "allowed-rg-locations"
  display_name         = "Allowed locations for resource groups"
  subscription_id      = local.subscription_scope
  policy_definition_id = local.builtin_policy_ids.allowed_rg_locations

  parameters = jsonencode({
    listOfAllowedLocations = { value = var.allowed_locations }
  })
}

resource "azurerm_subscription_policy_assignment" "deny_firewall_skus" {
  name                 = "deny-firewall-std-premium"
  display_name         = "Deny Azure Firewall Standard and Premium"
  subscription_id      = local.subscription_scope
  policy_definition_id = azurerm_policy_definition.deny_firewall_skus.id
}

resource "azurerm_subscription_policy_assignment" "deny_vm_sizes" {
  name                 = "deny-vm-sizes"
  display_name         = "Deny VM sizes outside the allowlist"
  subscription_id      = local.subscription_scope
  policy_definition_id = azurerm_policy_definition.deny_vm_sizes.id

  parameters = jsonencode({
    listOfAllowedSizes = { value = var.allowed_vm_sizes }
  })
}

resource "azurerm_subscription_policy_assignment" "postgres_no_public_access" {
  name                 = "postgres-no-public-access"
  display_name         = "PostgreSQL flexible servers: no public network access"
  subscription_id      = local.subscription_scope
  policy_definition_id = local.builtin_policy_ids.postgres_no_public

  parameters = jsonencode({
    effect = { value = "Deny" }
  })
}

resource "azurerm_subscription_policy_assignment" "keyvault_firewall_or_no_public_access" {
  name                 = "keyvault-firewall-or-no-public"
  display_name         = "Key Vault: firewall on or public access off"
  subscription_id      = local.subscription_scope
  policy_definition_id = local.builtin_policy_ids.keyvault_firewall

  parameters = jsonencode({
    effect = { value = "Deny" }
  })
}
