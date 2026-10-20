# Azure Policy at subscription scope: two guardrails for the resource layer.
# In-cluster rules are a different layer (ValidatingAdmissionPolicy, in the Helm chart).
#
#   - PostgreSQL flexible servers: no public network access (built-in definition
#     5e1de0e3-42cb-4ebc-a86d-61d0c619ca48, checked against github.com/Azure/azure-policy,
#     built-in-policies/policyDefinitions).
#   - VM and scale set sizes: only var.allowed_vm_sizes. Custom definition: the built-in VM
#     size policy skips VM scale sets, which is what AKS uses.

locals {
  builtin_policy_ids = {
    postgres_no_public = "/providers/Microsoft.Authorization/policyDefinitions/5e1de0e3-42cb-4ebc-a86d-61d0c619ca48"
  }
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
    "if" = {
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
