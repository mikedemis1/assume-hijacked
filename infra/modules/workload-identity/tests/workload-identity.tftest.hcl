# Plan-only tests with a mocked provider: nothing here reaches Azure or Entra.
# Run from infra/modules/workload-identity:  terraform init -backend=false && terraform test

mock_provider "azurerm" {}

# Computed values are unknown during plan; fixed values let the tests compare them.
override_resource {
  target          = azurerm_user_assigned_identity.this
  override_during = plan
  values = {
    id           = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-lab/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-tool-lookup-account"
    principal_id = "aaaaaaaa-0000-0000-0000-000000000001"
    client_id    = "bbbbbbbb-0000-0000-0000-000000000001"
  }
}

variables {
  name                = "id-tool-lookup-account"
  resource_group_name = "rg-lab"
  location            = "swedencentral"
  oidc_issuer_url     = "https://swedencentral.oic.prod-aks.azure.com/tenant/cluster/"
  namespace           = "ah-tools"
  service_account     = "tool-lookup-account"
  role_assignments = {
    "kv-tool-lookup-account/Key Vault Secrets User" = {
      role     = "Key Vault Secrets User"
      scope_id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-base/providers/Microsoft.KeyVault/vaults/kv-tool-lookup-a-abc123"
    }
  }
}

run "credential_trusts_exactly_one_service_account_of_one_issuer" {
  command = plan

  assert {
    condition     = azurerm_federated_identity_credential.this.subject == "system:serviceaccount:ah-tools:tool-lookup-account"
    error_message = "The subject must name exactly this namespace and ServiceAccount."
  }

  assert {
    condition     = azurerm_federated_identity_credential.this.issuer == var.oidc_issuer_url
    error_message = "The credential must trust only this cluster's OIDC issuer."
  }

  assert {
    condition     = length(azurerm_federated_identity_credential.this.audience) == 1 && azurerm_federated_identity_credential.this.audience[0] == "api://AzureADTokenExchange"
    error_message = "The audience must be exactly api://AzureADTokenExchange."
  }

  assert {
    condition     = azurerm_federated_identity_credential.this.user_assigned_identity_id == azurerm_user_assigned_identity.this.id
    error_message = "The credential must belong to this identity."
  }
}

run "roles_go_to_the_identity_at_the_given_scope" {
  command = plan

  assert {
    condition     = length(azurerm_role_assignment.this) == 1
    error_message = "One role assignment per entry."
  }

  assert {
    condition = alltrue([
      for k, a in azurerm_role_assignment.this :
      a.principal_id == azurerm_user_assigned_identity.this.principal_id
      && a.scope == var.role_assignments[k].scope_id
      && a.role_definition_name == "Key Vault Secrets User"
    ])
    error_message = "Each role must go to this identity, at the vault's resource ID."
  }
}

run "broad_roles_are_refused" {
  command = plan

  variables {
    role_assignments = {
      owner = {
        role     = "Owner"
        scope_id = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg-base"
      }
    }
  }

  expect_failures = [var.role_assignments]
}

run "logical_vault_name_as_scope_is_refused" {
  command = plan

  variables {
    role_assignments = {
      wrong = {
        role     = "Key Vault Secrets User"
        scope_id = "kv-tool-lookup-account"
      }
    }
  }

  expect_failures = [var.role_assignments]
}

run "namespace_must_be_a_dns_label" {
  command = plan

  variables {
    namespace = ""
  }

  expect_failures = [var.namespace]
}
