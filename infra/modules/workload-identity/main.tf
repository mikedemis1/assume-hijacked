# One workload identity: a user-assigned managed identity, one federated credential that
# trusts exactly one Kubernetes ServiceAccount of one cluster, and the identity's roles.
#
# No secret exists anywhere. The pod (or the Secrets Store CSI provider acting for it) shows
# Entra a projected ServiceAccount token signed by the cluster's OIDC issuer; Entra checks
# issuer, subject and audience against the credential below and returns an Azure token.
# Docs: learn.microsoft.com/azure/aks/workload-identity-overview

locals {
  # Fixed by Entra for workload identity federation.
  token_audience = "api://AzureADTokenExchange"
  subject        = "system:serviceaccount:${var.namespace}:${var.service_account}"
}

resource "azurerm_user_assigned_identity" "this" {
  name                = var.name
  resource_group_name = var.resource_group_name
  location            = var.location
  tags                = var.tags
}

resource "azurerm_federated_identity_credential" "this" {
  name                      = "fc-${var.namespace}-${var.service_account}"
  user_assigned_identity_id = azurerm_user_assigned_identity.this.id
  issuer                    = var.oidc_issuer_url
  subject                   = local.subject
  audience                  = [local.token_audience]
}

resource "azurerm_role_assignment" "this" {
  for_each = var.role_assignments

  scope                            = each.value.scope_id
  role_definition_name             = each.value.role
  principal_id                     = azurerm_user_assigned_identity.this.principal_id
  principal_type                   = "ServicePrincipal"
  skip_service_principal_aad_check = true # a new identity may not have replicated in Entra yet
}
