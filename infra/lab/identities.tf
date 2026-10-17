# Identities.
#
# 1. One workload identity per capability manifest with `azure.identity` (module
#    ../modules/workload-identity): a user-assigned identity in rg-lab, a federated credential
#    for exactly its ServiceAccount, and its Key Vault roles at the physical vault IDs from
#    infra/base. Roles whose scope is not a vault (for example Foundry) are not assigned here;
#    they are listed in the unassigned_azure_roles output.
# 2. Two cluster identities: the control plane and the kubelet. User-assigned, so their roles
#    exist BEFORE the cluster is created (route table, subnets, registry), and they survive a
#    cluster rebuild without new role assignments being needed in rg-base and rg-net.
#
# Every role handed out here is on ci-apply's allowlist (condition in
# infra/base/ci-identities.tf): Key Vault Secrets User/Officer, AcrPull, Network
# Contributor, Managed Identity Operator, Monitoring Metrics Publisher.

module "workload_identity" {
  source   = "../modules/workload-identity"
  for_each = local.placed

  name                = each.value.azure.identity
  resource_group_name = data.azurerm_resource_group.lab.name
  location            = var.location
  oidc_issuer_url     = azurerm_kubernetes_cluster.this.oidc_issuer_url
  namespace           = local.namespaces[each.key]
  service_account     = each.value.k8s.service_account
  role_assignments    = local.identity_grants[each.key]
  tags                = merge(var.tags, { component = each.key })
}

# ---------------------------------------------------------------- cluster identities

resource "azurerm_user_assigned_identity" "aks_control_plane" {
  name                = "id-aks-control-plane"
  resource_group_name = data.azurerm_resource_group.lab.name
  location            = var.location
  tags                = var.tags
}

resource "azurerm_user_assigned_identity" "aks_kubelet" {
  name                = "id-aks-kubelet"
  resource_group_name = data.azurerm_resource_group.lab.name
  location            = var.location
  tags                = var.tags
}

# The control plane assigns the kubelet identity to the node VMs.
resource "azurerm_role_assignment" "aks_control_plane_kubelet_operator" {
  scope                            = azurerm_user_assigned_identity.aks_kubelet.id
  role_definition_name             = "Managed Identity Operator"
  principal_id                     = azurerm_user_assigned_identity.aks_control_plane.principal_id
  principal_type                   = "ServicePrincipal"
  skip_service_principal_aad_check = true
}

# Bring-your-own subnets (rg-net): the control plane joins nodes and load balancers to them.
resource "azurerm_role_assignment" "aks_control_plane_subnets" {
  for_each = local.aks_subnet_ids

  scope                            = each.value
  role_definition_name             = "Network Contributor"
  principal_id                     = azurerm_user_assigned_identity.aks_control_plane.principal_id
  principal_type                   = "ServicePrincipal"
  skip_service_principal_aad_check = true
}

# With userDefinedRouting AKS checks, and may update, the route table on its subnets.
resource "azurerm_role_assignment" "aks_control_plane_route_table" {
  count = var.enable_firewall ? 1 : 0

  scope                            = azurerm_route_table.aks[0].id
  role_definition_name             = "Network Contributor"
  principal_id                     = azurerm_user_assigned_identity.aks_control_plane.principal_id
  principal_type                   = "ServicePrincipal"
  skip_service_principal_aad_check = true
}

# Nodes pull images from the registry in rg-base with the kubelet identity; no pull secret.
resource "azurerm_role_assignment" "aks_kubelet_acr_pull" {
  scope                            = local.base.acr_id
  role_definition_name             = "AcrPull"
  principal_id                     = azurerm_user_assigned_identity.aks_kubelet.principal_id
  principal_type                   = "ServicePrincipal"
  skip_service_principal_aad_check = true
}
