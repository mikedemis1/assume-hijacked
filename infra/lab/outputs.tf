# Values the Helm values file for env=azure needs (deploy/helm values-azure.yaml): azure.tenantId,
# azure.clientIds, azure.keyVaults, azure.dbAdmin, db.host. None of them is a secret.

output "cluster_name" {
  description = "AKS cluster name."
  value       = azurerm_kubernetes_cluster.this.name
}

output "oidc_issuer_url" {
  description = "Cluster OIDC issuer (trusted by every federated credential)."
  value       = azurerm_kubernetes_cluster.this.oidc_issuer_url
}

output "tenant_id" {
  description = "Helm azure.tenantId."
  value       = var.tenant_id
}

output "workload_client_ids" {
  description = "Helm azure.clientIds: component -> client ID of its workload identity."
  value       = { for c, m in module.workload_identity : c => m.client_id }
}

output "workload_identity_subjects" {
  description = "component -> the one ServiceAccount its identity trusts."
  value       = { for c, m in module.workload_identity : c => m.subject }
}

output "component_key_vaults" {
  description = "Helm azure.keyVaults: component -> physical name of its own vault (scope kv-<component>), for components that have one."
  value = {
    for c in keys(local.placed) : c => local.key_vaults["kv-${c}"].name
    if contains(keys(local.key_vaults), "kv-${c}")
  }
}

output "unassigned_azure_roles" {
  description = "Manifest roles this stack does not assign because their scope is not a Key Vault . Assign them where that resource lives."
  value       = [for r in local.non_vault_roles : "${r.component}: ${r.role} on ${r.scope}"]
}

output "postgres_host" {
  description = "Helm db.host: the server name. It resolves to the private endpoint inside the VNet."
  value       = azurerm_postgresql_flexible_server.this.fqdn
}

output "postgres_database" {
  description = "Application database created by Terraform."
  value       = azurerm_postgresql_flexible_server_database.supplier.name
}

output "postgres_entra_admin" {
  description = "Helm azure.dbAdmin: the Entra principal name db-migrate logs in as."
  value       = azurerm_postgresql_flexible_server_active_directory_administrator.db_migrate.principal_name
}

output "vnet_id" {
  description = "The lab VNet (AKS, private endpoints)."
  value       = azurerm_virtual_network.vnet.id
}

output "subnet_ids" {
  description = "Subnet IDs by name (snet-aks-system, snet-aks-sandbox, snet-pe)."
  value       = { for name, s in azurerm_subnet.subnet : name => s.id }
}

output "aks_subnet_ids" {
  description = "The two AKS subnets as a list: the value for infra/base `spoke_subnet_ids` (Key Vault firewall)."
  value       = [for n in local.aks_subnet_names : azurerm_subnet.subnet[n].id]
}

output "kubelet_identity_client_id" {
  description = "Kubelet identity (AcrPull on the registry)."
  value       = azurerm_user_assigned_identity.aks_kubelet.client_id
}
