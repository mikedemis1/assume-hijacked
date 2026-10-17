output "resource_group_name" {
  description = "Name of rg-base."
  value       = azurerm_resource_group.base.name
}

output "state_storage_account_name" {
  description = "Storage account for the Terraform state (use in the backend block)."
  value       = azurerm_storage_account.state.name
}

output "state_container_name" {
  description = "Blob container for the state files."
  value       = azurerm_storage_container.state.name
}

output "acr_id" {
  description = "Resource ID of the container registry."
  value       = azurerm_container_registry.acr.id
}

output "acr_name" {
  description = "Container registry name."
  value       = azurerm_container_registry.acr.name
}

output "acr_login_server" {
  description = "Registry host name, for image references."
  value       = azurerm_container_registry.acr.login_server
}

output "log_analytics_workspace_id" {
  description = "Resource ID of the Log Analytics workspace (diagnostic settings in infra/lab point here)."
  value       = azurerm_log_analytics_workspace.evidence.id
}

output "key_vault_ids" {
  description = "Vault name to resource ID."
  value       = { for name, kv in azurerm_key_vault.workload : name => kv.id }
}

output "key_vault_uris" {
  description = "Vault name to data-plane URI."
  value       = { for name, kv in azurerm_key_vault.workload : name => kv.vault_uri }
}

output "key_vault_grants" {
  description = "Roles that infra/lab must assign: identity name, role, vault. Taken from the capability manifests."
  value       = local.vault_grants
}

output "tenant_id" {
  description = "Entra tenant ID (the CI jobs need it for login)."
  value       = var.tenant_id
}

output "ci_client_ids" {
  description = "Client IDs of the GitLab CI identities. Not secrets: they only work with a GitLab token."
  value = {
    ci_plan  = azuread_application_registration.ci_plan.client_id
    ci_push  = azuread_application_registration.ci_push.client_id
    ci_apply = azuread_application_registration.ci_apply.client_id
  }
}

output "budget_ids" {
  description = "Budget name to resource ID."
  value       = { for k, b in azurerm_consumption_budget_subscription.monthly : k => b.id }
}
