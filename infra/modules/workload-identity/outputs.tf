output "id" {
  description = "Resource ID of the identity."
  value       = azurerm_user_assigned_identity.this.id
}

output "name" {
  description = "Name of the identity."
  value       = azurerm_user_assigned_identity.this.name
}

output "client_id" {
  description = "Client ID (goes into the ServiceAccount annotation and the SecretProviderClass)."
  value       = azurerm_user_assigned_identity.this.client_id
}

output "principal_id" {
  description = "Object ID of the identity's service principal (role assignments, PostgreSQL Entra admin)."
  value       = azurerm_user_assigned_identity.this.principal_id
}

output "subject" {
  description = "Federated credential subject: the one ServiceAccount the identity trusts."
  value       = azurerm_federated_identity_credential.this.subject
}

output "role_assignments" {
  description = "Role assignments made for the identity: key -> {role, scope_id}."
  value = {
    for k, a in azurerm_role_assignment.this : k => {
      role     = a.role_definition_name
      scope_id = a.scope
    }
  }
}
