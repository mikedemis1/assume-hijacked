# Three Entra identities for GitLab CI. No client secret exists for any of them:
# GitLab presents a short-lived OIDC token, Entra checks it against a federated
# credential, and hands back an Azure token.
#
#   ci-plan   any branch   Reader on the subscription, read on the state blob
#   ci-push   main         AcrPush on the registry
#   ci-apply  main         Contributor on rg-lab and rg-net, plus a role-assignment
#                          right that can only hand out a short list of roles
#
# GitLab subject format: project_path:<group>/<project>:ref_type:<branch|tag>:ref:<name>

locals {
  gitlab_subject_prefix = "project_path:${var.gitlab_project_path}"
  gitlab_main_subject   = "${local.gitlab_subject_prefix}:ref_type:branch:ref:main"
  entra_token_audience  = "api://AzureADTokenExchange"

  # Built-in role definition IDs (checked in the Azure built-in roles reference).
  role_ids = {
    acr_pull                  = "7f951dda-4ed3-4680-a7ca-43fe172d538d"
    key_vault_secrets_user    = "4633458b-17de-408a-b874-0445c86b69e6"
    key_vault_secrets_officer = "b86a8fe4-44ce-4948-aee5-eccb2c155cd7"
    network_contributor       = "4d97b98b-1d4f-4787-a291-c67834d212e7"
    monitoring_metrics_pub    = "3913510d-42f4-4e42-8a64-420c390055eb"
    managed_identity_operator = "f1a07417-d97a-45cb-824c-7a7467783830"
  }

  # The only roles ci-apply may assign or remove. Everything else (Owner, Contributor,
  # Role Based Access Control Administrator itself, ...) is refused by the condition.
  ci_apply_assignable_role_ids = [
    local.role_ids.acr_pull,
    local.role_ids.key_vault_secrets_user,
    local.role_ids.key_vault_secrets_officer,
    local.role_ids.network_contributor,
    local.role_ids.monitoring_metrics_pub,
    local.role_ids.managed_identity_operator,
  ]

  # ABAC condition (version 2.0), format from "Delegate Azure role assignment
  # management with conditions": writes are checked on the requested role,
  # deletes on the role of the existing assignment.
  ci_apply_assignable_guids = join(", ", local.ci_apply_assignable_role_ids)
  ci_apply_rbac_condition = join(" ", [
    "((!(ActionMatches{'Microsoft.Authorization/roleAssignments/write'}))",
    "OR (@Request[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals {${local.ci_apply_assignable_guids}}))",
    "AND ((!(ActionMatches{'Microsoft.Authorization/roleAssignments/delete'}))",
    "OR (@Resource[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals {${local.ci_apply_assignable_guids}}))",
  ])

  lab_scopes = var.grant_ci_apply_on_lab_and_net ? {
    lab = "${local.subscription_scope}/resourceGroups/${var.lab_resource_group_name}"
    net = "${local.subscription_scope}/resourceGroups/${var.net_resource_group_name}"
  } : {}

  # Scopes in rg-base where infra/lab must create role assignments (AcrPull for the
  # kubelet, Secrets User for workload identities). Contributor cannot do that.
  base_rbac_scopes = merge(
    { acr = azurerm_container_registry.acr.id },
    { for name, kv in azurerm_key_vault.workload : name => kv.id },
  )
}

# ---------------------------------------------------------------- applications

resource "azuread_application_registration" "ci_plan" {
  display_name     = "ci-plan"
  description      = "GitLab CI: terraform plan on any branch (read only)."
  sign_in_audience = "AzureADMyOrg"
}

resource "azuread_application_registration" "ci_push" {
  display_name     = "ci-push"
  description      = "GitLab CI: push signed images to the registry from main."
  sign_in_audience = "AzureADMyOrg"
}

resource "azuread_application_registration" "ci_apply" {
  display_name     = "ci-apply"
  description      = "GitLab CI: terraform apply from main (manual job)."
  sign_in_audience = "AzureADMyOrg"
}

resource "azuread_service_principal" "ci_plan" {
  client_id = azuread_application_registration.ci_plan.client_id
}

resource "azuread_service_principal" "ci_push" {
  client_id = azuread_application_registration.ci_push.client_id
}

resource "azuread_service_principal" "ci_apply" {
  client_id = azuread_application_registration.ci_apply.client_id
}

# ---------------------------------------------------------------- federated credentials

# Any branch of the project. Entra does not allow a wildcard in a normal federated
# credential, so this one is a flexible credential with a claims expression.
resource "azuread_application_flexible_federated_identity_credential" "ci_plan_any_branch" {
  application_id             = azuread_application_registration.ci_plan.id
  display_name               = "gitlab-any-branch"
  description                = "GitLab pipelines of ${var.gitlab_project_path} on any branch"
  audience                   = local.entra_token_audience
  issuer                     = var.gitlab_issuer
  claims_matching_expression = "claims['sub'] matches '${local.gitlab_subject_prefix}:ref_type:branch:ref:*'"
}

resource "azuread_application_federated_identity_credential" "ci_push_main" {
  application_id = azuread_application_registration.ci_push.id
  display_name   = "gitlab-main"
  description    = "GitLab pipelines of ${var.gitlab_project_path} on main"
  audiences      = [local.entra_token_audience]
  issuer         = var.gitlab_issuer
  subject        = local.gitlab_main_subject
}

resource "azuread_application_federated_identity_credential" "ci_apply_main" {
  application_id = azuread_application_registration.ci_apply.id
  display_name   = "gitlab-main"
  description    = "GitLab pipelines of ${var.gitlab_project_path} on main"
  audiences      = [local.entra_token_audience]
  issuer         = var.gitlab_issuer
  subject        = local.gitlab_main_subject
}

# ---------------------------------------------------------------- ci-plan: read only

resource "azurerm_role_assignment" "ci_plan_reader" {
  scope                            = local.subscription_scope
  role_definition_name             = "Reader"
  principal_id                     = azuread_service_principal.ci_plan.object_id
  principal_type                   = "ServicePrincipal"
  skip_service_principal_aad_check = true
}

# Read the state. Plan jobs must run with -lock=false: this role cannot write the lease.
resource "azurerm_role_assignment" "ci_plan_state_reader" {
  scope                            = azurerm_storage_account.state.id
  role_definition_name             = "Storage Blob Data Reader"
  principal_id                     = azuread_service_principal.ci_plan.object_id
  principal_type                   = "ServicePrincipal"
  skip_service_principal_aad_check = true
}

# ---------------------------------------------------------------- ci-push

resource "azurerm_role_assignment" "ci_push_acr" {
  scope                            = azurerm_container_registry.acr.id
  role_definition_name             = "AcrPush"
  principal_id                     = azuread_service_principal.ci_push.object_id
  principal_type                   = "ServicePrincipal"
  skip_service_principal_aad_check = true
}

# ---------------------------------------------------------------- ci-apply

resource "azurerm_role_assignment" "ci_apply_state" {
  scope                            = azurerm_storage_account.state.id
  role_definition_name             = "Storage Blob Data Contributor"
  principal_id                     = azuread_service_principal.ci_apply.object_id
  principal_type                   = "ServicePrincipal"
  skip_service_principal_aad_check = true
}

resource "azurerm_role_assignment" "ci_apply_contributor" {
  for_each = local.lab_scopes

  scope                            = each.value
  role_definition_name             = "Contributor"
  principal_id                     = azuread_service_principal.ci_apply.object_id
  principal_type                   = "ServicePrincipal"
  skip_service_principal_aad_check = true
}

# Role assignment rights, limited by the condition to the short role list above.
resource "azurerm_role_assignment" "ci_apply_rbac_admin_lab" {
  for_each = local.lab_scopes

  scope                            = each.value
  role_definition_name             = "Role Based Access Control Administrator"
  principal_id                     = azuread_service_principal.ci_apply.object_id
  principal_type                   = "ServicePrincipal"
  skip_service_principal_aad_check = true
  condition_version                = "2.0"
  condition                        = local.ci_apply_rbac_condition
}

resource "azurerm_role_assignment" "ci_apply_rbac_admin_base" {
  for_each = local.base_rbac_scopes

  scope                            = each.value
  role_definition_name             = "Role Based Access Control Administrator"
  principal_id                     = azuread_service_principal.ci_apply.object_id
  principal_type                   = "ServicePrincipal"
  skip_service_principal_aad_check = true
  condition_version                = "2.0"
  condition                        = local.ci_apply_rbac_condition
}
