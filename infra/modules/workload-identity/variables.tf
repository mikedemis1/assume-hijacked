variable "name" {
  description = "Name of the user-assigned managed identity (the `azure.identity` of the capability manifest)."
  type        = string

  validation {
    condition     = can(regex("^[a-zA-Z0-9][a-zA-Z0-9_-]{2,127}$", var.name))
    error_message = "Identity names are 3-128 letters, digits, hyphens and underscores, starting with a letter or digit."
  }
}

variable "resource_group_name" {
  description = "Resource group of the identity (rg-lab)."
  type        = string
}

variable "location" {
  description = "Region of the identity."
  type        = string
}

variable "oidc_issuer_url" {
  description = "OIDC issuer of the AKS cluster. Entra trusts tokens from this issuer only."
  type        = string
}

variable "namespace" {
  description = "Kubernetes namespace of the ServiceAccount."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$", var.namespace))
    error_message = "namespace must be a Kubernetes DNS label."
  }
}

variable "service_account" {
  description = "Kubernetes ServiceAccount that may use the identity (the `k8s.service_account` of the manifest)."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$", var.service_account))
    error_message = "service_account must be a Kubernetes object name."
  }
}

variable "role_assignments" {
  description = "Azure roles for the identity: map of a stable key to {role, scope_id}. scope_id is a resource ID (for example a Key Vault ID from the infra/base key_vaults output), never a logical name."
  type = map(object({
    role     = string
    scope_id = string
  }))
  default = {}

  # Only the data-plane vault roles. They are also the only vault roles ci-apply may hand out
  # (condition in infra/base/ci-identities.tf). Anything broader is refused here, at plan time.
  validation {
    condition     = alltrue([for a in values(var.role_assignments) : contains(["Key Vault Secrets User", "Key Vault Secrets Officer"], a.role)])
    error_message = "Only \"Key Vault Secrets User\" and \"Key Vault Secrets Officer\" may be assigned to a workload identity."
  }

  validation {
    condition     = alltrue([for a in values(var.role_assignments) : startswith(a.scope_id, "/subscriptions/")])
    error_message = "scope_id must be a full Azure resource ID, not a logical vault name."
  }
}

variable "tags" {
  description = "Tags for the identity."
  type        = map(string)
  default     = {}
}
