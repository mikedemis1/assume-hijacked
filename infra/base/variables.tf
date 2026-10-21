variable "subscription_id" {
  description = "Subscription that holds rg-base and receives the policies and budgets."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$", var.subscription_id))
    error_message = "subscription_id must be a GUID."
  }
}

variable "tenant_id" {
  description = "Entra tenant of the subscription."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$", var.tenant_id))
    error_message = "tenant_id must be a GUID."
  }
}

variable "location" {
  description = "Azure region for every resource. The design allows exactly one."
  type        = string
  default     = "swedencentral"

  validation {
    condition     = var.location == "swedencentral"
    error_message = "This build runs in Sweden Central only."
  }
}

variable "resource_group_name" {
  description = "Resource group that survives every destroy of rg-lab."
  type        = string
  default     = "rg-base"
}

variable "state_storage_account_name" {
  description = "Globally unique name of the Terraform state storage account (3-24 lowercase letters and digits)."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9]{3,24}$", var.state_storage_account_name))
    error_message = "Storage account names are 3-24 lowercase letters and digits."
  }
}

variable "state_container_name" {
  description = "Blob container for the state files."
  type        = string
  default     = "tfstate"
}

variable "acr_name" {
  description = "Globally unique container registry name (5-50 letters and digits)."
  type        = string

  validation {
    condition     = can(regex("^[a-zA-Z0-9]{5,50}$", var.acr_name))
    error_message = "Registry names are 5-50 letters and digits."
  }
}

variable "log_analytics_workspace_name" {
  description = "Name of the Log Analytics workspace (evidence and KQL alerts)."
  type        = string
  default     = "log-assume-hijacked"
}

variable "log_analytics_retention_days" {
  description = "Retention of the workspace in days."
  type        = number
  default     = 30
}

variable "log_analytics_daily_quota_gb" {
  description = "Daily ingestion cap in GB. Ingestion stops for the day when it is reached."
  type        = number
  default     = 0.5
}

variable "capabilities_dir" {
  description = "Directory with the capability manifests (one JSON file per component). Null means <repo>/permissions."
  type        = string
  default     = null
}

variable "optional_components" {
  description = "Components whose manifest says \"optional\": true get their vault, identity and federated credential only when listed here. Default: none."
  type        = list(string)
  default     = []
}

variable "spoke_subnet_ids" {
  description = "Subnets (with the Microsoft.KeyVault service endpoint) that may reach the vaults. Set after infra/lab has created its VNet (output aks_subnet_ids of infra/lab)."
  type        = list(string)
  default     = []
}

variable "key_vault_allowed_ip_ranges" {
  description = "Extra public IPs or CIDRs allowed through the vault firewalls (for example the owner's IP while testing)."
  type        = list(string)
  default     = []
}

variable "budget_start_date" {
  description = "First day of a month, RFC 3339. Budgets track from this month on."
  type        = string
  default     = "2026-10-01T00:00:00Z"

  validation {
    condition     = can(regex("^[0-9]{4}-[0-9]{2}-01T00:00:00Z$", var.budget_start_date))
    error_message = "budget_start_date must be the first of a month, like 2026-10-01T00:00:00Z."
  }
}

variable "budget_soft_amount" {
  description = "Early-warning monthly budget in the billing currency (EUR)."
  type        = number
  default     = 20
}

variable "budget_hard_amount" {
  description = "Upper monthly budget in the billing currency (EUR). Budgets alert only; they do not stop spending."
  type        = number
  default     = 50
}

variable "budget_notification_emails" {
  description = "Addresses that receive budget alerts. Kept out of the code on purpose."
  type        = list(string)

  validation {
    condition     = length(var.budget_notification_emails) > 0
    error_message = "At least one address is needed, or the budget alerts reach nobody."
  }
}

variable "allowed_vm_sizes" {
  description = "VM sizes the subscription may use (Azure Policy). AKS nodes are VM scale sets, so this covers them."
  type        = list(string)
  default     = ["Standard_D4als_v6"]
}

variable "lab_resource_group_name" {
  description = "Empty resource group created here for infra/lab, which references it by data source. A lab destroy removes its contents, never the group."
  type        = string
  default     = "rg-lab"
}

variable "gitlab_issuer" {
  description = "OIDC issuer of the GitLab instance."
  type        = string
  default     = "https://gitlab.com"
}

variable "gitlab_project_path" {
  description = "GitLab project that may use the CI identities."
  type        = string
  default     = "michail-demis/assume-hijacked"
}

variable "tags" {
  description = "Tags added to every taggable resource."
  type        = map(string)
  default = {
    project = "assume-hijacked"
    layer   = "base"
  }
}
