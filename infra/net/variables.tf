variable "subscription_id" {
  description = "Subscription that holds rg-net."
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
  default     = "northeurope"

  validation {
    condition     = var.location == "northeurope"
    error_message = "This build runs in North Europe only (decision 1)."
  }
}

variable "resource_group_name" {
  description = "Resource group for the network. Created EMPTY by infra/base (R15); this stack only reads it."
  type        = string
  default     = "rg-net"
}

variable "hub_address_space" {
  description = "Hub VNet address space. Must be a /24: it is split into the two /26 firewall subnets."
  type        = string
  default     = "10.10.0.0/24"

  validation {
    condition     = can(cidrhost(var.hub_address_space, 0)) && try(tonumber(split("/", var.hub_address_space)[1]) == 24, false)
    error_message = "hub_address_space must be a valid IPv4 CIDR with prefix length 24."
  }
}

variable "spoke_address_space" {
  description = "Spoke VNet address space. Must be a /16: it is split into the AKS and private endpoint subnets."
  type        = string
  default     = "10.20.0.0/16"

  validation {
    condition     = can(cidrhost(var.spoke_address_space, 0)) && try(tonumber(split("/", var.spoke_address_space)[1]) == 16, false)
    error_message = "spoke_address_space must be a valid IPv4 CIDR with prefix length 16."
  }
}

variable "dns_block_mode" {
  description = "false: the catch-all DNS rule for \".\" only raises an Alert (everything resolves, every query is logged). true: it Blocks everything that is not on the allowlist. Switch to true only after a session has shown the allowlist is complete."
  type        = bool
  default     = false
}

variable "dns_allowed_domains" {
  description = "Domains that always resolve (rule priority 100, action Allow). Each entry ends with a dot and covers its subdomains (DNS hierarchy). The first list is a starting point for AKS, Key Vault, PostgreSQL, ACR, Entra and Foundry; check it against the DNS query log before turning on dns_block_mode."
  type        = list(string)
  default = [
    "azure.com.",
    "azure.net.",
    "azmk8s.io.",
    "azurecr.io.",
    "windows.net.",
    "microsoft.com.",
    "microsoftonline.com.",
    "gitlab.com.",
  ]

  validation {
    condition     = length(var.dns_allowed_domains) >= 1 && alltrue([for d in var.dns_allowed_domains : can(regex("^[a-zA-Z0-9][a-zA-Z0-9.-]*[.]$", d))])
    error_message = "Give at least one domain; each must end with a dot, for example \"azurecr.io.\"."
  }
}

variable "log_analytics_workspace_id" {
  description = "Workspace that receives the DNS query log (category DnsResponse). null: no diagnostic setting, queries are not logged."
  type        = string
  default     = null
}

variable "tags" {
  description = "Tags added to every taggable resource."
  type        = map(string)
  default = {
    project = "assume-hijacked"
    layer   = "net"
  }
}
