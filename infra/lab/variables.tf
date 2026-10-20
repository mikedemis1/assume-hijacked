variable "subscription_id" {
  description = "Subscription that holds rg-lab."
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
    error_message = "This build runs in North Europe only."
  }
}

variable "resource_group_name" {
  description = "Resource group for the lab. Created EMPTY by infra/base, so that destroying the lab never removes it; this stack only reads it."
  type        = string
  default     = "rg-lab"
}

# ---------------------------------------------------------------- where base lives

variable "state_resource_group_name" {
  description = "Resource group of the Terraform state storage account (infra/base)."
  type        = string
  default     = "rg-base"
}

variable "state_storage_account_name" {
  description = "State storage account (infra/base output state_storage_account_name). The lab reads the base state from it."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9]{3,24}$", var.state_storage_account_name))
    error_message = "Storage account names are 3-24 lowercase letters and digits."
  }
}

variable "state_container_name" {
  description = "Blob container of the state files."
  type        = string
  default     = "tfstate"
}

variable "base_state_key" {
  description = "Blob name of the infra/base state."
  type        = string
  default     = "base.tfstate"
}

# ---------------------------------------------------------------- workload identities

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

variable "service_account_namespaces" {
  description = "Namespace of each component's ServiceAccount (the Helm chart's layout). Components named tool-* that are not listed here run in ah-tools."
  type        = map(string)
  default = {
    dispatcher     = "ah-intake"
    agent          = "ah-agent"
    "llm-gateway"  = "ah-agent"
    "tool-gateway" = "ah-gateway"
    "risk-engine"  = "ah-core"
    executor       = "ah-core"
    "db-migrate"   = "ah-core"
    console        = "ah-staff"
  }
}

variable "db_admin_component" {
  description = "Component whose identity becomes the PostgreSQL Entra administrator (it runs the schema migration)."
  type        = string
  default     = "db-migrate"
}

# ---------------------------------------------------------------- network

variable "vnet_address_space" {
  description = "Address space of the lab VNet. Must be a /16: it is split into the two AKS subnets and the private endpoint subnet."
  type        = string
  default     = "10.20.0.0/16"

  validation {
    condition     = can(cidrhost(var.vnet_address_space, 0)) && try(tonumber(split("/", var.vnet_address_space)[1]) == 16, false)
    error_message = "vnet_address_space must be a valid IPv4 CIDR with prefix length 16."
  }
}

variable "aks_pod_cidr" {
  description = "Pod range of the AKS overlay network. Overlay pod traffic is not encapsulated, so the AKS subnet NSGs must allow it."
  type        = string
  default     = "10.244.0.0/16"

  validation {
    # Two IPv4 ranges overlap when their first addresses (as integers) agree on the shorter
    # of the two prefixes. Checked against the VNet address space.
    condition = can(cidrhost(var.aks_pod_cidr, 0)) && try(
      floor(
        sum([for i, o in split(".", cidrhost(var.aks_pod_cidr, 0)) : tonumber(o) * pow(256, 3 - i)])
        / pow(2, 32 - min(tonumber(split("/", var.aks_pod_cidr)[1]), tonumber(split("/", var.vnet_address_space)[1])))
      )
      != floor(
        sum([for i, o in split(".", cidrhost(var.vnet_address_space, 0)) : tonumber(o) * pow(256, 3 - i)])
        / pow(2, 32 - min(tonumber(split("/", var.aks_pod_cidr)[1]), tonumber(split("/", var.vnet_address_space)[1])))
      ),
      false
    )
    error_message = "aks_pod_cidr must be an IPv4 CIDR that does not overlap the VNet address space (the NSGs allow every port to and from it)."
  }
}

# ---------------------------------------------------------------- AKS

variable "cluster_name" {
  description = "AKS cluster name."
  type        = string
  default     = "aks-assume-hijacked"
}

variable "kubernetes_version" {
  description = "Kubernetes version. Null takes the region's default; the patch channel keeps it current."
  type        = string
  default     = null
}

variable "node_vm_size" {
  description = "VM size of both node pools. Must support nested virtualization (Kata) and must not be burstable B-series."
  type        = string
  default     = "Standard_D4als_v6"

  validation {
    condition     = !startswith(lower(var.node_vm_size), "standard_b")
    error_message = "B-series (burstable) sizes are not allowed: they run out of CPU credits under load and do not support nested virtualization."
  }
}

variable "system_node_count" {
  description = "Nodes in the system pool. It also runs the app components that are not sandboxed, so one node is not enough."
  type        = number
  default     = 2

  validation {
    condition     = var.system_node_count >= 2 && floor(var.system_node_count) == var.system_node_count
    error_message = "The system pool needs at least 2 nodes."
  }
}

variable "sandbox_node_count" {
  description = "Nodes in the Kata sandbox pool. 0 parks the pool when no agent or tool needs to run."
  type        = number
  default     = 1

  validation {
    condition     = var.sandbox_node_count >= 0 && var.sandbox_node_count <= 3 && floor(var.sandbox_node_count) == var.sandbox_node_count
    error_message = "sandbox_node_count must be a whole number from 0 to 3."
  }
}

variable "service_cidr" {
  description = "Kubernetes service range. Must not overlap the pod range (aks_pod_cidr) or the VNet. The DNS service gets its 10th address."
  type        = string
  default     = "10.0.0.0/16"

  validation {
    condition     = can(cidrhost(var.service_cidr, 10)) && try(tonumber(split("/", var.service_cidr)[1]) >= 12, false)
    error_message = "service_cidr must be an IPv4 CIDR no wider than /12 (AKS limit)."
  }
}

variable "api_authorized_ip_ranges" {
  description = "Public CIDRs that may reach the Kubernetes API (for example the owner's IP as x.x.x.x/32)."
  type        = list(string)

  validation {
    condition     = length(var.api_authorized_ip_ranges) >= 1
    error_message = "Give at least one range; an empty list leaves the API server open to the Internet."
  }

  validation {
    condition = alltrue([
      for r in var.api_authorized_ip_ranges :
      can(cidrhost(r, 0)) && !contains(["0.0.0.0/0", "0.0.0.0/1", "128.0.0.0/1"], r) && try(tonumber(split("/", r)[1]) >= 8, false)
    ])
    error_message = "Each range must be an IPv4 CIDR no wider than /8; 0.0.0.0/0 is refused."
  }
}

variable "aks_admin_group_object_ids" {
  description = "Entra groups that get cluster-admin through Entra integration. Local accounts are off, so this (or an Azure RBAC role) is the only way in."
  type        = list(string)
  default     = []
}

variable "defender_enabled" {
  description = "Turn on the Microsoft Defender for Containers profile on the cluster (billable; the subscription plan must also be on). Defender does not assess Kata pods."
  type        = bool
  default     = false
}

variable "aks_audit_log_category" {
  description = "AKS audit log category sent to Log Analytics. kube-audit-admin skips get/list (cheaper); kube-audit has everything, including secret reads."
  type        = string
  default     = "kube-audit-admin"

  validation {
    condition     = contains(["kube-audit", "kube-audit-admin"], var.aks_audit_log_category)
    error_message = "aks_audit_log_category must be kube-audit or kube-audit-admin."
  }
}

# ---------------------------------------------------------------- PostgreSQL

variable "postgres_admin_login" {
  description = "Password administrator of the flexible server (break glass only; nobody holds its password, see postgres.tf)."
  type        = string
  default     = "ahbreakglass"
}

variable "postgres_admin_password_version" {
  description = "Increase by one to set a new random admin password (write-only argument: Terraform sends the password only when this number changes)."
  type        = number
  default     = 1
}

variable "postgres_extensions" {
  description = "Extensions allow-listed on the server (azure.extensions). The schema scripts create pgcrypto."
  type        = list(string)
  default     = ["PGCRYPTO"]

  validation {
    condition     = contains([for e in var.postgres_extensions : upper(e)], "PGCRYPTO")
    error_message = "PGCRYPTO must stay allow-listed: db/sql/05-lease.sql creates it."
  }
}

# ---------------------------------------------------------------- alerts

variable "alert_email" {
  description = "Address that receives the Log Analytics alerts. Kept out of the code on purpose."
  type        = string

  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.alert_email))
    error_message = "alert_email must be an e-mail address."
  }
}

variable "attack_event_kinds" {
  description = "Security event kinds (the `kind` field of the app's JSON security log, app/agent/events.py) that raise the attack alert. Add the gateway and risk-engine kinds once the application logs them."
  type        = list(string)
  default     = ["blocked", "reply_blocked", "unknown_tool"]

  validation {
    condition     = length(var.attack_event_kinds) >= 1 && alltrue([for k in var.attack_event_kinds : can(regex("^[a-z_]+$", k))])
    error_message = "Give at least one kind; kinds are lowercase letters and underscores (they go into a KQL query)."
  }
}

variable "tags" {
  description = "Tags added to every taggable resource."
  type        = map(string)
  default = {
    project = "assume-hijacked"
    layer   = "lab"
  }
}
