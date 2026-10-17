# rg-base: the part of the lab that survives every destroy of rg-lab.
# Contents: empty rg-net and rg-lab shells, state storage, container registry,
# Log Analytics (this file);
# Key Vaults (keyvaults.tf); budgets (budgets.tf); Azure Policy (policy.tf);
# CI identities (ci-identities.tf).

locals {
  subscription_scope = "/subscriptions/${var.subscription_id}"
}

resource "azurerm_resource_group" "base" {
  name     = var.resource_group_name
  location = var.location
  tags     = var.tags
}

# ---------------------------------------------------------------- rg-net and rg-lab (empty shells)
#
# The two resource groups of the other stacks are created HERE and stay empty. infra/net
# and infra/lab must reference them with `data "azurerm_resource_group"`, never create
# them. Reason: ci-apply's role assignments on these groups live in this state. If the
# nightly lab destroy deleted rg-lab itself, the assignments would vanish with it and CI
# could not recreate the lab. A lab destroy removes the group's contents, never the group.
# Empty resource groups cost nothing.

resource "azurerm_resource_group" "net" {
  name     = var.net_resource_group_name
  location = var.location
  tags     = var.tags
}

resource "azurerm_resource_group" "lab" {
  name     = var.lab_resource_group_name
  location = var.location
  tags     = var.tags
}

# ---------------------------------------------------------------- Terraform state

# prevent_destroy: the state of every stack lives here and cannot be rebuilt. To tear the lab
# project down for good, remove the lifecycle block of the account and the container first.
resource "azurerm_storage_account" "state" {
  #checkov:skip=CKV_AZURE_59: GitLab.com runners and the owner's PC reach the state over the public endpoint; shared keys and anonymous access are off, Entra roles are required
  #checkov:skip=CKV2_AZURE_33: no private endpoint: GitLab.com runners have no path into the VNet (same reason as CKV_AZURE_59)
  #checkov:skip=CKV_AZURE_206: LRS on purpose, the cheapest; blob versioning and 14 days of soft delete cover a bad apply
  #checkov:skip=CKV_AZURE_33: the queue service is not used by this account
  #checkov:skip=CKV2_AZURE_1: Microsoft-managed keys; a customer-managed key needs its own Key Vault key and identity (backlog)
  lifecycle {
    prevent_destroy = true
  }

  name                = var.state_storage_account_name
  resource_group_name = azurerm_resource_group.base.name
  location            = azurerm_resource_group.base.location

  account_tier             = "Standard"
  account_replication_type = "LRS" # a lab: one copy is enough, and it is the cheapest

  min_tls_version                 = "TLS1_2"
  https_traffic_only_enabled      = true
  allow_nested_items_to_be_public = false # no anonymous blob access, ever
  shared_access_key_enabled       = false # Entra ID only; no account key to leak
  default_to_oauth_authentication = true
  local_user_enabled              = false

  blob_properties {
    versioning_enabled = true # a bad apply can be rolled back to the last state

    delete_retention_policy {
      days = 14
    }

    container_delete_retention_policy {
      days = 14
    }
  }

  tags = var.tags
}

resource "azurerm_storage_container" "state" {
  #checkov:skip=CKV2_AZURE_21: blob read logging is off; the Activity log records management changes (backlog)
  lifecycle {
    prevent_destroy = true
  }

  name                  = var.state_container_name
  storage_account_id    = azurerm_storage_account.state.id
  container_access_type = "private"
}

# ---------------------------------------------------------------- container registry

resource "azurerm_container_registry" "acr" {
  #checkov:skip=CKV_AZURE_139: Basic tier on purpose (cost); this needs Premium or Defender for Containers
  #checkov:skip=CKV_AZURE_163: Basic tier on purpose (cost); this needs Premium or Defender for Containers
  #checkov:skip=CKV_AZURE_164: Basic tier on purpose (cost); this needs Premium or Defender for Containers
  #checkov:skip=CKV_AZURE_165: Basic tier on purpose (cost); this needs Premium or Defender for Containers
  #checkov:skip=CKV_AZURE_166: Basic tier on purpose (cost); this needs Premium or Defender for Containers
  #checkov:skip=CKV_AZURE_167: Basic tier on purpose (cost); this needs Premium or Defender for Containers
  #checkov:skip=CKV_AZURE_233: Basic tier on purpose (cost); this needs Premium or Defender for Containers
  #checkov:skip=CKV_AZURE_237: Basic tier on purpose (cost); this needs Premium or Defender for Containers
  name                = var.acr_name
  resource_group_name = azurerm_resource_group.base.name
  location            = azurerm_resource_group.base.location

  sku           = "Basic" # cheapest tier; no private endpoint, no zone redundancy
  admin_enabled = false   # pull and push use Entra roles (AcrPull, AcrPush), never the admin user

  tags = var.tags
}

# ---------------------------------------------------------------- Log Analytics

resource "azurerm_log_analytics_workspace" "evidence" {
  name                = var.log_analytics_workspace_name
  resource_group_name = azurerm_resource_group.base.name
  location            = azurerm_resource_group.base.location

  sku               = "PerGB2018"
  retention_in_days = var.log_analytics_retention_days
  daily_quota_gb    = var.log_analytics_daily_quota_gb # hard cap on cost: ingestion stops at the cap

  tags = var.tags
}
