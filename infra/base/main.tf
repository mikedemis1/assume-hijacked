# rg-base: the part of the lab that survives every destroy of rg-lab.
# Contents: the empty rg-lab shell, state storage, container registry,
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

# ---------------------------------------------------------------- rg-lab (empty shell)
#
# The resource group of the lab stack is created HERE and stays empty. infra/lab must
# reference it with `data "azurerm_resource_group"`, never create it. Reason: ci-apply's
# role assignments on the group live in this state. If the nightly lab destroy deleted
# rg-lab itself, the assignments would vanish with it and CI could not recreate the lab.
# A lab destroy removes the group's contents, never the group.
# An empty resource group costs nothing.

resource "azurerm_resource_group" "lab" {
  name     = var.lab_resource_group_name
  location = var.location
  tags     = var.tags
}

# ---------------------------------------------------------------- Terraform state

# prevent_destroy: the state of every stack lives here and cannot be rebuilt. To tear the lab
# project down for good, remove the lifecycle block of the account and the container first.
resource "azurerm_storage_account" "state" {
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
  lifecycle {
    prevent_destroy = true
  }

  name                  = var.state_container_name
  storage_account_id    = azurerm_storage_account.state.id
  container_access_type = "private"
}

# ---------------------------------------------------------------- container registry

resource "azurerm_container_registry" "acr" {
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
