terraform {
  required_version = "~> 1.15.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }

    # Only for the ephemeral PostgreSQL admin password (postgres.tf). Ephemeral resources are
    # never written to the plan or the state; random 3.7 is the first version that has them.
    random = {
      source  = "hashicorp/random"
      version = "~> 3.7"
    }
  }

  # State: same storage account as infra/base, own key. Enable after base is
  # applied and its state migrated (see the bootstrap note in infra/base/versions.tf).
  #
  # backend "azurerm" {
  #   resource_group_name  = "rg-base"
  #   storage_account_name = "<state_storage_account_name>"
  #   container_name       = "tfstate"
  #   key                  = "lab.tfstate"
  #   use_azuread_auth     = true
  # }
}

provider "azurerm" {
  subscription_id     = var.subscription_id
  tenant_id           = var.tenant_id
  storage_use_azuread = true

  features {}
}
