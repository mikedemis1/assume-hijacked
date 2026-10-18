terraform {
  required_version = "~> 1.15.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 3.0"
    }
  }

  # Bootstrap note
  # --------------
  # The storage account that holds the state is created by this very configuration, so
  # the first apply uses LOCAL state (no backend block). After the first apply:
  #   1. Give yourself "Storage Blob Data Contributor" on the state storage account.
  #   2. Remove the comment markers below, fill in the names from `terraform output`.
  #   3. Run `terraform init -migrate-state`.
  # Shared keys are disabled on the account, so the backend must use Entra ID.
  #
  # backend "azurerm" {
  #   resource_group_name  = "rg-base"
  #   storage_account_name = "<state_storage_account_name>"
  #   container_name       = "tfstate"
  #   key                  = "base.tfstate"
  #   use_azuread_auth     = true
  # }
}

provider "azurerm" {
  subscription_id     = var.subscription_id
  tenant_id           = var.tenant_id
  storage_use_azuread = true # the account has shared keys off; data-plane calls use Entra

  features {}
}

provider "azuread" {
  tenant_id = var.tenant_id
}
