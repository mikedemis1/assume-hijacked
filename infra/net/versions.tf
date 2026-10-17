terraform {
  required_version = "~> 1.15.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }

    # Used ONLY for the DNS security policy objects in dns-policy.tf (ruling R16).
    # azurerm 4.81.0 has no resource for them; upstream request:
    # https://github.com/hashicorp/terraform-provider-azurerm/issues/28597
    # When azurerm gains them, move dns-policy.tf to azurerm and drop this provider.
    azapi = {
      source  = "Azure/azapi"
      version = "2.13.0"
    }
  }

  # State: same storage account as infra/base, own key. Enable after base is applied
  # and the state storage exists (see the bootstrap note in infra/base/versions.tf).
  #
  # backend "azurerm" {
  #   resource_group_name  = "rg-base"
  #   storage_account_name = "<state_storage_account_name>"
  #   container_name       = "tfstate"
  #   key                  = "net.tfstate"
  #   use_azuread_auth     = true
  # }
}

provider "azurerm" {
  subscription_id = var.subscription_id
  tenant_id       = var.tenant_id

  features {}
}

provider "azapi" {
  subscription_id = var.subscription_id
  tenant_id       = var.tenant_id
}
