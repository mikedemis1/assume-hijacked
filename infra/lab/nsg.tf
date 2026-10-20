# One NSG per subnet.
#
# Rule layout (all three NSGs):
#   100-399   allow only what the subnet needs
#   4000      deny inbound from the Internet (explicit, so it shows in reviews and logs)
#   4096      deny everything else, inbound and outbound
#
# NSG rules are the coarse wall; the Cilium policies are the fine ones. Because our deny rule sits before the default allow rules (priority 65000+),
# every platform range a subnet needs is named explicitly (168.63.129.16 = Azure DNS and
# health probes).

locals {
  pe_prefix = local.subnets["snet-pe"]

  # Rules both AKS subnets have. Priorities are unique per direction.
  aks_common_rules = {
    allow-aks-subnets-in = {
      priority         = 100, direction = "Inbound", access = "Allow", protocol = "*"
      dest_port_ranges = ["*"], source_prefixes = local.aks_cluster_prefixes, dest_prefixes = ["*"]
    }
    allow-load-balancer-in = {
      priority         = 110, direction = "Inbound", access = "Allow", protocol = "*"
      dest_port_ranges = ["*"], source_prefixes = ["AzureLoadBalancer"], dest_prefixes = ["*"]
    }
    deny-internet-in = {
      priority         = 4000, direction = "Inbound", access = "Deny", protocol = "*"
      dest_port_ranges = ["*"], source_prefixes = ["Internet"], dest_prefixes = ["*"]
    }
    deny-all-in = {
      priority         = 4096, direction = "Inbound", access = "Deny", protocol = "*"
      dest_port_ranges = ["*"], source_prefixes = ["*"], dest_prefixes = ["*"]
    }
    allow-aks-subnets-out = {
      priority         = 100, direction = "Outbound", access = "Allow", protocol = "*"
      dest_port_ranges = ["*"], source_prefixes = ["*"], dest_prefixes = local.aks_cluster_prefixes
    }
    allow-postgres-to-pe = {
      priority         = 110, direction = "Outbound", access = "Allow", protocol = "Tcp"
      dest_port_ranges = ["5432"], source_prefixes = ["*"], dest_prefixes = [local.pe_prefix]
    }
    allow-https-to-pe = {
      priority         = 120, direction = "Outbound", access = "Allow", protocol = "Tcp"
      dest_port_ranges = ["443"], source_prefixes = ["*"], dest_prefixes = [local.pe_prefix]
    }
    allow-dns-to-azure = {
      priority         = 130, direction = "Outbound", access = "Allow", protocol = "*"
      dest_port_ranges = ["53"], source_prefixes = ["*"], dest_prefixes = ["168.63.129.16"]
    }
    deny-all-out = {
      priority         = 4096, direction = "Outbound", access = "Deny", protocol = "*"
      dest_port_ranges = ["*"], source_prefixes = ["*"], dest_prefixes = ["*"]
    }
  }

  nsg_rules = {
    snet-aks-system = merge(local.aks_common_rules, {
      # The pods that sign in with Entra (LLM gateway, console, db-migrate) run on this pool.
      allow-entra-out = {
        priority         = 140, direction = "Outbound", access = "Allow", protocol = "Tcp"
        dest_port_ranges = ["443"], source_prefixes = ["*"], dest_prefixes = ["AzureActiveDirectory"]
      }
      # Node egress (image pulls, GitLab agent, Azure APIs) leaves through the AKS load balancer.
      allow-node-https-out = {
        priority         = 150, direction = "Outbound", access = "Allow", protocol = "Tcp"
        dest_port_ranges = ["443"], source_prefixes = ["*"], dest_prefixes = ["Internet"]
      }
    })

    snet-aks-sandbox = merge(local.aks_common_rules, {
      # Tools and agents run here: no general Internet rule. Azure allows ONE service tag
      # per rule, so every tag gets its own rule.
      #
      # Platform ranges the node itself needs (registry, AKS control plane):
      allow-azure-cloud-out = {
        priority         = 140, direction = "Outbound", access = "Allow", protocol = "Tcp"
        dest_port_ranges = ["443"], source_prefixes = ["*"], dest_prefixes = ["AzureCloud.northeurope"]
      }
      allow-container-registry-out = {
        priority         = 150, direction = "Outbound", access = "Allow", protocol = "Tcp"
        dest_port_ranges = ["443"], source_prefixes = ["*"], dest_prefixes = ["MicrosoftContainerRegistry"]
      }
      # Entra and Key Vault: the Secrets Store CSI provider DaemonSet runs on EVERY node,
      # the sandbox pool included. It does the workload identity token exchange (Entra) and
      # reads the vault. The NSG cannot tell it from a pod, so the subnet allows both; the
      # pods themselves stay limited by their CiliumNetworkPolicy (no Entra, no vault).
      allow-entra-out = {
        priority         = 160, direction = "Outbound", access = "Allow", protocol = "Tcp"
        dest_port_ranges = ["443"], source_prefixes = ["*"], dest_prefixes = ["AzureActiveDirectory"]
      }
      allow-key-vault-out = {
        priority         = 170, direction = "Outbound", access = "Allow", protocol = "Tcp"
        dest_port_ranges = ["443"], source_prefixes = ["*"], dest_prefixes = ["AzureKeyVault.northeurope"]
      }
    })

    snet-pe = {
      allow-postgres-from-aks = {
        priority         = 100, direction = "Inbound", access = "Allow", protocol = "Tcp"
        dest_port_ranges = ["5432"], source_prefixes = local.aks_prefixes, dest_prefixes = ["*"]
      }
      allow-https-from-aks = {
        priority         = 110, direction = "Inbound", access = "Allow", protocol = "Tcp"
        dest_port_ranges = ["443"], source_prefixes = local.aks_prefixes, dest_prefixes = ["*"]
      }
      deny-internet-in = {
        priority         = 4000, direction = "Inbound", access = "Deny", protocol = "*"
        dest_port_ranges = ["*"], source_prefixes = ["Internet"], dest_prefixes = ["*"]
      }
      deny-all-in = {
        priority         = 4096, direction = "Inbound", access = "Deny", protocol = "*"
        dest_port_ranges = ["*"], source_prefixes = ["*"], dest_prefixes = ["*"]
      }
      # A private endpoint never starts a connection.
      deny-all-out = {
        priority         = 4096, direction = "Outbound", access = "Deny", protocol = "*"
        dest_port_ranges = ["*"], source_prefixes = ["*"], dest_prefixes = ["*"]
      }
    }
  }
}

resource "azurerm_network_security_group" "subnet" {
  for_each = local.nsg_rules

  name                = "nsg-${each.key}"
  location            = var.location
  resource_group_name = data.azurerm_resource_group.lab.name
  tags                = var.tags

  dynamic "security_rule" {
    for_each = each.value

    content {
      name                         = security_rule.key
      priority                     = security_rule.value.priority
      direction                    = security_rule.value.direction
      access                       = security_rule.value.access
      protocol                     = security_rule.value.protocol
      source_port_range            = "*"
      destination_port_ranges      = security_rule.value.dest_port_ranges
      source_address_prefixes      = security_rule.value.source_prefixes
      destination_address_prefixes = security_rule.value.dest_prefixes
    }
  }
}

# Every subnet gets its NSG. A subnet without an entry in local.nsg_rules fails the lookup
# at plan time instead of staying open.
resource "azurerm_subnet_network_security_group_association" "subnet" {
  for_each = azurerm_subnet.subnet

  subnet_id                 = each.value.id
  network_security_group_id = azurerm_network_security_group.subnet[each.key].id
}
