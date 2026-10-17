# AKS: Free tier, Azure CNI overlay with the Cilium data plane and Advanced Container
# Networking Services (Cilium FQDN/DNS policies, decision 4), Entra-only access with Azure
# RBAC, workload identity, two node pools:
#
#   system   2+ x Standard_D4als_v6, Azure Linux, tainted CriticalAddonsOnly=true:NoSchedule
#            (only_critical_addons_enabled). There is no user pool (decision 6), so the app
#            components that are not sandboxed tolerate the taint and run here (ruling R17b).
#   sandbox  0-3 x Standard_D4als_v6, Azure Linux, workload runtime KataVmIsolation. AKS
#            provides the RuntimeClass `kata-vm-isolation`; agent Jobs and tools use it.
#            No taint: the AKS RuntimeClass carries no toleration, and the system taint
#            already keeps the sandboxed pods off the system pool.
#
# Checked (azurerm 4.81.0 provider schema and docs, learn.microsoft.com):
#   - workload_runtime "KataVmIsolation" (azurerm r/kubernetes_cluster_node_pool: allowed
#     values KataVmIsolation, OCIContainer, WasmWasi; the old KataMshvVmIsolation is not in the
#     4.81.0 binary). AKS: learn.microsoft.com/azure/aks/use-pod-sandboxing (--workload-runtime
#     KataVmIsolation, Azure Linux only, Gen2 size with nested virtualization).
#   - Standard_D4als_v6: Gen2, nested virtualization supported, no local disk so no ephemeral
#     OS disk (learn.microsoft.com/azure/virtual-machines/sizes/general-purpose/dalsv6-series).
#   - network_profile.advanced_networking {observability_enabled, security_enabled} = ACNS.
#   - Egress with userDefinedRouting: route table on the subnets before the cluster exists,
#     firewall public IP in the API authorized ranges
#     (learn.microsoft.com/azure/aks/limit-egress-traffic).

locals {
  service_cidr = var.service_cidr

  # Overlap test on IPv4 ranges: same start on the shorter prefix.
  service_pod_ranges = {
    for k, c in { service = local.service_cidr, pod = local.net.aks_pod_cidr } : k => {
      start               = sum([for i, o in split(".", cidrhost(c, 0)) : tonumber(o) * pow(256, 3 - i)])
      bits                = tonumber(split("/", c)[1])
    }
  }
  service_pod_bits = min(local.service_pod_ranges.service.bits, local.service_pod_ranges.pod.bits)
  service_overlaps_pods = (
    floor(local.service_pod_ranges.service.start / pow(2, 32 - local.service_pod_bits))
    == floor(local.service_pod_ranges.pod.start / pow(2, 32 - local.service_pod_bits))
  )

  # The firewall's public IP must be authorized, or nodes behind the firewall cannot reach
  # the API server (their traffic leaves through that IP).
  api_authorized_ip_ranges = concat(
    var.api_authorized_ip_ranges,
    var.enable_firewall ? ["${azurerm_public_ip.firewall_data[0].ip_address}/32"] : [],
  )
}

resource "azurerm_kubernetes_cluster" "this" {
  name                = var.cluster_name
  location            = var.location
  resource_group_name = data.azurerm_resource_group.lab.name
  dns_prefix          = var.cluster_name
  node_resource_group = "${data.azurerm_resource_group.lab.name}-aks-nodes"
  kubernetes_version  = var.kubernetes_version
  sku_tier            = "Free"

  automatic_upgrade_channel = "patch"
  node_os_upgrade_channel   = "NodeImage"

  # Access: Entra only. No local admin kubeconfig, Azure RBAC decides, no run-command
  # backdoor around the API authorized ranges.
  local_account_disabled            = true
  role_based_access_control_enabled = true
  run_command_enabled               = false

  azure_active_directory_role_based_access_control {
    azure_rbac_enabled     = true
    tenant_id              = var.tenant_id
    admin_group_object_ids = var.aks_admin_group_object_ids
  }

  api_server_access_profile {
    authorized_ip_ranges = local.api_authorized_ip_ranges
  }

  # Workload identity: pods trade their ServiceAccount token for an Entra token.
  oidc_issuer_enabled       = true
  workload_identity_enabled = true

  # Secrets Store CSI driver (Key Vault -> K8s Secret). The pods' SecretProviderClass uses
  # each component's own workload identity, not the add-on identity.
  key_vault_secrets_provider {
    secret_rotation_enabled  = true
    secret_rotation_interval = "2m"
  }

  # Admission is ValidatingAdmissionPolicy + Pod Security Admission (decision 9), not
  # Azure Policy for Kubernetes.
  azure_policy_enabled         = false
  image_cleaner_enabled        = true
  image_cleaner_interval_hours = 48

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.aks_control_plane.id]
  }

  kubelet_identity {
    client_id                 = azurerm_user_assigned_identity.aks_kubelet.client_id
    object_id                 = azurerm_user_assigned_identity.aks_kubelet.principal_id
    user_assigned_identity_id = azurerm_user_assigned_identity.aks_kubelet.id
  }

  default_node_pool {
    name                         = "system"
    vm_size                      = var.node_vm_size
    node_count                   = var.system_node_count
    only_critical_addons_enabled = true # taint CriticalAddonsOnly=true:NoSchedule
    os_sku                       = "AzureLinux"
    os_disk_type                 = "Managed" # the size has no local disk
    vnet_subnet_id               = local.aks_subnet_ids["snet-aks-system"]
    temporary_name_for_rotation  = "systemtmp"
    node_labels                  = { "ah/pool" = "system" }

    upgrade_settings {
      max_surge = "1"
    }
  }

  network_profile {
    network_plugin      = "azure"
    network_plugin_mode = "overlay"
    network_data_plane  = "cilium"
    network_policy      = "cilium"
    load_balancer_sku   = "standard"
    outbound_type       = var.enable_firewall ? "userDefinedRouting" : "loadBalancer"

    # Pod range from infra/net, whose AKS NSGs allow exactly this range (overlay pod traffic
    # is not encapsulated). Service range: outside hub 10.10.0.0/24, spoke 10.20.0.0/16 and pods.
    pod_cidr       = local.net.aks_pod_cidr
    service_cidr   = local.service_cidr
    dns_service_ip = cidrhost(local.service_cidr, 10)

    # Advanced Container Networking Services: Cilium FQDN filtering and L7 policy
    # (security) and Hubble flow logs (observability).
    advanced_networking {
      observability_enabled = true
      security_enabled      = true
    }
  }

  # Container logs and Kubernetes events -> Log Analytics (DCR in monitoring.tf).
  oms_agent {
    log_analytics_workspace_id      = local.base.log_analytics_workspace_id
    msi_auth_for_monitoring_enabled = true
  }

  dynamic "microsoft_defender" {
    for_each = var.defender_enabled ? [1] : []

    content {
      log_analytics_workspace_id = local.base.log_analytics_workspace_id
    }
  }

  tags = var.tags

  # Roles and routes must exist before AKS validates the subnets and starts the nodes.
  depends_on = [
    azurerm_role_assignment.aks_control_plane_kubelet_operator,
    azurerm_role_assignment.aks_control_plane_subnets,
    azurerm_role_assignment.aks_control_plane_route_table,
    azurerm_role_assignment.aks_kubelet_acr_pull,
    azurerm_subnet_route_table_association.aks,
    azurerm_firewall_policy_rule_collection_group.egress,
  ]

  lifecycle {
    ignore_changes = [
      kubernetes_version, # moved by the patch upgrade channel
    ]

    precondition {
      condition     = !local.service_overlaps_pods
      error_message = "The service range ${local.service_cidr} overlaps the pod range ${local.net.aks_pod_cidr} from infra/net."
    }
  }
}

resource "azurerm_kubernetes_cluster_node_pool" "sandbox" {
  name                  = "sandbox"
  kubernetes_cluster_id = azurerm_kubernetes_cluster.this.id
  mode                  = "User"
  vm_size               = var.node_vm_size
  node_count            = var.sandbox_node_count
  os_type               = "Linux"
  os_sku                = "AzureLinux" # Kata needs Azure Linux
  os_disk_type          = "Managed"
  workload_runtime      = "KataVmIsolation"
  vnet_subnet_id        = local.aks_subnet_ids["snet-aks-sandbox"]
  node_labels           = { "ah/pool" = "sandbox" }

  upgrade_settings {
    max_surge = "1"
  }

  tags = var.tags
}
