# Evidence and alerts. Everything goes to the Log Analytics workspace in rg-base (daily cap
# 0.5 GB there is the cost ceiling).
#
#   diagnostic settings  AKS audit, PostgreSQL logs, Key Vault audit
#   container logs       Azure Monitor agent + data collection rule, only the ah-* namespaces
#   alert rules          heartbeat missing, attack events
#
# Alert rules and the action group live in rg-lab on purpose: they are destroyed with the lab,
# so the "heartbeat missing" rule cannot fire every night while the lab is down. The Key Vault
# diagnostic settings are extension resources on the vaults in rg-base (ci-apply has
# Monitoring Contributor there); vault reads while the lab is down are therefore
# not logged, and nothing can read the vaults then except their owners.
#
# Table names checked on learn.microsoft.com/azure/azure-monitor/reference/tables:
# ContainerLogV2, KubePodInventory.

locals {
  workspace_id = local.base.log_analytics_workspace_id

  # Namespaces whose container logs are collected (the chart's namespaces). kube-system is
  # left out to stay under the workspace's daily cap.
  log_namespaces = ["ah-intake", "ah-agent", "ah-gateway", "ah-tools", "ah-core", "ah-staff"]

  attack_kinds_kql = join(", ", [for k in var.attack_event_kinds : "\"${k}\""])

  # name -> rule. Queries return one row with a number; the rule fires on the threshold.
  alert_rules = {
    heartbeat-missing = {
      severity    = 1
      description = "No running executor pod reported in the last 15 minutes: effects (credits, move-outs) are not being executed or checked."
      query       = <<-KQL
          KubePodInventory
          | where Namespace == "ah-core" and ControllerName startswith "executor"
          | summarize running = dcountif(Name, PodStatus == "Running")
        KQL
      column      = "running"
      operator    = "LessThan"
      threshold   = 1
    }
    attack-events = {
      severity    = 2
      description = "The app logged security events of an attack kind (blocked tool call, blocked reply, unknown tool)."
      query       = <<-KQL
          ContainerLogV2
          | where PodNamespace startswith "ah-"
          | extend kind = extract(@'"kind":\s*"([a-z_]+)"', 1, tostring(LogMessage))
          | where kind in (${local.attack_kinds_kql})
          | summarize events = count()
        KQL
      column      = "events"
      operator    = "GreaterThan"
      threshold   = 0
    }
  }
}

# ---------------------------------------------------------------- diagnostic settings

resource "azurerm_monitor_diagnostic_setting" "aks" {
  name                           = "to-log-analytics"
  target_resource_id             = azurerm_kubernetes_cluster.this.id
  log_analytics_workspace_id     = local.workspace_id
  log_analytics_destination_type = "Dedicated" # AKSAudit / AKSAuditAdmin tables

  enabled_log {
    category = var.aks_audit_log_category
  }

  # Entra (guard) authentication decisions: who tried to use the API.
  enabled_log {
    category = "guard"
  }
}

resource "azurerm_monitor_diagnostic_setting" "postgres" {
  name                       = "to-log-analytics"
  target_resource_id         = azurerm_postgresql_flexible_server.this.id
  log_analytics_workspace_id = local.workspace_id

  enabled_log {
    category = "PostgreSQLLogs"
  }
}

resource "azurerm_monitor_diagnostic_setting" "key_vault" {
  for_each = local.key_vaults

  name                       = "lab-to-log-analytics"
  target_resource_id         = each.value.id
  log_analytics_workspace_id = local.workspace_id

  enabled_log {
    category = "AuditEvent"
  }
}

# ---------------------------------------------------------------- container logs

# Format: learn.microsoft.com/azure/azure-monitor/containers/container-insights-transformations
# (dataSources.extensions ContainerInsights with dataCollectionSettings).
resource "azurerm_monitor_data_collection_rule" "container_logs" {
  name                = "dcr-${var.cluster_name}"
  resource_group_name = data.azurerm_resource_group.lab.name
  location            = var.location
  kind                = "Linux"

  data_sources {
    extension {
      name           = "ContainerInsightsExtension"
      extension_name = "ContainerInsights"
      streams        = ["Microsoft-ContainerLogV2", "Microsoft-KubePodInventory"]

      extension_json = jsonencode({
        dataCollectionSettings = {
          interval               = "5m"
          namespaceFilteringMode = "Include"
          namespaces             = local.log_namespaces
          enableContainerLogV2   = true
        }
      })
    }
  }

  destinations {
    log_analytics {
      name                  = "workspace"
      workspace_resource_id = local.workspace_id
    }
  }

  data_flow {
    streams      = ["Microsoft-ContainerLogV2", "Microsoft-KubePodInventory"]
    destinations = ["workspace"]
  }

  tags = var.tags
}

resource "azurerm_monitor_data_collection_rule_association" "container_logs" {
  name                    = "dcra-container-logs"
  target_resource_id      = azurerm_kubernetes_cluster.this.id
  data_collection_rule_id = azurerm_monitor_data_collection_rule.container_logs.id
}

# The agent's identity publishes its own health metrics on the cluster.
resource "azurerm_role_assignment" "oms_agent_metrics" {
  scope                            = azurerm_kubernetes_cluster.this.id
  role_definition_name             = "Monitoring Metrics Publisher"
  principal_id                     = azurerm_kubernetes_cluster.this.oms_agent[0].oms_agent_identity[0].object_id
  principal_type                   = "ServicePrincipal"
  skip_service_principal_aad_check = true
}

# ---------------------------------------------------------------- alerts

resource "azurerm_monitor_action_group" "owner" {
  name                = "ag-assume-hijacked"
  resource_group_name = data.azurerm_resource_group.lab.name
  short_name          = "ah-alerts"

  email_receiver {
    name                    = "owner"
    email_address           = var.alert_email
    use_common_alert_schema = true
  }

  tags = var.tags
}

resource "azurerm_monitor_scheduled_query_rules_alert_v2" "this" {
  for_each = local.alert_rules

  name                = "alert-${each.key}"
  resource_group_name = data.azurerm_resource_group.lab.name
  location            = var.location
  description         = each.value.description
  severity            = each.value.severity
  scopes              = [local.workspace_id]

  # 15 minutes: the cheapest evaluation frequency that still catches an incident in a session.
  evaluation_frequency = "PT15M"
  window_duration      = "PT15M"

  # Tables appear only after the first record arrives, so creation must not fail on an
  # unknown table.
  skip_query_validation   = true
  auto_mitigation_enabled = true

  criteria {
    query                   = each.value.query
    time_aggregation_method = "Total"
    metric_measure_column   = each.value.column
    operator                = each.value.operator
    threshold               = each.value.threshold

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  action {
    action_groups = [azurerm_monitor_action_group.owner.id]
  }

  tags = var.tags
}
