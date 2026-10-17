# Budgets are a smoke alarm, not a brake: they notify, they do not stop spending,
# and cost data arrives 8-24 hours late. Amounts are in the billing currency (EUR).

locals {
  budgets = {
    soft = { name = "budget-monthly-soft", amount = var.budget_soft_amount }
    hard = { name = "budget-monthly-hard", amount = var.budget_hard_amount }
  }
}

resource "azurerm_consumption_budget_subscription" "monthly" {
  for_each = local.budgets

  name            = each.value.name
  subscription_id = local.subscription_scope
  amount          = each.value.amount
  time_grain      = "Monthly"

  time_period {
    start_date = var.budget_start_date
  }

  # Money already spent: warn at 50 % and 100 %.
  dynamic "notification" {
    for_each = [50, 100]
    content {
      enabled        = true
      threshold      = notification.value
      threshold_type = "Actual"
      operator       = "GreaterThanOrEqualTo"
      contact_emails = var.budget_notification_emails
    }
  }

  # Money Azure expects to be spent by the end of the month: warn at 100 %.
  notification {
    enabled        = true
    threshold      = 100
    threshold_type = "Forecasted"
    operator       = "GreaterThanOrEqualTo"
    contact_emails = var.budget_notification_emails
  }
}
