# tflint rules for infra/*. Not run by the pipeline, only by hand; docs: https://github.com/terraform-linters/tflint
#
# The terraform ruleset is bundled with tflint. The azurerm ruleset checks values the provider
# accepts at plan time but Azure refuses at apply time (VM sizes, SKUs, names). Its version is
# pinned here; `tflint --init` downloads it from GitHub and checks its signature.

config {
  # The workload-identity module is a local path; nothing is fetched from a registry.
  call_module_type = "local"
}

plugin "terraform" {
  enabled = true
  preset  = "recommended"
}

plugin "azurerm" {
  enabled = true
  version = "0.32.0"
  source  = "github.com/terraform-linters/tflint-ruleset-azurerm"
}
