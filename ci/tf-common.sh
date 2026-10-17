# Shared by ci/tf-plan.sh, ci/tf-apply.sh, ci/tf-destroy.sh and ci/leftover-check.sh. Sourced, not
# run: `. ci/tf-common.sh`. These scripts run in the manual Azure jobs only (.gitlab-ci.yml,
# stage azure). They never run on a PC: they need the OIDC token that GitLab hands to the job.
#
# Authentication: no secret is stored anywhere. GitLab signs a short-lived ID token for the job
# (id_tokens, audience api://AzureADTokenExchange), Entra checks it against the federated
# credential of the CI app (infra/base/ci-identities.tf) and returns an Azure token.
#   ci-plan   any branch   Reader + state blob reader     tf-plan, leftover-check
#   ci-apply  main only    Contributor on rg-net/rg-lab   tf-apply, tf-destroy
# terraform reads the token from ARM_OIDC_TOKEN (provider and azurerm backend):
# https://developer.hashicorp.com/terraform/language/backend/azurerm
#
# What CI manages: infra/net, then infra/lab. infra/base is NOT managed from CI, on purpose:
#   - it holds the CI identities themselves and the role assignments they may use, so a job that
#     could apply it could widen its own rights;
#   - it needs Microsoft Graph rights (Entra applications) that neither CI identity has, so even
#     a plan would fail;
#   - it is applied rarely, by the owner, from a PC. Every push still runs fmt, validate,
#     `terraform test`, tflint and checkov on it (ci/iac.sh).
# Order matters: infra/lab reads the states of base and net, so net is applied before lab and
# destroyed after it.
. ci/lib.sh

APPLY_STACKS="infra/net infra/lab"
DESTROY_STACKS="infra/lab infra/net"
# Saved plans, passed between jobs of one pipeline as GitLab artifacts: plans/apply/<stack>.tfplan
# (+ .txt to read, .changes yes|no) from tf-plan, plans/destroy/... from tf-destroy-plan.
PLANS=plans

die() {
    echo "$*" >&2
    exit 1
}

# azure_env <plan|apply>: check the job's inputs and export the settings terraform and az read.
azure_env() {
    identity=$1
    [ "${AZURE_ENABLED:-}" = "true" ] || die "AZURE_ENABLED is not true: this job does nothing until it is"
    [ -n "${AZURE_ID_TOKEN:-}" ] || die "no AZURE_ID_TOKEN: the job needs id_tokens with aud api://AzureADTokenExchange"
    case "$identity" in
        plan) client_id="${AZURE_CI_PLAN_CLIENT_ID:-}" ;;
        apply)
            client_id="${AZURE_CI_APPLY_CLIENT_ID:-}"
            # ci-apply only trusts main (federated credential), so Entra would refuse anyway;
            # this says why in plain words before any terraform runs.
            [ "${CI_COMMIT_BRANCH:-}" = "${CI_DEFAULT_BRANCH:-main}" ] \
                || die "apply and destroy run on the default branch only (ci-apply trusts main)"
            ;;
        *) die "azure_env: plan or apply" ;;
    esac
    [ -n "$client_id" ] || die "AZURE_CI_$(printf '%s' "$identity" | tr a-z A-Z)_CLIENT_ID is not set"
    [ -n "${AZURE_TENANT_ID:-}" ] || die "AZURE_TENANT_ID is not set"
    [ -n "${AZURE_SUBSCRIPTION_ID:-}" ] || die "AZURE_SUBSCRIPTION_ID is not set"
    export ARM_USE_OIDC=true ARM_USE_AZUREAD=true ARM_OIDC_TOKEN="$AZURE_ID_TOKEN"
    export ARM_CLIENT_ID="$client_id" ARM_TENANT_ID="$AZURE_TENANT_ID"
    export ARM_SUBSCRIPTION_ID="$AZURE_SUBSCRIPTION_ID"
    export TF_VAR_subscription_id="$AZURE_SUBSCRIPTION_ID" TF_VAR_tenant_id="$AZURE_TENANT_ID"
    export TF_IN_AUTOMATION=true TF_INPUT=0
}

# tf_init <stack>: init against the azurerm backend. The stacks keep their backend block
# commented out until the owner has migrated the state (infra/*/versions.tf), so the job writes
# an override file with an empty azurerm backend and passes the settings on the command line.
# `*_override.tf` is ignored by git. -lockfile=readonly: the committed lock file decides which
# provider versions are used.
tf_init() {
    stack=$1
    account="${TF_STATE_STORAGE_ACCOUNT:-}"
    [ -n "$account" ] || die "TF_STATE_STORAGE_ACCOUNT is not set (output state_storage_account_name of infra/base)"
    printf 'terraform {\n  backend "azurerm" {}\n}\n' >"$stack/zz_backend_override.tf"
    TF_VAR_state_storage_account_name="$account"
    export TF_VAR_state_storage_account_name
    terraform -chdir="$stack" init -input=false -lockfile=readonly -reconfigure \
        -backend-config="resource_group_name=${TF_STATE_RESOURCE_GROUP:-rg-base}" \
        -backend-config="storage_account_name=$account" \
        -backend-config="container_name=${TF_STATE_CONTAINER:-tfstate}" \
        -backend-config="key=$(basename "$stack").tfstate" \
        -backend-config="use_azuread_auth=true" \
        -backend-config="use_oidc=true"
}

# tf_vars <stack>: -var-file argument from the File-type CI/CD variable TFVARS_<STACK> (the
# values that stay out of git: address ranges, e-mail address, admin group). Prints nothing if
# the variable is not set; terraform then fails on the missing inputs.
tf_vars() {
    name="TFVARS_$(basename "$1" | tr a-z A-Z)"
    eval "path=\${$name:-}"
    if [ -n "$path" ]; then
        printf '%s\n' "-var-file=$path"
    fi
}

# These jobs only run in CI, in the Terraform image. A PC without terraform stops here.
need_terraform() {
    if ! in_tool_image && ! command -v terraform >/dev/null 2>&1; then
        die "terraform is not installed; this job runs in CI, in $TERRAFORM_IMAGE"
    fi
}

# plan_stack <apply|destroy> <stack> [extra plan arguments]: plan without a lock (ci-plan can read
# the state but not write its lease), save the plan file and a readable copy under plans/<kind>/,
# print it, and record whether it changes anything. The apply and destroy jobs run these files and
# never plan again, so what a person read in the plan job is what runs.
plan_stack() {
    kind=$1
    stack=$2
    shift 2
    name=$(basename "$stack")
    dir="$PWD/$PLANS/$kind"
    mkdir -p "$dir"
    set -- -input=false -lock=false -no-color -detailed-exitcode -out="$dir/$name.tfplan" "$@"
    for arg in $(tf_vars "$stack"); do
        set -- "$@" "$arg"
    done
    rc=0
    terraform -chdir="$stack" plan "$@" || rc=$?
    case "$rc" in
        0) changes=no ;;
        2) changes=yes ;;
        *) die "terraform plan failed for $stack (exit code $rc)" ;;
    esac
    terraform -chdir="$stack" show -no-color "$dir/$name.tfplan" >"$dir/$name.txt"
    cat "$dir/$name.txt"
    echo "$changes" >"$dir/$name.changes"
    echo "${CI_COMMIT_SHA:-unknown}" >"$dir/commit"
}

# require_plan <apply|destroy> <stack>: the saved plan must exist and come from this commit.
require_plan() {
    file="$PLANS/$1/$(basename "$2").tfplan"
    [ -f "$file" ] || die "no saved plan for $2 ($file): run the plan job of this pipeline first"
    [ "$(cat "$PLANS/$1/commit" 2>/dev/null)" = "${CI_COMMIT_SHA:-unknown}" ] \
        || die "the saved plan for $2 was made for another commit"
}

# refuse_managed_resource_groups <stack>: infra/net and infra/lab only read rg-net and rg-lab (infra/base
# creates them empty), so a resource group among the resources a stack manages means destroy would
# delete it. A state that cannot be read stops the job too: an unreadable list is not an empty one.
# Data sources (data.azurerm_resource_group...) are fine; module-nested groups are caught.
refuse_managed_resource_groups() {
    list=$(terraform -chdir="$1" state list) || die "could not read the state of $1; refusing to go on"
    if echo "$list" | grep -E '(^|\.)azurerm_resource_group\.' | grep -vqE '(^|\.)data\.azurerm_resource_group\.'; then
        die "$1 manages a resource group; destroying it would remove the group. Refusing."
    fi
}
