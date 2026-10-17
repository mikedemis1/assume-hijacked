#!/bin/sh
# terraform destroy for infra/lab, then infra/net, as ci-apply, on main, started by hand.
# Only what those two stacks created goes. Never infra/base (state storage, registry, Key Vaults,
# CI identities, budgets) and never the resource groups rg-net and rg-lab: base creates them
# empty and the two stacks only read them (ruling R15). Before anything is destroyed, the script
# looks at both states: a managed resource group in either one stops the job.
. ci/tf-common.sh

need_terraform
azure_env apply

for stack in $DESTROY_STACKS; do
    echo "== check $stack"
    tf_init "$stack"
    if terraform -chdir="$stack" state list | grep -q '^azurerm_resource_group\.'; then
        die "$stack manages a resource group; destroy would remove it. Refusing."
    fi
done

for stack in $DESTROY_STACKS; do
    echo "== destroy $stack"
    set -- -destroy -input=false -lock-timeout=5m -no-color -out=destroy.tfplan
    for arg in $(tf_vars "$stack"); do
        set -- "$@" "$arg"
    done
    terraform -chdir="$stack" plan "$@"
    terraform -chdir="$stack" apply -input=false -lock-timeout=5m -no-color destroy.tfplan
    rm -f "$stack/destroy.tfplan"
done
