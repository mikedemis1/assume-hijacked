#!/bin/sh
# terraform destroy for infra/lab, then infra/net, as ci-apply, on main, started by hand, from the
# destroy plans that tf-destroy-plan of the SAME pipeline saved (plans/destroy/). It never plans.
# Only what those two stacks created goes. Never infra/base (state storage, registry, Key Vaults,
# CI identities, budgets) and never the resource groups rg-net and rg-lab: base creates them
# empty and the two stacks only read them. Before anything is destroyed the job looks at both
# states again: a managed resource group, or a state it cannot read, stops it.
. ci/tf-common.sh

need_terraform
azure_env apply
for stack in $DESTROY_STACKS; do
    require_plan destroy "$stack"
done

for stack in $DESTROY_STACKS; do
    echo "== check $stack"
    tf_init "$stack"
    refuse_managed_resource_groups "$stack"
done

for stack in $DESTROY_STACKS; do
    echo "== destroy $stack"
    terraform -chdir="$stack" apply -input=false -lock-timeout=5m -no-color "$PWD/$PLANS/destroy/$(basename "$stack").tfplan"
done
