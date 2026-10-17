#!/bin/sh
# terraform plan for infra/net and infra/lab as ci-plan (Reader on the subscription, Storage Blob
# Data Reader on the state), on any branch. Why not infra/base: see ci/tf-common.sh.
# -lock=false: ci-plan can read the state blob but not write its lease; a plan changes nothing.
# A plan of infra/lab reads the net state as it was last applied, so a net change that is only
# on this branch shows up in the net plan, not yet in the lab plan.
. ci/tf-common.sh

need_terraform
azure_env plan
for stack in $PLAN_STACKS; do
    echo "== plan $stack"
    tf_init "$stack"
    set -- -input=false -lock=false -no-color
    for arg in $(tf_vars "$stack"); do
        set -- "$@" "$arg"
    done
    terraform -chdir="$stack" plan "$@"
done
