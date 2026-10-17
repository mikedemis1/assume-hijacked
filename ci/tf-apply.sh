#!/bin/sh
# terraform apply for infra/net, then infra/lab, as ci-apply, on main, started by hand.
# Each stack: plan to a file, apply exactly that file. The plan the job prints is what runs; a
# change that appears between the two steps is not applied. Why not infra/base: ci/tf-common.sh.
# The lab bills by the hour (AKS nodes, firewall, PostgreSQL): tf-destroy takes it down again
# and leftover-check proves it (docs/pipeline.md, "Azure jobs").
. ci/tf-common.sh

need_terraform
azure_env apply
for stack in $APPLY_STACKS; do
    echo "== apply $stack"
    tf_init "$stack"
    set -- -input=false -lock-timeout=5m -no-color -out=tfplan
    for arg in $(tf_vars "$stack"); do
        set -- "$@" "$arg"
    done
    terraform -chdir="$stack" plan "$@"
    terraform -chdir="$stack" apply -input=false -lock-timeout=5m -no-color tfplan
    rm -f "$stack/tfplan"
done
