#!/bin/sh
# terraform apply for infra/net, then infra/lab, as ci-apply, on main, started by hand, from the
# plan files that tf-plan of the SAME pipeline saved (plans/apply/, a job artifact). It never
# plans: what a person read in tf-plan is what runs. A missing plan, a plan from another commit
# or a plan that no longer matches the state (terraform refuses a stale plan) fails the job.
# Why not infra/base: ci/tf-common.sh.
#
# infra/lab reads the net state, and its plan was made before net changed. So if net had changes,
# this job applies net and then stops with an error before lab: run tf-plan again (it now sees
# the new net state), read it, then run tf-apply. The lab bills by the hour (AKS nodes,
# firewall, PostgreSQL): tf-destroy takes it down again and leftover-check proves it.
. ci/tf-common.sh

need_terraform
azure_env apply
for stack in $APPLY_STACKS; do
    require_plan apply "$stack"
done

previous_changed=no
for stack in $APPLY_STACKS; do
    name=$(basename "$stack")
    if [ "$previous_changed" = yes ]; then
        die "$stack was not applied: infra/net changed, so this plan of $stack is out of date. Run tf-plan again, read it, then tf-apply."
    fi
    echo "== apply $stack"
    tf_init "$stack"
    terraform -chdir="$stack" apply -input=false -lock-timeout=5m -no-color "$PWD/$PLANS/apply/$name.tfplan"
    previous_changed=$(cat "$PLANS/apply/$name.changes")
done
