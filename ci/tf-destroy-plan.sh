#!/bin/sh
# What tf-destroy would remove: `terraform plan -destroy` for infra/lab, then infra/net, as
# ci-plan, saved under plans/destroy/ as a job artifact (plan file, readable .txt) for tf-destroy
# of the same pipeline to run. Read the .txt (it is also in the job log) before you start
# tf-destroy. Never infra/base, and never the resource groups: base creates rg-net and rg-lab
# empty and the two stacks only read them, so a state that manages a group stops the job.
. ci/tf-common.sh

need_terraform
azure_env plan
for stack in $DESTROY_STACKS; do
    echo "== destroy plan $stack"
    tf_init "$stack"
    refuse_managed_resource_groups "$stack"
    plan_stack destroy "$stack" -destroy
done
