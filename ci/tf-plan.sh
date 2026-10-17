#!/bin/sh
# terraform plan for infra/net and infra/lab as ci-plan (Reader on the subscription, Storage Blob
# Data Reader on the state), on any branch. Why not infra/base: see ci/tf-common.sh.
# Each plan is saved under plans/apply/ (the plan file, a readable .txt and a .changes marker) and
# kept as a job artifact: tf-apply runs exactly these files and never plans again, so the plan
# you read here is the plan that runs. A plan of infra/lab reads the net state as it was last
# applied; tf-apply handles a net change that lands first (see ci/tf-apply.sh).
. ci/tf-common.sh

need_terraform
azure_env plan
for stack in $APPLY_STACKS; do
    echo "== plan $stack"
    tf_init "$stack"
    plan_stack apply "$stack"
done
