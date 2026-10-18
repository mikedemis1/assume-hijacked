#!/bin/sh
# Rotate the workload database passwords on AKS. An explicit step, never part of a deploy: a
# helm upgrade does not change the passwords (templates/db-migrate.yaml explains why).
# Run from the repository root, at the commit that is deployed:
#
#   sh scripts/azure-rotate-db-passwords.sh <kube-context> [release]
#
#   1. render the rotation Job (templates/db-passwords-rotate.yaml) from the deployed release's
#      values and run it: every workload role gets a new password, written into its vault
#   2. wait longer than the Secrets Store CSI driver's rotation interval, so every synced Secret
#      holds the new password (the driver refreshes an existing Secret only on that poll)
#   3. restart the Deployments with a database role (label ah/db-role) and wait for them
#
# Between 1 and 3 the running pods keep their open connections but cannot open new ones.
set -eu

if [ $# -lt 1 ]; then
    echo "usage: sh scripts/azure-rotate-db-passwords.sh <kube-context> [release]" >&2
    exit 2
fi
CONTEXT=$1
RELEASE=${2:-ah}
RELEASE_NAMESPACE=${RELEASE_NAMESPACE:-default}
CHART=deploy/helm/assume-hijacked
# The CSI driver's rotation poll interval on the cluster (infra/lab: 2 minutes) and a margin.
CSI_ROTATION_SECONDS=${CSI_ROTATION_SECONDS:-120}
WAIT_SECONDS=$((CSI_ROTATION_SECONDS + 60))

if command -v cygpath >/dev/null 2>&1; then
    export MSYS_NO_PATHCONV=1
fi

k() {
    kubectl --context "$CONTEXT" "$@"
}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
native_work=$work
if command -v cygpath >/dev/null 2>&1; then
    native_work=$(cygpath -m "$work")
fi

job="db-passwords-rotate-$(date -u +%Y%m%d%H%M%S)"
helm --kube-context "$CONTEXT" --namespace "$RELEASE_NAMESPACE" get values "$RELEASE" --all -o yaml \
    > "$work/values.yaml"
helm template "$RELEASE" "$CHART" -f "$native_work/values.yaml" \
    --set dbPasswords.rotationJob=true --set "dbPasswords.rotationJobName=$job" \
    --show-only templates/db-passwords-rotate.yaml > "$work/job.yaml"

# 1. The passwords Job.
k create -f "$work/job.yaml"
while :; do
    state=$(k --namespace ah-core get job "$job" \
        -o 'jsonpath={.status.succeeded}/{.status.failed}')
    case "$state" in
        1/*) break ;;
        */1)
            k --namespace ah-core logs "job/$job" --all-containers >&2 || true
            echo "rotation Job $job failed; the passwords may be half rotated: run it again" >&2
            exit 1
            ;;
    esac
    sleep 5
done
echo "passwords rotated by job/$job"

# 2. Let the CSI driver sync the new passwords into every workload's Secret.
echo "waiting ${WAIT_SECONDS}s (CSI rotation interval ${CSI_ROTATION_SECONDS}s + 60s)"
sleep "$WAIT_SECONDS"

# 3. Restart every pod that logs in to the database, so it reads the new password.
deployments=$(k get deployments --all-namespaces -l ah/db-role \
    -o 'jsonpath={range .items[*]}{.metadata.namespace}/{.metadata.name}{" "}{end}')
for deployment in $deployments; do
    k --namespace "${deployment%%/*}" rollout restart "deployment/${deployment#*/}"
done
for deployment in $deployments; do
    k --namespace "${deployment%%/*}" rollout status "deployment/${deployment#*/}" --timeout=300s
done
echo "workload database passwords rotated"
