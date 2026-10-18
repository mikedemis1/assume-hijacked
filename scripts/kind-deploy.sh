#!/bin/sh
# Build the application image from this tree, push it to the local registry and install or
# upgrade the chart on the kind cluster "ah", by digest. Run from the repository root with Git
# Bash, cluster up (sh scripts/kind-up.sh):
#
#   sh scripts/kind-deploy.sh         build, push, helm upgrade --install, wait for every pod
#   sh scripts/kind-deploy.sh reset   uninstall the release and delete the database volume
#
# Running it again applies what changed: the same code gives the same image digest, the same
# Secrets are read back from the cluster, and helm upgrades only what differs.
#
# Why a registry and a digest: the admission policy admits images only by digest from
# localhost:5001/, and a locally built image has no registry digest until it is pushed
# (scripts/kind-registry.sh). Loading the image straight into the nodes would leave it
# without one.
#
# Secrets: the passwords of the database roles and the gateway's signing key are generated here
# on the first install (random, never written to the repository) and read back from the cluster's
# Secrets on every later run, because the database keeps the passwords it was set up with.
#
# Order: helm runs with --wait=hookOnly. It waits for the database setup Job (a post-install
# hook) but not for the pods, and this script then waits for every rollout. With --wait, Helm
# would wait for pods that need the database before it runs the Job that sets the database up.
set -eu

CLUSTER=ah
CONTEXT=kind-$CLUSTER
RELEASE=ah
RELEASE_NAMESPACE=default
CHART=deploy/helm/assume-hijacked
PUSH=127.0.0.1:5001/assume-hijacked
PULL=localhost:5001/assume-hijacked
# Every database login role (the chart's ah.dbRoles).
DB_ROLES="tool_read_ticket tool_lookup_account tool_request_disconnection tool_issue_bill_credit
tool_set_temp_protection executor approver gateway risk_engine dispatcher register_sync"

# Git Bash on Windows: do not rewrite container-side paths.
if command -v cygpath >/dev/null 2>&1; then
    export MSYS_NO_PATHCONV=1
fi

k() {
    kubectl --context "$CONTEXT" "$@"
}

h() {
    helm --kube-context "$CONTEXT" --namespace "$RELEASE_NAMESPACE" "$@"
}

release_exists() {
    h status "$RELEASE" >/dev/null 2>&1
}

database_volume_exists() {
    k --namespace ah-data get pvc data-postgres-0 >/dev/null 2>&1
}

if [ "${1:-}" = "reset" ]; then
    if release_exists; then
        h uninstall "$RELEASE" --wait --timeout 5m
    fi
    k --namespace ah-data delete pvc data-postgres-0 --ignore-not-found --wait=true
    echo "release $RELEASE and the database volume are gone; run sh scripts/kind-deploy.sh"
    exit 0
elif [ -n "${1:-}" ]; then
    echo "usage: sh scripts/kind-deploy.sh [reset]" >&2
    exit 2
fi

# The database setup runs on the first install only (db/init/init.sh is not idempotent). A
# database volume left from an earlier release would make it fail on roles that exist, with
# passwords this run does not know.
if ! release_exists && database_volume_exists; then
    echo "a database volume from an earlier release exists (ah-data/data-postgres-0) but release" \
         "$RELEASE does not: run sh scripts/kind-deploy.sh reset first" >&2
    exit 1
fi

k get --raw /version >/dev/null
sh scripts/kind-registry.sh >/dev/null

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
chmod 700 "$work"
# Native Windows programs (helm.exe, openssl) do not understand Git Bash's /tmp: hand them a
# Windows path.
native_work=$work
if command -v cygpath >/dev/null 2>&1; then
    native_work=$(cygpath -m "$work")
fi

# --- the image -----------------------------------------------------------------------------------
# The same build inputs as Compose: an optional CA bundle for TLS-intercepting networks
# (PIP_CERT_FILE) and an optional folder of wheels (LOCAL_WHEELS_DIR), both from .env. Only these
# two lines are read; the passwords in .env are for Compose and are not used here.
env_setting() {
    [ -f .env ] || return 0
    sed -n "s/^$1=//p" .env | tr -d '\r' | tail -n 1
}
pip_cert=$(env_setting PIP_CERT_FILE)
wheels=$(env_setting LOCAL_WHEELS_DIR)
# No provenance attestation: it carries the build time, so every build would get a new digest
# and every run would restart every pod.
docker build --quiet --provenance=false \
    --build-context "wheels=${wheels:-build/empty}" \
    --secret "id=pip_cert,src=${pip_cert:-build/no-pip-cert.empty}" \
    -t "$PUSH:dev" . >/dev/null
docker push --quiet "$PUSH:dev" >/dev/null
digest=$(docker inspect -f '{{range .RepoDigests}}{{println .}}{{end}}' "$PUSH:dev" \
    | grep "^$PUSH@" | head -n 1 | cut -d @ -f 2)
if [ -z "$digest" ]; then
    echo "no registry digest for $PUSH:dev after the push" >&2
    exit 1
fi
image="$PULL@$digest"
echo "image $image"

# --- the secrets ---------------------------------------------------------------------------------
# One value of a Secret the chart created, or nothing.
secret_value() {  # secret_value <namespace> <secret> <key>
    key=$(printf '%s' "$3" | sed 's/\./\\./g')
    k --namespace "$1" get secret "$2" -o "jsonpath={.data.$key}" 2>/dev/null | base64 -d 2>/dev/null || true
}

new_password() {
    openssl rand -hex 24
}

postgres_password=$(secret_value ah-data postgres-secrets POSTGRES_PASSWORD)
[ -n "$postgres_password" ] || postgres_password=$(new_password)
{
    echo "secrets:"
    echo "  postgresPassword: \"$postgres_password\""
    echo "  dbPasswords:"
    for role in $DB_ROLES; do
        upper=$(printf '%s' "$role" | tr '[:lower:]' '[:upper:]')
        password=$(secret_value ah-data postgres-secrets "DB_PASSWORD_$upper")
        [ -n "$password" ] || password=$(new_password)
        echo "    $role: \"$password\""
    done
} > "$work/secrets.yaml"

# The gateway's ES256 key pair (EC P-256): the private half signs the per-tool tokens, the public
# half goes to the tools. Generated once, then read back.
secret_value ah-gateway tool-gateway-secrets signing-key.pem > "$work/signing-key.pem"
if [ ! -s "$work/signing-key.pem" ]; then
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$native_work/signing-key.pem"
fi
openssl pkey -in "$native_work/signing-key.pem" -pubout -out "$native_work/public-key.pem"

# --- the chart -----------------------------------------------------------------------------------
# db/init/init.sh and every db/sql file, so the chart's ConfigMaps hold exactly the files in db/.
set -- --set-file "dbFiles.initSh=db/init/init.sh"
for file in db/sql/*.sql; do
    set -- "$@" --set-file "dbFiles.sql.$(basename "$file" .sql)=$file"
done
# Components without their code in this tree run the ops stand-in while this file exists.
if [ -f "$CHART/values-kind-stubs.yaml" ]; then
    set -- "$@" -f "$CHART/values-kind-stubs.yaml"
fi

h upgrade --install "$RELEASE" "$CHART" \
    -f "$CHART/values-kind.yaml" \
    -f "$native_work/secrets.yaml" \
    --set-file "secrets.gatewaySigningKeyPem=$native_work/signing-key.pem" \
    --set-file "gateway.publicKeyPem=$native_work/public-key.pem" \
    --set "images.app=$image" \
    "$@" \
    --wait=hookOnly --timeout 10m

# --- wait for every pod --------------------------------------------------------------------------
k --namespace ah-data rollout status statefulset/postgres --timeout=300s
for deployment in $(k get deployments --all-namespaces -l app.kubernetes.io/part-of=assume-hijacked \
        -o 'jsonpath={range .items[*]}{.metadata.namespace}/{.metadata.name}{" "}{end}'); do
    k --namespace "${deployment%%/*}" rollout status "deployment/${deployment#*/}" --timeout=300s
done
k get pods --all-namespaces -l app.kubernetes.io/part-of=assume-hijacked
echo "release $RELEASE is deployed with $image"
