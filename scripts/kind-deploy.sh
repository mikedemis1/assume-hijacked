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
# Secrets on every later run, because the database keeps the passwords it was set up with. While
# the release exists every read must succeed: a failed read never turns into new passwords.
# Helm keeps each revision's values, these secrets included, in a Secret
# sh.helm.release.v1.<release>.v<n> in the release namespace (default), readable by anyone who can
# read Secrets there; --history-max keeps only the last few revisions.
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
tool_set_temp_protection executor approver gateway risk_engine dispatcher demo_portal demo_ops"

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

# What the release is: "deployed" (a revision completed, so the database is set up),
# "failed-install" (it exists, but no revision ever completed: the first install's database setup
# failed or was cut off) or "none". Any other answer from helm stops the script.
release_state() {
    if out=$(h history "$RELEASE" -o json 2>&1); then
        case "$out" in
            *'"status":"deployed"'* | *'"status":"superseded"'*) echo deployed ;;
            *) echo failed-install ;;
        esac
    else
        case "$out" in
            *"release: not found"*) echo none ;;
            *)
                echo "helm cannot read release $RELEASE: $out" >&2
                return 1
                ;;
        esac
    fi
}

# Whether the database volume exists. Any error but NotFound stops the script.
database_volume_exists() {
    if out=$(k --namespace ah-data get pvc data-postgres-0 -o name 2>&1); then
        return 0
    fi
    case "$out" in
        *NotFound* | *"not found"*) return 1 ;;
    esac
    echo "kubectl cannot check the database volume: $out" >&2
    exit 1
}

k get --raw /version >/dev/null
state=$(release_state)

if [ "${1:-}" = "reset" ]; then
    if [ "$state" != none ]; then
        h uninstall "$RELEASE" --wait --timeout 5m
    fi
    k --namespace ah-data delete pvc data-postgres-0 --ignore-not-found --wait=true
    echo "release $RELEASE and the database volume are gone; run sh scripts/kind-deploy.sh"
    exit 0
elif [ -n "${1:-}" ]; then
    echo "usage: sh scripts/kind-deploy.sh [reset]" >&2
    exit 2
fi

# The database setup runs on the first install only (db/init/init.sh is not idempotent), so:
#   - a first install whose setup failed is never upgraded (the pods would crash-loop on a
#     database that was never set up), and
#   - a database volume left from an earlier release would make the setup fail on roles that
#     exist, with passwords this run does not know.
if [ "$state" = failed-install ]; then
    echo "release $RELEASE never completed its first install (the database setup failed or was" \
         "cut off): run sh scripts/kind-deploy.sh reset, then deploy again" >&2
    exit 1
fi
if [ "$state" = none ] && database_volume_exists; then
    echo "a database volume from an earlier release exists (ah-data/data-postgres-0) but release" \
         "$RELEASE does not: run sh scripts/kind-deploy.sh reset first" >&2
    exit 1
fi

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
# The build inputs: an optional CA bundle for TLS-intercepting networks
# (PIP_CERT_FILE) and an optional folder of wheels (LOCAL_WHEELS_DIR), both from .env. Only these
# two lines are read; the other settings in .env are not used here.
env_setting() {
    [ -f .env ] || return 0
    sed -n "s/^$1=//p" .env | tr -d '\r' | tail -n 1
}
pip_cert=$(env_setting PIP_CERT_FILE)
wheels=$(env_setting LOCAL_WHEELS_DIR)
# No provenance attestation: it carries the build time, so every build would get a new digest
# and every run would restart every pod.
docker build --quiet --provenance=false \
    --build-context "wheels=${wheels:-scripts/build/empty}" \
    --secret "id=pip_cert,src=${pip_cert:-scripts/build/no-pip-cert.empty}" \
    -t "$PUSH:dev" . >/dev/null
docker push --quiet "$PUSH:dev" >/dev/null
digest=$(docker inspect -f '{{range .RepoDigests}}{{println .}}{{end}}' "$PUSH:dev" \
    | grep "^$PUSH@" | head -n 1 | cut -d @ -f 2)
if [ -z "$digest" ]; then
    echo "no registry digest for $PUSH:dev after the push" >&2
    exit 1
fi
tag=$(git rev-parse --short HEAD)
image="$PULL:$tag@$digest"
echo "image $image"

# --- the secrets ---------------------------------------------------------------------------------
# One value of a Secret of the deployed release. It must be there: a failed or empty read stops
# the script (in a command substitution the exit ends the subshell, and set -e the script).
secret_value() {  # secret_value <namespace> <secret> <key>
    key=$(printf '%s' "$3" | sed 's/\./\\./g')
    if ! encoded=$(k --namespace "$1" get secret "$2" -o "jsonpath={.data.$key}" 2>&1); then
        echo "cannot read $3 from $1/$2 of release $RELEASE: $encoded" >&2
        exit 1
    fi
    if [ -z "$encoded" ]; then
        echo "$1/$2 of release $RELEASE has no $3 (a role added after the database was set up?" \
             "sh scripts/kind-deploy.sh reset starts over)" >&2
        exit 1
    fi
    printf '%s' "$encoded" | base64 -d
}

# A new random value on the first install, else the deployed one.
setting() {  # setting <namespace> <secret> <key>
    if [ "$state" = none ]; then
        openssl rand -hex 24
    else
        secret_value "$@"
    fi
}

postgres_password=$(setting ah-data postgres-secrets POSTGRES_PASSWORD)
{
    echo "secrets:"
    echo "  postgresPassword: \"$postgres_password\""
    echo "  dbPasswords:"
    for role in $DB_ROLES; do
        upper=$(printf '%s' "$role" | tr '[:lower:]' '[:upper:]')
        password=$(setting ah-data postgres-secrets "DB_PASSWORD_$upper")
        echo "    $role: \"$password\""
    done
} > "$work/secrets.yaml"

# The gateway's ES256 key pair (EC P-256): the private half signs the per-tool tokens, the public
# half goes to the tools. Generated on the first install, then read back.
if [ "$state" = none ]; then
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$native_work/signing-key.pem"
else
    secret_value ah-gateway tool-gateway-secrets signing-key.pem > "$work/signing-key.pem"
fi
openssl pkey -in "$native_work/signing-key.pem" -pubout -out "$native_work/public-key.pem"

# --- the chart -----------------------------------------------------------------------------------
# db/init/init.sh and every db/sql file, so the chart's ConfigMaps hold exactly the files in db/.
set -- --set-file "dbFiles.initSh=db/init/init.sh"
for file in db/sql/*.sql; do
    set -- "$@" --set-file "dbFiles.sql.$(basename "$file" .sql)=$file"
done
# The real model, only when asked: LLM_BACKEND=anthropic ANTHROPIC_KEY_FILE=<one-line key file>.
# The armed demo attack stays scripted (llm.simulatedHijack). Without LLM_BACKEND: scripted, no key.
if [ "${LLM_BACKEND:-scripted}" = anthropic ]; then
    if [ -z "${ANTHROPIC_KEY_FILE:-}" ] || [ ! -f "$ANTHROPIC_KEY_FILE" ]; then
        echo "LLM_BACKEND=anthropic needs ANTHROPIC_KEY_FILE to name an existing key file" >&2
        exit 1
    fi
    native_key=$ANTHROPIC_KEY_FILE
    if command -v cygpath >/dev/null 2>&1; then
        native_key=$(cygpath -m "$ANTHROPIC_KEY_FILE")
    fi
    set -- "$@" --set llm.backend=anthropic --set llm.simulatedHijack=true \
        --set-file "secrets.anthropicApiKey=$native_key"
elif [ "${LLM_BACKEND:-scripted}" != scripted ]; then
    echo "LLM_BACKEND must be scripted or anthropic" >&2
    exit 1
fi
h upgrade --install "$RELEASE" "$CHART" \
    -f "$CHART/values-kind.yaml" \
    -f "$native_work/secrets.yaml" \
    --set-file "secrets.gatewaySigningKeyPem=$native_work/signing-key.pem" \
    --set-file "gateway.publicKeyPem=$native_work/public-key.pem" \
    --set "images.app=$image" \
    "$@" \
    --history-max 3 --wait=hookOnly --timeout 10m

# --- wait for every pod --------------------------------------------------------------------------
k --namespace ah-data rollout status statefulset/postgres --timeout=300s
for deployment in $(k get deployments --all-namespaces -l app.kubernetes.io/part-of=assume-hijacked \
        -o 'jsonpath={range .items[*]}{.metadata.namespace}/{.metadata.name}{" "}{end}'); do
    k --namespace "${deployment%%/*}" rollout status "deployment/${deployment#*/}" --timeout=300s
done
k get pods --all-namespaces -l app.kubernetes.io/part-of=assume-hijacked
echo "release $RELEASE is deployed with $image"
