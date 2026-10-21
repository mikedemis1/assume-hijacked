#!/bin/sh
# Install the chart on the AKS cluster of infra/lab: the image into ACR, the Terraform outputs into
# Helm values, then helm install. Run from the repo root in Git Bash, after both stacks are applied:
#   CONSOLE_CLIENT_ID=<console app id> sh scripts/azure-deploy.sh
#   LLM_BACKEND=anthropic ANTHROPIC_KEY_FILE=<key file> CONSOLE_CLIENT_ID=... sh scripts/azure-deploy.sh
# Needs az login, Docker, kubectl on the cluster (az aks get-credentials, then kubelogin), and
# "Key Vault Secrets Officer" for the caller on the vaults (it writes the gateway key).
set -eu

CHART=deploy/helm/assume-hijacked
RELEASE=ah
CONSOLE_REDIRECT=${CONSOLE_REDIRECT:-https://localhost:8443/auth/callback}
: "${CONSOLE_CLIENT_ID:?set CONSOLE_CLIENT_ID to the console app registration's application id}"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
chmod 700 "$work"
native_work=$work
if command -v cygpath >/dev/null 2>&1; then
    native_work=$(cygpath -m "$work")
fi

terraform -chdir=infra/base output -json > "$work/base.json"
# LAB_OUTPUTS: a saved copy of `terraform output -json` for infra/lab, for when its state is locked.
if [ -n "${LAB_OUTPUTS:-}" ]; then
    cp "$LAB_OUTPUTS" "$work/lab.json"
else
    terraform -chdir=infra/lab output -json > "$work/lab.json"
fi
output() {  # output <base|lab> <name> [key]: one output, or one key of a map output
    python -c "import json,sys; v=json.load(open(sys.argv[1]))[sys.argv[2]]['value']; print(v[sys.argv[3]] if len(sys.argv)>3 else v)" \
        "$native_work/$1.json" "$2" ${3:+"$3"}
}
acr=$(output base acr_name)
login=$(output base acr_login_server)

# --- images: ours built and pushed, the two upstream ones imported (ACR keeps their digest) ------
env_setting() {  # the same two optional build inputs as kind-deploy.sh, from .env
    [ -f .env ] || return 0
    sed -n "s/^$1=//p" .env | tr -d '\r' | tail -n 1
}
pip_cert=$(env_setting PIP_CERT_FILE)
wheels=$(env_setting LOCAL_WHEELS_DIR)
# A token instead of `az acr login`, which needs the Docker CLI to be found by az.
az acr login --name "$acr" --expose-token --query accessToken -o tsv \
    | docker login "$login" -u 00000000-0000-0000-0000-000000000000 --password-stdin >/dev/null
# SOURCE_IMAGE reuses an image already built from this commit (the one kind runs), else build.
if [ -n "${SOURCE_IMAGE:-}" ]; then
    docker tag "$SOURCE_IMAGE" "$login/assume-hijacked:dev"
else
    docker build --quiet --provenance=false \
        --build-context "wheels=${wheels:-scripts/build/empty}" \
        --secret "id=pip_cert,src=${pip_cert:-scripts/build/no-pip-cert.empty}" \
        -t "$login/assume-hijacked:dev" . >/dev/null
fi
docker push --quiet "$login/assume-hijacked:dev" >/dev/null
digest=$(docker inspect -f '{{range .RepoDigests}}{{println .}}{{end}}' "$login/assume-hijacked:dev" \
    | grep "^$login/assume-hijacked@" | head -n 1 | cut -d @ -f 2)
image="$login/assume-hijacked:$(git rev-parse --short HEAD)@$digest"
postgres_digest=$(sed -n 's/^  postgres: .*@\(sha256:[0-9a-f]*\)$/\1/p' "$CHART/values-azure.yaml")
# Imported once: Docker Hub rate-limits anonymous pulls, and a second import gains nothing.
az acr repository show --name "$acr" --image postgres:17-alpine >/dev/null 2>&1 ||
    az acr import --name "$acr" --source "docker.io/library/postgres@$postgres_digest" --image postgres:17-alpine >/dev/null
az acr repository show --name "$acr" --image azure-cli:latest >/dev/null 2>&1 ||
    az acr import --name "$acr" --source mcr.microsoft.com/azure-cli:latest --image azure-cli:latest >/dev/null
cli_digest=$(az acr repository show --name "$acr" --image azure-cli:latest --query digest -o tsv)
echo "image $image"

# --- secrets that nothing else writes ----------------------------------------------------------
# The gateway's ES256 key pair: the private half into the tool-gateway vault, the public half to the tools.
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$native_work/signing-key.pem"
openssl pkey -in "$native_work/signing-key.pem" -pubout -out "$native_work/public-key.pem"
az keyvault secret set --vault-name "$(output lab component_key_vaults tool-gateway)" \
    --name gateway-signing-key --file "$native_work/signing-key.pem" >/dev/null
set --
if [ "${LLM_BACKEND:-scripted}" = anthropic ]; then
    az keyvault secret set --vault-name "$(output lab component_key_vaults llm-gateway)" \
        --name anthropic-api-key --file "$ANTHROPIC_KEY_FILE" >/dev/null
    set -- --set llm.backend=anthropic --set llm.simulatedHijack=true
fi

# --- values from the Terraform outputs (JSON is valid YAML) --------------------------------------
python - "$native_work" "$login" "$image" "$postgres_digest" "$cli_digest" "$CONSOLE_CLIENT_ID" "$CONSOLE_REDIRECT" <<'EOF'
import json, sys
work, login, image, pg, cli, console_id, redirect = sys.argv[1:]
lab = {k: v["value"] for k, v in json.load(open(f"{work}/lab.json")).items()}
values = {
    "registry": f"{login}/",
    "images": {"app": image, "postgres": f"{login}/postgres:17-alpine@{pg}", "azureCli": f"{login}/azure-cli@{cli}"},
    "db": {"host": lab["postgres_host"]},
    "azure": {"tenantId": lab["tenant_id"], "dbAdmin": lab["postgres_entra_admin"],
              "clientIds": lab["workload_client_ids"], "keyVaults": lab["component_key_vaults"]},
    "console": {"redirectUri": redirect, "entra": {"tenantId": lab["tenant_id"], "clientId": console_id}},
    "demo": {"enabled": True},
}
json.dump(values, open(f"{work}/install.json", "w"), indent=2)
EOF

# The VNet's DNS suffix that AKS adds to every pod's search list (chart network.podSearchDomain).
cluster=$(output lab cluster_name)
node_rg=$(az aks list --query "[?name=='$cluster'].nodeResourceGroup | [0]" -o tsv)
vmss=$(az vmss list -g "$node_rg" --query "[0].name" -o tsv)
search_domain=$(az vmss nic list -g "$node_rg" --vmss-name "$vmss" --query "[0].dnsSettings.internalDomainNameSuffix" -o tsv)
set -- "$@" --set "network.podSearchDomain=$search_domain"

for file in db/sql/*.sql; do
    set -- "$@" --set-file "dbFiles.sql.$(basename "$file" .sql)=$file"
done
helm upgrade --install "$RELEASE" "$CHART" \
    -f "$CHART/values-azure.yaml" -f "$native_work/install.json" \
    --set-file "gateway.publicKeyPem=$native_work/public-key.pem" \
    --set-file "dbFiles.initSh=db/init/init.sh" \
    "$@" --history-max 3 --wait=hookOnly --timeout 15m

for deployment in $(kubectl get deployments --all-namespaces -l app.kubernetes.io/part-of=assume-hijacked \
        -o 'jsonpath={range .items[*]}{.metadata.namespace}/{.metadata.name}{" "}{end}'); do
    kubectl --namespace "${deployment%%/*}" rollout status "deployment/${deployment#*/}" --timeout=300s || true
done
kubectl get pods --all-namespaces -l app.kubernetes.io/part-of=assume-hijacked
