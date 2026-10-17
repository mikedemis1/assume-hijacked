#!/bin/sh
# Create (or wake) the local Kubernetes cluster "ah": kind + Cilium + Hubble + the stand-in
# RuntimeClass. Run from the repository root with Git Bash: `sh scripts/kind-up.sh`.
#
#   - No cluster yet: creates it (deploy/kind/cluster.yaml), installs Cilium, applies the
#     RuntimeClass, starts the local registry (scripts/kind-registry.sh) and waits until
#     everything is ready.
#   - Cluster exists but its containers are stopped: starts them and waits.
#   - Cluster is running: checks readiness and applies the RuntimeClass again (idempotent).
#
# Stopping to free memory for the Compose stack:  sh scripts/kind-down.sh stop
# Deleting the cluster:                           sh scripts/kind-down.sh
set -eu

CLUSTER=ah
CONTEXT=kind-$CLUSTER
NODES="$CLUSTER-control-plane $CLUSTER-worker"

# Cilium chart 1.20.2 (appVersion 1.20.2, created 2026-09-16, so more than 14 days old when
# pinned). Version and sha256 of the chart file come from https://helm.cilium.io/index.yaml
# (checked 2026-10-17); the script refuses a chart file with another digest.
CILIUM_VERSION="1.20.2"
CILIUM_CHART_SHA256="b2afd87b7f75f875f92a14559f14f59b7babbb479d968e3fd625a20bf30ec20e"
CILIUM_REPO="https://helm.cilium.io"

# Git Bash on Windows: do not rewrite container-side paths.
if command -v cygpath >/dev/null 2>&1; then
    export MSYS_NO_PATHCONV=1
fi

k() {
    kubectl --context "$CONTEXT" "$@"
}

cluster_exists() {
    kind get clusters 2>/dev/null | grep -qx "$CLUSTER"
}

# Start the node containers that are not running (after `kind-down.sh stop` or a reboot).
start_nodes() {
    for node in $NODES; do
        if [ "$(docker inspect -f '{{.State.Running}}' "$node" 2>/dev/null)" != "true" ]; then
            echo "starting $node"
            docker start "$node" >/dev/null
        fi
    done
}

# Antivirus that scans HTTPS (Avast Web Shield on this PC) answers on 127.0.0.1:16443 with its own
# certificate, so kubectl and helm reject the API server ("x509: certificate signed by unknown
# authority"). Only then is certificate checking switched off for this one kubeconfig entry,
# the API server on this PC's loopback. Client-certificate login still works through the shield.
# On a machine without such a scanner nothing changes.
ensure_api_reachable() {
    tries=0
    while :; do
        out=$(kubectl --context "$CONTEXT" get --raw /version 2>&1) && return 0
        case "$out" in
            *"unknown authority"*)
                echo "TLS to the API server is intercepted (antivirus): skipping certificate"                      "verification for the loopback cluster entry $CONTEXT" >&2
                kubectl config unset "clusters.$CONTEXT.certificate-authority-data" >/dev/null
                kubectl config set-cluster "$CONTEXT" --insecure-skip-tls-verify=true >/dev/null
                ;;
            *)
                # The API server needs a while after the containers start.
                tries=$((tries + 1))
                if [ "$tries" -ge 60 ]; then
                    echo "the API server did not answer within 120 s: $out" >&2
                    return 1
                fi
                sleep 2
                ;;
        esac
    done
}

install_cilium() {
    work=$(mktemp -d)
    # helm.exe does not understand Git Bash's /tmp: hand it a Windows path.
    if command -v cygpath >/dev/null 2>&1; then
        work=$(cygpath -m "$work")
    fi
    trap 'rm -rf "$work"' EXIT
    helm pull cilium --repo "$CILIUM_REPO" --version "$CILIUM_VERSION" --destination "$work"
    actual=$(sha256sum "$work/cilium-$CILIUM_VERSION.tgz" | cut -d ' ' -f 1)
    if [ "$actual" != "$CILIUM_CHART_SHA256" ]; then
        echo "cilium chart digest mismatch: expected $CILIUM_CHART_SHA256, got $actual" >&2
        exit 1
    fi
    helm --kube-context "$CONTEXT" upgrade --install cilium "$work/cilium-$CILIUM_VERSION.tgz" \
        --namespace kube-system --values deploy/kind/cilium-values.yaml --wait --timeout 8m
}

if cluster_exists; then
    start_nodes
else
    kind create cluster --config deploy/kind/cluster.yaml
fi

kind export kubeconfig --name "$CLUSTER" >/dev/null
ensure_api_reachable

# Nodes stay NotReady until the CNI runs, so this waits for Cilium first.
if ! helm --kube-context "$CONTEXT" status cilium --namespace kube-system >/dev/null 2>&1; then
    install_cilium
fi

k wait --for=condition=Ready node --all --timeout=300s
k --namespace kube-system rollout status daemonset/cilium --timeout=300s
k --namespace kube-system rollout status deployment/cilium-operator --timeout=300s
k --namespace kube-system rollout status deployment/hubble-relay --timeout=300s
k --namespace kube-system rollout status deployment/hubble-ui --timeout=300s
k apply -f deploy/kind/runtimeclass.yaml
# The local registry the nodes pull pinned images from (R14).
sh scripts/kind-registry.sh

echo "cluster $CLUSTER is ready (kubectl context $CONTEXT)"
