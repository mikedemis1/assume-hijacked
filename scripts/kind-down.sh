#!/bin/sh
# Stop or delete the local Kubernetes cluster "ah". Run from the repository root.
#   sh scripts/kind-down.sh stop   stop the node containers and the local registry (keeps the
#                                  cluster, its state and the pushed images; frees memory for
#                                  the Compose stack). `sh scripts/kind-up.sh` starts them again.
#   sh scripts/kind-down.sh        delete the cluster and the registry container.
set -eu

CLUSTER=ah

case "${1:-delete}" in
    stop)
        docker stop "$CLUSTER-control-plane" "$CLUSTER-worker"
        docker stop kind-registry >/dev/null 2>&1 || true
        ;;
    delete)
        kind delete cluster --name "$CLUSTER"
        docker rm -f kind-registry >/dev/null 2>&1 || true
        ;;
    *)
        echo "usage: sh scripts/kind-down.sh [stop|delete]" >&2
        exit 2
        ;;
esac
