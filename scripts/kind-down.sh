#!/bin/sh
# Stop or delete the local Kubernetes cluster "ah". Run from the repository root.
#   sh scripts/kind-down.sh stop   stop the node containers (keeps the cluster and its state;
#                                  frees memory for the Compose stack). `sh scripts/kind-up.sh`
#                                  starts them again.
#   sh scripts/kind-down.sh        delete the cluster.
set -eu

CLUSTER=ah

case "${1:-delete}" in
    stop)
        docker stop "$CLUSTER-control-plane" "$CLUSTER-worker"
        ;;
    delete)
        kind delete cluster --name "$CLUSTER"
        ;;
    *)
        echo "usage: sh scripts/kind-down.sh [stop|delete]" >&2
        exit 2
        ;;
esac
