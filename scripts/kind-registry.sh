#!/bin/sh
# The local image registry of the kind cluster "ah" (ruling R14). Run from the repository root
# with Git Bash: `sh scripts/kind-registry.sh` (scripts/kind-up.sh runs it).
#
# A locally built image has no registry digest, and the admission policy only admits images by
# digest from localhost:5001/. So images are pushed to a registry container, kind-registry, on
# 127.0.0.1:5001, and the nodes pull from it. Wiring from the kind docs, "Local Registry"
# (https://kind.sigs.k8s.io/docs/user/local-registry/, checked 2026-10-17):
#   - the cluster is created with containerd's config_path = /etc/containerd/certs.d
#     (deploy/kind/cluster.yaml)
#   - each node gets certs.d/localhost:5001/hosts.toml pointing at http://kind-registry:5000
#   - the registry container joins the "kind" Docker network, so the nodes reach it by name
#   - ConfigMap kube-public/local-registry-hosting tells tools where the registry is (KEP-1755)
#
# Push from the host to 127.0.0.1:5001/<name>; pods reference localhost:5001/<name>@sha256:...
# scripts/kind-attack-image.sh does this for the attack-suite image; B6's kind-deploy.sh for the
# app image. Idempotent.
set -eu

CLUSTER=ah
CONTEXT=kind-$CLUSTER
NAME=kind-registry
PORT=5001
# registry:3 (distribution 3.1.2), created 2026-09-24, so more than 14 days old when pinned.
# Index digest from `docker buildx imagetools inspect registry:3` (2026-10-17).
IMAGE="registry:3@sha256:ddf754342cfc8acc51a56d5d0ab6af06826461864460636d8bd5c546dab2a7b8"
CERTS_DIR="/etc/containerd/certs.d/localhost:$PORT"

# Git Bash on Windows: do not rewrite container-side paths.
if command -v cygpath >/dev/null 2>&1; then
    export MSYS_NO_PATHCONV=1
fi

state=$(docker inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null || true)
case "$state" in
    true) ;;
    false) docker start "$NAME" >/dev/null ;;
    *) docker run -d --name "$NAME" -p "127.0.0.1:$PORT:5000" "$IMAGE" >/dev/null ;;
esac

if [ "$(docker inspect -f '{{json .NetworkSettings.Networks.kind}}' "$NAME")" = "null" ]; then
    docker network connect kind "$NAME"
fi

for node in $(kind get nodes --name "$CLUSTER"); do
    # A cluster created before deploy/kind/cluster.yaml had the patch has no config_path, and
    # containerd would ignore hosts.toml: say so instead of failing later at image pull.
    if ! docker exec "$node" grep -q 'config_path = "/etc/containerd/certs.d"' /etc/containerd/config.toml; then
        echo "$node: containerd has no registry config_path (cluster created before the registry" \
             "patch). Recreate it: sh scripts/kind-down.sh && sh scripts/kind-up.sh" >&2
        exit 1
    fi
    docker exec "$node" mkdir -p "$CERTS_DIR"
    printf '[host."http://%s:5000"]\n' "$NAME" | docker exec -i "$node" cp /dev/stdin "$CERTS_DIR/hosts.toml"
done

kubectl --context "$CONTEXT" apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: local-registry-hosting
  namespace: kube-public
data:
  localRegistryHosting.v1: |
    host: "localhost:$PORT"
    help: "https://kind.sigs.k8s.io/docs/user/local-registry/"
EOF

echo "registry $NAME: push to 127.0.0.1:$PORT/<name>, pull as localhost:$PORT/<name>@sha256:<digest>"
