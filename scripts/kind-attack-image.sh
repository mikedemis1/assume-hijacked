#!/bin/sh
# Build the attack-suite image (attacks/Dockerfile), push it to the local registry and print the
# reference pods use: localhost:5001/assume-hijacked-attacks@sha256:<digest>.
# Run from the repository root with Git Bash, cluster up: `sh scripts/kind-attack-image.sh`.
# tests/k8s/test_walls.py runs it when AH_ATTACK_IMAGE is not set.
set -eu

PUSH=127.0.0.1:5001/assume-hijacked-attacks
PULL=localhost:5001/assume-hijacked-attacks

# Progress goes to stderr: stdout is only the image reference.
docker build --quiet -f attacks/Dockerfile -t "$PUSH:dev" . >&2
docker push --quiet "$PUSH:dev" >&2
digest=$(docker inspect -f '{{range .RepoDigests}}{{println .}}{{end}}' "$PUSH:dev" \
    | grep "^$PUSH@" | head -n 1 | cut -d @ -f 2)
if [ -z "$digest" ]; then
    echo "no registry digest for $PUSH:dev after the push" >&2
    exit 1
fi
echo "$PULL@$digest"
