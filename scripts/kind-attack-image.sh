#!/bin/sh
# Build the attack-suite image (tests/attacks/Dockerfile), push it to the local registry and print the
# reference pods use: localhost:5001/assume-hijacked-attacks:<commit>@sha256:<digest>.
# Run from the repository root with Git Bash, cluster up: `sh scripts/kind-attack-image.sh`.
# tests/k8s/test_walls.py runs it when AH_ATTACK_IMAGE is not set.
set -eu

PUSH=127.0.0.1:5001/assume-hijacked-attacks
PULL=localhost:5001/assume-hijacked-attacks

# Progress goes to stderr: stdout is only the image reference.
# No provenance attestation (it carries the build time): the same code keeps the same digest.
docker build --quiet --provenance=false -f tests/attacks/Dockerfile -t "$PUSH:dev" . >&2
docker push --quiet "$PUSH:dev" >&2
digest=$(docker inspect -f '{{range .RepoDigests}}{{println .}}{{end}}' "$PUSH:dev" \
    | grep "^$PUSH@" | head -n 1 | cut -d @ -f 2)
if [ -z "$digest" ]; then
    echo "no registry digest for $PUSH:dev after the push" >&2
    exit 1
fi
tag=$(git rev-parse --short HEAD)
echo "$PULL:$tag@$digest"
