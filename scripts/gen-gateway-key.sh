#!/bin/sh
# Makes the tool gateway's key pair for the Compose stack: an EC P-256 private key
# (build/keys/gateway.pem) and its public key (build/keys/gateway.pub). The gateway signs each
# tool call's token with the private key; every tool checks it with the public key
# (app/security/tokens.py). Run it once before `docker compose up`; it keeps keys that exist.
#   sh scripts/gen-gateway-key.sh            make the pair if it is missing
#   sh scripts/gen-gateway-key.sh --force    replace it (running stacks must be restarted)
# KEY_DIR changes the folder. build/keys/ is not in the repository. The files are world-readable
# on purpose: Compose mounts them as secrets for a container user that is not the file's owner,
# and these are throwaway keys of a local stack. In a cluster the keys are Secrets made by the
# deployment, not by this script.
# Uses openssl, or Python with the `cryptography` package when there is no openssl.
set -eu

dir="${KEY_DIR:-build/keys}"
private="$dir/gateway.pem"
public="$dir/gateway.pub"

if [ "${1:-}" != "--force" ] && [ -s "$private" ] && [ -s "$public" ]; then
    echo "gateway key pair exists in $dir (use --force to replace it)"
    exit 0
fi

mkdir -p "$dir"
umask 077
if command -v openssl >/dev/null 2>&1; then
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$private"
    openssl pkey -in "$private" -pubout -out "$public"
else
    python=$(command -v python3 || command -v python)
    "$python" - "$private" "$public" <<'PY'
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

key = ec.generate_private_key(ec.SECP256R1())
with open(sys.argv[1], "wb") as out:
    out.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()))
with open(sys.argv[2], "wb") as out:
    out.write(key.public_key().public_bytes(serialization.Encoding.PEM,
                                            serialization.PublicFormat.SubjectPublicKeyInfo))
PY
fi
chmod 644 "$private" "$public"
echo "wrote $private and $public"
