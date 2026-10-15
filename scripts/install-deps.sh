#!/bin/sh
# Runs inside the image build (see Dockerfile). Installs the locked dependencies, then the app.
# Every package must match a sha256 in requirements.lock; pip refuses anything else.
set -eu

# Optional build secret "pip_cert": CA bundle for networks that intercept TLS.
if [ -s /run/secrets/pip_cert ]; then
    export PIP_CERT=/run/secrets/pip_cert
fi

# Optional local wheels (bind-mounted at /wheels). A wheel is used only if its name and
# version are in the lock, and it is installed with the lock's hashes, so a changed file fails.
# After this, pip sees the package as already installed and does not ask the index for it.
for whl in /wheels/*.whl; do
    [ -e "$whl" ] || continue
    base=$(basename "$whl")
    name=${base%%-*}
    rest=${base#*-}
    version=${rest%%-*}
    awk -v p="$name==$version" 'index($0, p) == 1 { on = 1 } on { print; if (substr($0, length($0)) != "\\") exit }' \
        requirements.lock > /tmp/local-wheel.lock
    if [ ! -s /tmp/local-wheel.lock ]; then
        echo "install-deps: $base is not in requirements.lock" >&2
        exit 1
    fi
    pip install --no-cache-dir --no-index --no-deps --require-hashes \
        --find-links /wheels -r /tmp/local-wheel.lock
done

# Wheels only: every locked package has a cp312 manylinux wheel with a locked hash (checked
# 2026-10-15), so no dependency's setup.py runs in the build.
pip install --no-cache-dir --only-binary :all: --require-hashes -r requirements.lock
pip install --no-cache-dir --no-deps .
