#!/bin/sh
# Helm chart tests: `pytest tests/k8s/test_chart.py` (helm lint and helm template, read back as
# YAML; no cluster). The chart is deploy/helm/assume-hijacked, from the k8s branch (ruling R17a).
#
# The tests skip themselves when the helm binary is missing. In CI that would make a green job
# that checked nothing, so this script fails when any test is skipped or none ran.
#
# CI: the job image is alpine/helm (pinned in ci/lib.sh). It has no Python, so the script adds
#     python3 from Alpine and installs only what the chart tests import (pytest and PyYAML, with
#     their dependencies), from requirements-dev.lock, hash-checked like every other install.
# PC: your virtualenv and your helm binary when both are there (the Python image of the other
#     scripts has no helm); otherwise the same pinned image as CI.
#
# --confcutdir=tests/k8s keeps pytest from loading tests/conftest.py, which opens a database
# connection for every test and imports psycopg. The chart tests need neither.
. ci/lib.sh

if [ ! -f tests/k8s/test_chart.py ]; then
    echo "tests/k8s/test_chart.py is missing: the chart arrives with the k8s branch" >&2
    exit 1
fi

if ! in_tool_image; then
    if ! command -v helm >/dev/null 2>&1; then
        # CA bundle from .env as in ci/build-scan.sh, for apk and pip behind HTTPS scanning.
        if [ -z "${PIP_CERT_FILE:-}" ] && [ -f .env ]; then
            PIP_CERT_FILE=$(sed -n 's/^PIP_CERT_FILE=//p' .env)
        fi
        if [ -n "${PIP_CERT_FILE:-}" ]; then
            rerun_in "$HELM_IMAGE" ci/chart.sh -v "$PIP_CERT_FILE:/tmp/extra-ca.pem:ro" \
                -e SSL_CERT_FILE=/tmp/extra-ca.pem -e PIP_CERT=/tmp/extra-ca.pem
        else
            rerun_in "$HELM_IMAGE" ci/chart.sh
        fi
        exit
    fi
    python=$(python_bin)
else
    if [ -f /tmp/extra-ca.pem ]; then
        # PC only (mounted above): added to the system bundle, which apk and pip then use.
        cat /tmp/extra-ca.pem >>/etc/ssl/certs/ca-certificates.crt
        export PIP_CERT=/etc/ssl/certs/ca-certificates.crt
    fi
    apk add --no-cache python3 py3-pip >/dev/null
    python3 -m venv /tmp/chart-venv
    python=/tmp/chart-venv/bin/python
    # The lock lines of the packages the chart tests import: name, then its indented hash lines.
    awk -v want=" pytest iniconfig packaging pluggy pygments pyyaml " '
        /^[A-Za-z0-9]/ { name = $1; sub(/==.*/, "", name); keep = index(want, " " name " ") > 0 }
        keep { print }
    ' requirements-dev.lock >/tmp/chart-requirements.txt
    "$python" -m pip install --quiet --require-hashes --no-deps -r /tmp/chart-requirements.txt
fi

mkdir -p reports
log=$(mktemp)
rc=0
"$python" -m pytest -q -rs -p no:cacheprovider --confcutdir=tests/k8s \
    --junitxml=reports/chart-junit.xml tests/k8s/test_chart.py >"$log" 2>&1 || rc=$?
cat "$log"
if [ "$rc" -ne 0 ]; then
    exit "$rc"
fi
if grep -q 'SKIPPED' "$log"; then
    echo "chart tests were skipped (is helm installed?): that is a failure here" >&2
    exit 1
fi
if ! grep -Eq '[0-9]+ passed' "$log"; then
    echo "no chart test ran" >&2
    exit 1
fi
echo "chart tests: passed"
