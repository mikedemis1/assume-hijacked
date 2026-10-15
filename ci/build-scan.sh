#!/bin/sh
# Builds the application image and scans it with trivy: OS packages of the base image and the
# Python packages installed from requirements.lock.
# https://trivy.dev/latest/docs/configuration/filtering/
#   Two runs: a full report (every severity, fixed or not; artifacts, never fails) and the gate
#   (--severity HIGH,CRITICAL --ignore-unfixed --exit-code 1): fails on a high or critical
#   vulnerability that has a fixed version to move to. An accepted one goes in .trivyignore with
#   the reason and an expiry date (exp:YYYY-MM-DD).
# https://trivy.dev/latest/docs/configuration/reporting/ (formats, the GitLab template)
# CI: Docker-in-Docker (https://docs.gitlab.com/ci/docker/using_docker_build/). trivy runs as a
# container next to the build and reads the image through the Docker socket of that daemon.
# PC: the same commands against Docker Desktop. PIP_CERT_FILE and LOCAL_WHEELS_DIR (from .env
# or the environment) are passed to the build the way compose.yaml does; CI sets neither.
. ci/lib.sh

image=assume-hijacked:scan
if ! in_ci && [ -f .env ]; then
    # Only these two build settings, never the passwords.
    : "${PIP_CERT_FILE:=$(sed -n 's/^PIP_CERT_FILE=//p' .env)}"
    : "${LOCAL_WHEELS_DIR:=$(sed -n 's/^LOCAL_WHEELS_DIR=//p' .env)}"
fi
set -- --tag "$image"
if [ -n "${PIP_CERT_FILE:-}" ]; then
    set -- "$@" --secret "id=pip_cert,src=$PIP_CERT_FILE"
fi
if [ -n "${LOCAL_WHEELS_DIR:-}" ]; then
    set -- "$@" --build-context "wheels=$LOCAL_WHEELS_DIR"
fi
wait_for_docker
docker build "$@" .

# trivy downloads its vulnerability database over HTTPS: on a network that intercepts TLS it
# needs the same CA bundle as the build (PC only; CI sets no PIP_CERT_FILE). The database is kept
# in a volume on the daemon, so the second run does not download it again.
trivy() {
    if [ -n "${PIP_CERT_FILE:-}" ]; then
        set -- -v "$PIP_CERT_FILE:/tmp/extra-ca.pem:ro" -e SSL_CERT_FILE=/tmp/extra-ca.pem \
            "$TRIVY_IMAGE" "$@"
    else
        set -- "$TRIVY_IMAGE" "$@"
    fi
    docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$(repo_mount):/repo" \
        -v assume-hijacked-trivy-cache:/root/.cache/trivy "$@"
}

# 1. Report, never fails the job: every severity, fixed or not (unfixed, will_not_fix and
# fix_deferred included), as JSON and in GitLab's container scanning format. The accepted
# unfixed HIGHs are reviewed from this report (README, "CI pipeline").
mkdir -p reports
trivy image --scanners vuln --exit-code 0 --no-progress --skip-version-check \
    --format json --output /repo/reports/trivy-all.json "$image"
trivy convert --format template --template @/contrib/gitlab.tpl \
    --output /repo/reports/gl-container-scanning-report.json /repo/reports/trivy-all.json
echo "== report only: every HIGH and CRITICAL, with or without a fix"
trivy convert --format table --severity HIGH,CRITICAL /repo/reports/trivy-all.json

# 2. Gate: fails on a HIGH or CRITICAL that has a fixed version.
ignore=
if [ -f .trivyignore ]; then
    ignore="--ignorefile /repo/.trivyignore"
fi
echo "== gate: HIGH and CRITICAL with a fixed version"
# shellcheck disable=SC2086  # $ignore is empty or two words on purpose
trivy image --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed \
    --exit-code 1 --no-progress --skip-version-check $ignore "$image"
