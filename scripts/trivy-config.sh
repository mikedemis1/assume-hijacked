#!/bin/sh
# Trivy config scan: the rendered Helm chart (kind and Azure values), infra/ and both Dockerfiles.
#   sh scripts/trivy-config.sh [report.json]
# Exit status 1 when a HIGH or CRITICAL misconfiguration is found that .trivyignore does not accept.
# report.json (default reports/trivy-config.json) gets every finding of every severity.
#
# Needs helm and python with pytest and PyYAML (scripts/render-chart.py), and either a `trivy`
# on PATH (CI: the pinned binary from scripts/ci-tools.sh) or Docker (the image pinned in
# .gitlab-ci.yml, as TRIVY_IMAGE, which is the one the build job scans with).
#
# The checks are the ones built into that Trivy version (--skip-check-update): no bundle is
# downloaded, so the rules change only when the pinned version changes.
# With Docker the files are copied in with `docker cp`, not bind-mounted: on Docker Desktop for
# Windows a bind mount from a Git Bash path is sometimes empty.
set -eu
cd "$(dirname "$0")/.."

report=${1:-reports/trivy-config.json}
export MSYS_NO_PATHCONV=1  # Git Bash must not rewrite /scan into a Windows path

# What is scanned, in one directory: the rendered chart, infra without provider downloads, the Dockerfiles.
scan=$(mktemp -d)
trap 'rm -rf "$scan"' EXIT
native=$(cygpath -m "$scan" 2>/dev/null || echo "$scan")  # docker.exe and python want a Windows path in Git Bash
python scripts/render-chart.py "$native"
cp -R infra "$scan/infra"
find "$scan/infra" -name .terraform -type d -prune -exec rm -rf {} +
cp Dockerfile "$scan/Dockerfile"
mkdir -p "$scan/tests/attacks"
cp tests/attacks/Dockerfile "$scan/tests/attacks/Dockerfile"
cp .trivyignore "$scan/.trivyignore"
mkdir -p "$(dirname "$report")"

# trivy_config <args>...: `trivy config` on the scan directory. A report written with
# `--output report.json` is copied to $report afterwards.
if command -v trivy >/dev/null 2>&1; then
    trivy_config() {
        (cd "$scan" && trivy config --skip-version-check --skip-check-update --ignorefile .trivyignore "$@" .)
    }
else
    image=$(sed -n 's/^ *TRIVY_IMAGE: *//p' .gitlab-ci.yml)
    trivy_config() {
        box=$(docker create --workdir /scan "$image" \
            config --skip-version-check --skip-check-update --ignorefile .trivyignore "$@" .)
        docker cp "$native/." "$box:/scan"
        status=0
        docker start -a "$box" || status=$?
        docker cp "$box:/scan/report.json" "$native/report.json" 2>/dev/null || true
        docker rm "$box" >/dev/null
        return $status
    }
fi

echo "== report: every severity, in $report"
trivy_config --format json --output report.json
cp "$scan/report.json" "$report"

echo "== gate: HIGH and CRITICAL"
trivy_config --severity HIGH,CRITICAL --exit-code 1
