#!/bin/sh
# Trivy config scan: the rendered Helm chart (kind and Azure values), infra/ and both Dockerfiles.
#   sh scripts/trivy-config.sh [report.json]
# Exit status 1 when a HIGH or CRITICAL misconfiguration is found that .trivyignore.yaml does not
# accept, when a target was not scanned, or when the accepted findings are not exactly the three
# listed in scripts/check-trivy-report.py. report.json (default reports/trivy-config.json) gets
# every finding of every severity, the suppressed ones marked.
#
# Needs helm and python with pytest and PyYAML (scripts/render-chart.py), and either a `trivy`
# on PATH (CI: the pinned binary from scripts/ci-tools.sh) or Docker (the image pinned in
# .gitlab-ci.yml, as TRIVY_IMAGE, which is the one the build job scans with).
#
# The checks are a bundle pinned by digest (CHECKS below, the tag :2 as of 2026-10-20), not the
# newest one and not the set built into the binary: those differ (the built-in set does not flag
# AZU-0051 here). Trivy downloads it from mirror.gcr.io into a cache directory that is new on every
# run. If the download fails Trivy falls back to the built-in checks and logs an ERROR; the
# accepted findings are then missing and scripts/check-trivy-report.py fails the run. To update:
# take the Docker-Content-Digest of mirror.gcr.io/aquasec/trivy-checks:2 and run the script.
#
# With Docker the files are copied in with `docker cp`, not bind-mounted: on Docker Desktop for
# Windows a bind mount from a Git Bash path is sometimes empty.
set -eu
cd "$(dirname "$0")/.."

CHECKS=mirror.gcr.io/aquasec/trivy-checks@sha256:b591e9190cff4aa4e385b1a25bccfd9ecf178d3c77fd194e1410b7ce7e1df058
report=${1:-reports/trivy-config.json}
export MSYS_NO_PATHCONV=1  # Git Bash must not rewrite /scan into a Windows path

# What is scanned, in one directory: the rendered chart, infra without provider downloads, the
# Dockerfiles. The report, the ignore file and Trivy's cache are kept outside it.
scan=$(mktemp -d)
out=$(mktemp -d)
trap 'rm -rf "$scan" "$out"' EXIT
native=$(cygpath -m "$scan" 2>/dev/null || echo "$scan")  # docker.exe and python want a Windows path in Git Bash
native_out=$(cygpath -m "$out" 2>/dev/null || echo "$out")
python scripts/render-chart.py "$native"
cp -R infra "$scan/infra"
find "$scan/infra" -name .terraform -type d -prune -exec rm -rf {} +
cp Dockerfile "$scan/Dockerfile"
mkdir -p "$scan/tests/attacks"
cp tests/attacks/Dockerfile "$scan/tests/attacks/Dockerfile"
cp .trivyignore.yaml "$out/trivyignore.yaml"
mkdir -p "$(dirname "$report")"

# trivy_scan <args>...: Trivy on the scan directory with the ignore file. The run that writes the
# report uses `fs --scanners misconfig` because only that command has --show-suppressed; the gate
# uses `config`.
if command -v trivy >/dev/null 2>&1; then
    outfile="$out/report.json"
    trivy_scan() {
        (cd "$scan" && trivy "$@" --skip-version-check --checks-bundle-repository "$CHECKS" --cache-dir "$out/cache" \
            --ignorefile "$out/trivyignore.yaml" .)
    }
else
    outfile=/out/report.json
    image=$(sed -n 's/^ *TRIVY_IMAGE: *//p' .gitlab-ci.yml)
    trivy_scan() {
        box=$(docker create --workdir /scan "$image" "$@" --skip-version-check --checks-bundle-repository "$CHECKS" \
            --ignorefile /out/trivyignore.yaml .)
        docker cp "$native/." "$box:/scan"
        docker cp "$native_out/." "$box:/out"
        status=0
        docker start -a "$box" || status=$?
        docker cp "$box:/out/report.json" "$native_out/report.json" 2>/dev/null || true
        docker rm "$box" >/dev/null
        return $status
    }
fi

echo "== report: every severity, suppressed findings included, in $report"
trivy_scan fs --scanners misconfig --format json --output "$outfile" --show-suppressed
cp "$out/report.json" "$report"
python scripts/check-trivy-report.py "$report"

echo "== gate: HIGH and CRITICAL"
trivy_scan config --severity HIGH,CRITICAL --exit-code 1
