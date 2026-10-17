#!/bin/sh
# Infrastructure-as-code checks. Nothing here talks to Azure and nothing costs money.
#
#   terraform  fmt -check, init -backend=false, validate, `terraform test` (mock providers)
#              https://developer.hashicorp.com/terraform/cli/commands/test
#   tflint     .tflint.hcl: the bundled terraform ruleset and the pinned azurerm ruleset
#              https://github.com/terraform-linters/tflint
#   checkov    infra/ (Terraform), and deploy/ (the Helm chart, rendered for kind and Azure)
#              https://www.checkov.io/2.Basics/CLI%20Command%20Reference.html
#
# IAC_STEP=terraform|tflint|checkov runs one step; unset or `all` runs the three. In CI every
# step is its own job with its own image (the Terraform image has no tflint and the reverse), so
# .gitlab-ci.yml sets IAC_STEP per job. On a PC `sh ci/iac.sh` runs all three.
#
# On a PC the terraform and tflint binaries are used when installed, because Go programs use the
# Windows certificate store and so work behind the antivirus' HTTPS scanning; a Linux container
# does not. Without the binary the pinned image runs instead, with the CA bundle from .env
# (PIP_CERT_FILE) as in ci/build-scan.sh. TF_DISABLE_PLUGIN_TLS is passed on when it is set in
# your environment (needed for terraform on this PC, see docs/pipeline.md) and never set here.
#
# deploy/ (the Helm chart) is optional: without it the checkov step says so and skips it, unless
# IAC_REQUIRE_DEPLOY=true (the CI job sets it, so a pipeline cannot pass by scanning nothing).
# An accepted checkov finding in Terraform carries `#checkov:skip=CKV_xxx: reason` in the file.
. ci/lib.sh

STACKS="infra/base infra/net infra/lab infra/modules/workload-identity"
# Rendered-chart checks accepted for the whole chart. checkov cannot skip one rendered object, so
# each is a decision, not a convenience:
#   CKV_K8S_35  database passwords reach the pods as environment variables from a Secret
#               (decision 3: Key Vault -> Secrets Store CSI -> K8s Secret -> env var)
#   CKV_K8S_40  the kind-only Postgres StatefulSet runs as the image's own uid
#   CKV_K8S_8, CKV_K8S_9  liveness and readiness probes: the three fakes have none yet
#               (open item for the merge; every other component has both)
CHART_SKIPS="CKV_K8S_35,CKV_K8S_40,CKV_K8S_8,CKV_K8S_9"

step="${IAC_STEP:-all}"
case "$step" in
    all | terraform | tflint | checkov) ;;
    *)
        echo "IAC_STEP must be terraform, tflint, checkov or all, got '$step'" >&2
        exit 2
        ;;
esac
if [ "$step" = all ] && in_ci; then
    echo "in CI every step is its own job (IAC_STEP=terraform|tflint|checkov)" >&2
    exit 2
fi

# rerun_step <image> <step>: this script again, for one step, inside the pinned image (PC only).
# Passes on the CA bundle from .env, if there is one, and the two settings that may be in your
# environment (an unset variable stays unset in the container).
rerun_step() {
    image=$1
    only=$2
    if [ -z "${PIP_CERT_FILE:-}" ] && [ -f .env ]; then
        PIP_CERT_FILE=$(sed -n 's/^PIP_CERT_FILE=//p' .env)
    fi
    set -- -e TF_DISABLE_PLUGIN_TLS -e IAC_REQUIRE_DEPLOY -e "IAC_STEP=$only"
    if [ -n "${PIP_CERT_FILE:-}" ]; then
        set -- -v "$PIP_CERT_FILE:/tmp/extra-ca.pem:ro" -e SSL_CERT_FILE=/tmp/extra-ca.pem "$@"
    fi
    rerun_in "$image" ci/iac.sh "$@"
}

step_terraform() {
    if ! in_tool_image && ! command -v terraform >/dev/null 2>&1; then
        rerun_step "$TERRAFORM_IMAGE" terraform
        return
    fi
    echo "== terraform fmt -check"
    terraform fmt -check -recursive -diff infra
    for stack in $STACKS; do
        echo "== $stack: init, validate, test"
        # readonly: the committed .terraform.lock.hcl must already cover every provider, so a
        # changed provider or a missing hash fails here and not at the first apply.
        terraform -chdir="$stack" init -backend=false -input=false -lockfile=readonly
        terraform -chdir="$stack" validate
        terraform -chdir="$stack" test
    done
}

step_tflint() {
    if ! in_tool_image && ! command -v tflint >/dev/null 2>&1; then
        rerun_step "$TFLINT_IMAGE" tflint
        return
    fi
    config="$(repo_mount)/.tflint.hcl"
    echo "== tflint --init (downloads the pinned azurerm ruleset)"
    tflint --init --config="$config"
    for stack in $STACKS; do
        echo "== $stack"
        tflint --chdir="$stack" --config="$config"
    done
}

# checkov_run <label> <checkov arguments...>: fails on findings, and also when checkov scanned
# nothing or could not parse a file. checkov exits 0 in both of those cases, which would make a
# broken scan look like a clean one. "Scanned nothing" is tried up to five times: on a PC, Docker
# Desktop's bind mount sometimes fails a directory listing with "Cannot allocate memory" while
# the machine is busy, and checkov then sees an empty folder. A real empty scan stays empty.
checkov_run() {
    label=$1
    shift
    log=$(mktemp)
    attempt=1
    while :; do
        rc=0
        checkov --skip-download --quiet --compact "$@" >"$log" 2>&1 || rc=$?
        if [ "$rc" -ne 0 ] || grep -q 'Passed checks: [1-9]' "$log" || [ "$attempt" -ge 5 ]; then
            break
        fi
        attempt=$((attempt + 1))
        echo "checkov ($label): nothing scanned, trying again ($attempt of 5)" >&2
        sleep "${IAC_RETRY_SLEEP:-3}"
    done
    cat "$log"
    if [ "$rc" -ne 0 ]; then
        echo "checkov ($label): findings, exit code $rc" >&2
        return 1
    fi
    if ! grep -q 'Passed checks: [1-9]' "$log"; then
        echo "checkov ($label): no check passed, so nothing was scanned" >&2
        return 1
    fi
    if grep -q 'Parsing errors' "$log"; then
        echo "checkov ($label): some files could not be parsed" >&2
        return 1
    fi
    echo "checkov ($label): clean"
}

# helm template, with the stand-in install values in ci/chart-values (the same ones
# tests/k8s/test_chart.py uses) and the database files, as scripts/kind-deploy.sh passes them.
render_chart() {
    chart=$1
    env=$2
    set -- template ah "$chart" -f "$chart/values-$env.yaml" -f "ci/chart-values/$env.json" \
        --set-file dbFiles.initSh=db/init/init.sh
    for sql in db/sql/*.sql; do
        name=$(basename "$sql" .sql)
        set -- "$@" --set-file "dbFiles.sql.$name=$sql"
    done
    helm "$@"
}

step_checkov() {
    if ! in_tool_image; then
        rerun_step "$CHECKOV_IMAGE" checkov
        return
    fi
    echo "== checkov: infra/ (Terraform)"
    # tests/ holds .tftest.hcl files: checkov's HCL parser fails on them and they are not
    # deployed code. The pattern is plain `tests`: longer regexes made checkov skip other paths.
    checkov_run infra --framework terraform -d infra --skip-path tests

    if [ ! -d deploy/helm ]; then
        if [ "${IAC_REQUIRE_DEPLOY:-}" = "true" ]; then
            echo "deploy/helm is missing and IAC_REQUIRE_DEPLOY=true" >&2
            return 1
        fi
        echo "== checkov: deploy/ not found, skipped"
        return
    fi
    rendered=$(mktemp -d)
    for chart in deploy/helm/*/; do
        chart=${chart%/}
        for env in kind azure; do
            echo "== checkov: $chart rendered for $env"
            render_chart "$chart" "$env" >"$rendered/$(basename "$chart")-$env.yaml"
        done
    done
    checkov_run deploy --framework kubernetes -d "$rendered" --skip-check "$CHART_SKIPS"
}

if [ "$step" = all ]; then
    for s in terraform tflint checkov; do
        "step_$s"
    done
else
    "step_$step"
fi
# Once per run: the PC wrapper and the container it starts both reach this line.
if ! in_tool_image || in_ci; then
    echo "iac: ${step} passed"
fi
