#!/bin/sh
# Install (or remove) the monitoring stack in the kind cluster "ah": kube-prometheus-stack
# (Prometheus, Alertmanager, Grafana), Mailpit, the alert rules and the "Walls" dashboard, all in
# the namespace ah-monitoring. Run from the repository root with Git Bash, after
# `sh scripts/kind-up.sh`:
#
#   sh scripts/kind-monitoring.sh           install or upgrade (safe to run again)
#   sh scripts/kind-monitoring.sh remove    delete all of it, including the CRDs of the operator
#
# The stack needs about 1 GB on top of the cluster. Docker has 6 GB, so install it while the
# Compose stack is down, and remove it when the check is done.
#
# Grafana:       kubectl --context kind-ah -n ah-monitoring port-forward svc/kps-grafana 3000:80
#                login admin, password in the Secret grafana-admin (printed at the first install)
# Mailpit:       kubectl --context kind-ah -n ah-monitoring port-forward svc/mailpit 8025:8025
# Prometheus:    kubectl --context kind-ah -n ah-monitoring port-forward svc/kps-prometheus 9090:9090
set -eu

CONTEXT=kind-ah
NAMESPACE=ah-monitoring
RELEASE=kps

# kube-prometheus-stack 91.9.0 (created 2026-10-02, more than 14 days old when pinned). The sha256
# of the chart file is the digest in https://prometheus-community.github.io/helm-charts/index.yaml
# (checked 2026-10-17); the script refuses a file with another digest.
KPS_VERSION="91.9.0"
KPS_CHART_SHA256="75ee7cf15ee9492faf1babc0682237caf6ba706700370cd34b1ea261cee737fe"
KPS_REPO="https://prometheus-community.github.io/helm-charts"

# Git Bash on Windows: do not rewrite container-side paths.
if command -v cygpath >/dev/null 2>&1; then
    export MSYS_NO_PATHCONV=1
fi

k() {
    kubectl --context "$CONTEXT" "$@"
}

# The operator's CRDs are created by the chart and are not removed with it.
crds() {
    k get crd -o name | grep '\.monitoring\.coreos\.com$' || true
}

remove() {
    helm --kube-context "$CONTEXT" uninstall "$RELEASE" --namespace "$NAMESPACE" --wait 2>/dev/null || true
    k delete namespace "$NAMESPACE" --ignore-not-found --wait=true
    crds | while read -r crd; do
        k delete "$crd" --ignore-not-found
    done
    echo "monitoring removed"
}

# The namespace is outside the application chart: it has its own release. Pod Security
# "restricted" is enforced like in the ah-* namespaces; every pod of the stack and Mailpit
# complies (tests/k8s/test_monitoring.py checks the rendered manifests).
namespace() {
    k apply -f - <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: $NAMESPACE
  labels:
    app.kubernetes.io/part-of: assume-hijacked-monitoring
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/warn-version: latest
EOF
}

# Grafana's admin password: random, created once, kept in the cluster.
grafana_secret() {
    if k --namespace "$NAMESPACE" get secret grafana-admin >/dev/null 2>&1; then
        return 0
    fi
    password=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')
    k --namespace "$NAMESPACE" create secret generic grafana-admin \
        --from-literal=admin-user=admin --from-literal=admin-password="$password" >/dev/null
    echo "Grafana login: admin / $password (kept in the Secret grafana-admin)"
}

# The dashboard is a ConfigMap with the label the Grafana sidecar looks for.
dashboard() {
    k --namespace "$NAMESPACE" create configmap ah-dashboard-walls \
        --from-file=walls.json=deploy/monitoring/dashboards/walls.json --dry-run=client -o yaml \
        | k label --local -f - grafana_dashboard=1 -o yaml \
        | k --namespace "$NAMESPACE" apply -f - >/dev/null
}

install_stack() {
    work=$(mktemp -d)
    # helm.exe does not understand Git Bash's /tmp: hand it a Windows path.
    if command -v cygpath >/dev/null 2>&1; then
        work=$(cygpath -m "$work")
    fi
    trap 'rm -rf "$work"' EXIT
    helm pull kube-prometheus-stack --repo "$KPS_REPO" --version "$KPS_VERSION" --destination "$work"
    actual=$(sha256sum "$work/kube-prometheus-stack-$KPS_VERSION.tgz" | cut -d ' ' -f 1)
    if [ "$actual" != "$KPS_CHART_SHA256" ]; then
        echo "kube-prometheus-stack chart digest mismatch: expected $KPS_CHART_SHA256, got $actual" >&2
        exit 1
    fi
    helm --kube-context "$CONTEXT" upgrade --install "$RELEASE" \
        "$work/kube-prometheus-stack-$KPS_VERSION.tgz" --namespace "$NAMESPACE" \
        --values deploy/monitoring/kube-prometheus-values.yaml --wait --timeout 8m
}

case "${1:-install}" in
    remove)
        remove
        exit 0
        ;;
    install) ;;
    *)
        echo "usage: sh scripts/kind-monitoring.sh [install|remove]" >&2
        exit 2
        ;;
esac

namespace
grafana_secret
dashboard
install_stack
# The rule needs the PrometheusRule CRD, which the chart has just created.
k apply -f deploy/monitoring/rules/assume-hijacked.yaml
k apply -f deploy/monitoring/mailpit.yaml
k --namespace "$NAMESPACE" rollout status deployment/mailpit --timeout=180s
k --namespace "$NAMESPACE" rollout status deployment/kps-grafana --timeout=180s
k --namespace "$NAMESPACE" rollout status statefulset/prometheus-kps-prometheus --timeout=180s
k --namespace "$NAMESPACE" rollout status statefulset/alertmanager-kps-alertmanager --timeout=180s

echo "monitoring is ready in the namespace $NAMESPACE"
