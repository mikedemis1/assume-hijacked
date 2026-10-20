#!/bin/sh
# Open the demo UI: kubectl port-forward to svc/demo, then http://localhost:8085
#   sh scripts/demo-ui.sh
# The demo has no ingress and no LoadBalancer: this is the only way to reach it, on this PC only.
# Port-forwards get dropped now and then (an antivirus that inspects local traffic does it on
# this PC), so the command is restarted until you press Ctrl-C.
# DEMO_PORT picks another local port. DEMO_UI_MAX_TRIES stops after that many starts (0, the
# default, never stops); the tests use it.
set -eu

CONTEXT=kind-ah
NAMESPACE=ah-demo
PORT=${DEMO_PORT:-8085}
MAX_TRIES=${DEMO_UI_MAX_TRIES:-0}

case $PORT in
    '' | *[!0-9]*)
        echo "DEMO_PORT must be a number, got: $PORT" >&2
        exit 2
        ;;
esac
case $MAX_TRIES in
    '' | *[!0-9]*)
        echo "DEMO_UI_MAX_TRIES must be a number, got: $MAX_TRIES" >&2
        exit 2
        ;;
esac

if ! kubectl --context "$CONTEXT" --namespace "$NAMESPACE" get service demo >/dev/null 2>&1; then
    echo "demo-ui: no service demo in $NAMESPACE. Is the cluster up and the chart deployed with demo.enabled=true (kind does that)?" >&2
    exit 1
fi

echo "Demo UI: http://localhost:$PORT   (Ctrl-C to stop)"
tries=0
while :; do
    tries=$((tries + 1))
    kubectl --context "$CONTEXT" --namespace "$NAMESPACE" port-forward --address 127.0.0.1 service/demo "$PORT:8085" || true
    if [ "$MAX_TRIES" -ne 0 ] && [ "$tries" -ge "$MAX_TRIES" ]; then
        exit 0
    fi
    echo "demo-ui: the port-forward ended, starting it again in 2 s" >&2
    sleep "${DEMO_UI_PAUSE:-2}"
done
