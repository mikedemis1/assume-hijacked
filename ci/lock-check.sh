#!/bin/sh
# Are the locks still what pyproject.toml asks for? Runs pip-compile again on a copy of each lock
# and compares the package lines and hashes (comment lines are left out of the comparison).
# https://pip-tools.readthedocs.io/en/stable/
# pip-compile keeps the versions already in the output file, so the only differences are a
# dependency changed in pyproject.toml without a new lock, or files PyPI added later for a pinned
# version. Non-blocking in CI (allow_failure): it needs PyPI and can flag a harmless new wheel.
# The locks are for Linux and Python 3.12, so on a PC run it in the CI Python image:
#   docker run --rm -e IN_TOOL_IMAGE=1 -v "$PWD:/repo" -w /repo <PYTHON_IMAGE> sh ci/lock-check.sh
. ci/lib.sh

if in_tool_image; then
    install_python_tools
fi
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
status=0

without_comments() {
    grep -v -e '^[[:space:]]*#' -e '^[[:space:]]*$' -e '^--index-url' -e '^--trusted-host' "$1"
}

check() {  # check <lock> [extra pip-compile options...]
    lock=$1
    shift
    cp "$lock" "$work/fresh"
    "$(python_bin)" -m piptools compile --quiet --generate-hashes --strip-extras "$@" \
        --output-file="$work/fresh" pyproject.toml
    without_comments "$lock" > "$work/old"
    without_comments "$work/fresh" > "$work/new"
    if diff -u "$work/old" "$work/new"; then
        echo "$lock: up to date"
    else
        echo "$lock: differs from a fresh pip-compile (diff above)" >&2
        status=1
    fi
}

check requirements.lock
check requirements-dev.lock --allow-unsafe --extra=dev
exit "$status"
