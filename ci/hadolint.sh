#!/bin/sh
# Dockerfile lint with hadolint: https://github.com/hadolint/hadolint
# --failure-threshold warning: errors and warnings fail the job, info and style do not.
# An accepted rule carries `# hadolint ignore=DLxxxx` and the reason on the line above.
. ci/lib.sh

if ! in_tool_image; then
    rerun_in "$HADOLINT_IMAGE" ci/hadolint.sh
    exit
fi

for dockerfile in Dockerfile ci/smoke-runner.Dockerfile attacks/Dockerfile; do
    echo "== $dockerfile"
    hadolint --failure-threshold warning "$dockerfile"
done
echo "hadolint: no findings at warning level or above"
