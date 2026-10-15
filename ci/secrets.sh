#!/bin/sh
# Secret scan of the full git history (every commit on every branch), not only the files in
# the last commit: a password that was committed once and deleted later is still in the history.
# gitleaks: https://github.com/gitleaks/gitleaks
#   --redact keeps any secret it finds out of the log and the report artifact.
. ci/lib.sh

if ! in_tool_image; then
    rerun_in "$GITLEAKS_IMAGE" ci/secrets.sh
    exit
fi

mkdir -p reports
# The checkout belongs to another user than the one in the container.
git config --global --add safe.directory "$PWD"
# A shallow clone would hide old commits. CI asks for the full history (GIT_DEPTH: 0);
# this is the second line of defence.
if [ "$(git rev-parse --is-shallow-repository)" = "true" ]; then
    git fetch --unshallow --quiet
fi
echo "commits to scan: $(git rev-list --all --count)"
gitleaks git --redact --verbose --log-opts="--all" \
    --report-format json --report-path reports/gitleaks.json .
