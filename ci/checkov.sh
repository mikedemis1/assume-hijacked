#!/bin/sh
# Policy checks with checkov: https://www.checkov.io/2.Basics/CLI%20Command%20Reference.html
#   - the Dockerfiles (framework dockerfile)
#   - this pipeline itself (framework gitlab_ci)
# compose.yaml is not scanned: checkov has no Docker Compose framework (the --framework list in
# the reference above has dockerfile, kubernetes, helm ... but no compose).
# --skip-download: no calls to the Prisma Cloud API, the built-in checks only.
# An accepted check carries `#checkov:skip=CKV_xxx: reason` in the file.
. ci/lib.sh

if ! in_tool_image; then
    rerun_in "$CHECKOV_IMAGE" ci/checkov.sh
    exit
fi

checkov --skip-download --quiet --compact --framework dockerfile \
    -f Dockerfile -f ci/smoke-runner.Dockerfile -f attacks/Dockerfile
checkov --skip-download --quiet --compact --framework gitlab_ci -f .gitlab-ci.yml
