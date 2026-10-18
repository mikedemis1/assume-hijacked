#!/bin/sh
# Evidence report (python -m secops.evidence): one static HTML page, reports/evidence.html, from
# the JSON reports in reports/. It lists the pinned image references of this repository first
# (reports/image-digests.json). Only the standard library is needed, so nothing is installed.
# A report that is not there is shown as "not run" and the page as INCOMPLETE; the page is
# evidence, not a gate, so that does not fail the job. EVIDENCE_STRICT=1 makes it one.
. ci/lib.sh

strict=""
if [ "${EVIDENCE_STRICT:-0}" = "1" ]; then
    strict="--strict"
fi
# shellcheck disable=SC2086 # strict is empty or one word
"$(python_bin)" -m secops.evidence --reports reports --out reports/evidence.html \
    --collect-images . $strict
