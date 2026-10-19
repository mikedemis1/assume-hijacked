#!/bin/sh
# Unit and attack tests (pytest), JUnit XML in reports/junit.xml for the merge request widget:
# https://docs.gitlab.com/ci/testing/unit_test_reports/
# CI: against the job's own PostgreSQL service (ci/db-setup.sh).
# PC: against the local Compose database, settings from .env (`docker compose up -d db` first).
# The smoke tests need the whole stack and run in their own job (ci/smoke.sh).
. ci/lib.sh

if in_ci; then
    # Some tests ask git which files are ignored, and the kind deploy script tags images with
    # the commit; python:3.12-slim has no git.
    if ! command -v git >/dev/null 2>&1; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq --no-install-recommends git >/dev/null
        git config --global --add safe.directory "$PWD"
    fi
    install_python_tools
    . ci/db-setup.sh
fi
mkdir -p reports
"$(python_bin)" -m pytest -q --junitxml=reports/junit.xml
