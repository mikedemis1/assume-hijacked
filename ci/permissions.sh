#!/bin/sh
# Permission assessment (python -m secops.permassess): the roles and grants of the database that
# db/sql builds, and the networks of compose.yaml, compared with security/expected-permissions.json.
# Exit 1 on any extra or missing line, 2 when a plane cannot be read; either fails the job.
# Reports go to reports/permissions/ (summary.txt, diff.json, actual.json, matrix.md).
# docs/permission-matrix.md must also be what the expected file gives (report --check).
#
# CI: the job's own PostgreSQL service, built by ci/db-setup.sh with db/init/init.sh. The job
#     image has no Docker CLI, so compose.yaml is read with PyYAML (from requirements-dev.lock)
#     and handed over as JSON; tests/test_permassess.py checks this gives the same lines as
#     `docker compose config`.
# PC: the local database (DB_HOST, DB_PORT, POSTGRES_PASSWORD from the environment, else .env)
#     and `docker compose config`. Only catalog SELECTs are run.
. ci/lib.sh

if in_ci; then
    install_python_tools
    . ci/db-setup.sh
else
    for key in DB_HOST DB_PORT POSTGRES_PASSWORD; do
        eval "already=\${$key+x}"
        if [ -z "$already" ] && [ -f .env ]; then
            value=$(sed -n "s/^$key=//p" .env | tail -n 1)
            if [ -n "$value" ]; then
                export "$key=$value"
            fi
        fi
    done
fi
# The database the stack runs on; db/init/init.sh builds supplier_test the same way.
export DB_NAME=supplier

python=$(python_bin)
out=reports/permissions
mkdir -p "$out"

"$python" -m secops.permassess.report --expected security/expected-permissions.json \
    --out docs/permission-matrix.md --check

if in_ci; then
    "$python" -c 'import json, sys, yaml
with open("compose.yaml", encoding="utf-8") as f:
    json.dump(yaml.safe_load(f), sys.stdout)' >"$out/compose-config.json"
    "$python" -m secops.permassess --planes pg,compose --compose-json "$out/compose-config.json" \
        --out "$out"
else
    "$python" -m secops.permassess --planes pg,compose --out "$out"
fi
