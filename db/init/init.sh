#!/bin/sh
# Runs once, when the database volume is empty.
# Roles are cluster-wide, so they are created once. The schema, grants, leases, risk tables,
# row-level security and seed are applied to both databases: supplier (the stack) and
# supplier_test (the pytest suite only).
# CI (scripts/ci-db-setup.sh) runs this same file against a service container: SQL_DIR points at the
# checkout and psql takes the server from PGHOST/PGPASSWORD.
set -eu

SQL_DIR="${SQL_DIR:-/db/sql}"

run() {  # run <database> <file>
    psql -v ON_ERROR_STOP=1 \
         -v pw_tool_read_ticket="$DB_PASSWORD_TOOL_READ_TICKET" \
         -v pw_tool_lookup_account="$DB_PASSWORD_TOOL_LOOKUP_ACCOUNT" \
         -v pw_tool_request_disconnection="$DB_PASSWORD_TOOL_REQUEST_DISCONNECTION" \
         -v pw_tool_issue_bill_credit="$DB_PASSWORD_TOOL_ISSUE_BILL_CREDIT" \
         -v pw_tool_set_temp_protection="$DB_PASSWORD_TOOL_SET_TEMP_PROTECTION" \
         -v pw_executor="$DB_PASSWORD_EXECUTOR" \
         -v pw_approver="$DB_PASSWORD_APPROVER" \
         -v pw_gateway="$DB_PASSWORD_GATEWAY" \
         -v pw_risk_engine="$DB_PASSWORD_RISK_ENGINE" \
         -v pw_dispatcher="$DB_PASSWORD_DISPATCHER" \
         --username "$POSTGRES_USER" --dbname "$1" -f "$2"
}

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
     -c "CREATE DATABASE supplier_test"

run "$POSTGRES_DB" "$SQL_DIR/02-roles.sql"
for database in "$POSTGRES_DB" supplier_test; do
    for f in 01-schema.sql 03-grants.sql 05-lease.sql 06-risk.sql 07-flags.sql 08-rls.sql 04-seed.sql; do
        run "$database" "$SQL_DIR/$f"
    done
    # The local staff list (the console's dev sign-in users, public oids). Opt-in: only the local
    # callers (test-db.sh, ci-db-setup.sh, the kind postgres-init Job) set SEED_DEV_STAFF=yes. On
    # Azure an admin fills the list (docs/azure.md, "Staff").
    if [ "${SEED_DEV_STAFF:-no}" = yes ]; then
        run "$database" "$SQL_DIR/09-dev-staff.sql"
    fi
done
