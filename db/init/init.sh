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
         -v pw_demo_portal="$DB_PASSWORD_DEMO_PORTAL" \
         -v pw_demo_ops="$DB_PASSWORD_DEMO_OPS" \
         --username "$POSTGRES_USER" --dbname "$1" -f "$2"
}

# Only when missing, like the roles in 02-roles.sql: a setup that stopped halfway can run again.
# The user that runs this creates both databases, so it owns them and their public schema. On
# Azure that user is not a superuser and needs that ownership; on kind and CI the postgres image
# has already created POSTGRES_DB, so only supplier_test is created. Connects to the "postgres"
# database, which every server has.
for database in "$POSTGRES_DB" supplier_test; do
    echo "SELECT 'CREATE DATABASE $database' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '$database') \gexec" |
        psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres
done

run "$POSTGRES_DB" "$SQL_DIR/02-roles.sql"
for database in "$POSTGRES_DB" supplier_test; do
    # A user that is not a superuser (Azure) can give a function to an owner role (ALTER FUNCTION
    # ... OWNER TO) only if that role may create in the function's schema. The owners get CREATE
    # on public for the setup only; it is taken back below.
    psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$database" \
         -c "GRANT CREATE ON SCHEMA public TO api_owner, lease_owner, risk_owner, staff_owner, demo_owner"
    for f in 01-schema.sql 03-grants.sql 05-lease.sql 06-risk.sql 07-flags.sql 08-rls.sql 09-demo.sql 04-seed.sql; do
        run "$database" "$SQL_DIR/$f"
    done
    psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$database" \
         -c "REVOKE CREATE ON SCHEMA public FROM api_owner, lease_owner, risk_owner, staff_owner, demo_owner"
    # The local staff list (the console's dev sign-in users, public oids). Opt-in: only the local
    # callers (test-db.sh, ci-db-setup.sh, the kind postgres-init Job) set SEED_DEV_STAFF=yes. On
    # Azure an admin fills the list (docs/azure.md, "Staff").
    if [ "${SEED_DEV_STAFF:-no}" = yes ]; then
        run "$database" "$SQL_DIR/09-dev-staff.sql"
    fi
done
