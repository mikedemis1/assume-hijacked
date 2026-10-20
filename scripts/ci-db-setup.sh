# CI only, sourced by the test job in .gitlab-ci.yml: `. scripts/ci-db-setup.sh`.
# Turns the job's empty PostgreSQL service container (alias TEST_DB_SERVICE_HOST) into what
# db/init/init.sh builds for scripts/test-db.sh: the roles, supplier and supplier_test.
# A service container cannot mount the init scripts, so the job runs the same init.sh over the
# network: https://docs.gitlab.com/ci/services/
#
# Passwords: the service starts with POSTGRES_BOOTSTRAP_PASSWORD, a fixed value in
# .gitlab-ci.yml that is not a secret (the database lives for this job only, has fake data and
# only this job's network reaches it). The first thing done here is to replace it with a random
# one. Every role password is random too, made here, never printed, gone with the job.

set -eu

# 48 random hex characters, for throwaway passwords. Plain POSIX tools: works on Alpine and Debian.
rand_hex() {
    od -An -N24 -tx1 /dev/urandom | tr -d ' \n'
}

if ! command -v psql >/dev/null 2>&1; then
    # The client for the PostgreSQL major of the service image, pinned to that major: Debian 13
    # (the python:3.12-slim base) ships postgresql-client-17 in its own signed repository, so no
    # extra (PGDG) repository is needed. apt checks the signatures; the minor version is not pinned.
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends postgresql-client-17 >/dev/null
fi

export PGHOST="$TEST_DB_SERVICE_HOST" PGPORT=5432 PGUSER=postgres
export PGPASSWORD="$POSTGRES_BOOTSTRAP_PASSWORD"

tries=0
until pg_isready -q -d postgres; do
    tries=$((tries + 1))
    if [ "$tries" -ge 60 ]; then
        echo "db-setup: the PostgreSQL service did not come up in 60 s" >&2
        exit 1
    fi
    sleep 1
done

admin_password=$(rand_hex)
# psql variables are not expanded in -c, so the statement goes through stdin.
echo "ALTER ROLE postgres PASSWORD :'pw';" |
    psql -q -v ON_ERROR_STOP=1 -v pw="$admin_password" -d postgres
export PGPASSWORD="$admin_password" POSTGRES_PASSWORD="$admin_password"
unset admin_password

for role in TOOL_READ_TICKET TOOL_LOOKUP_ACCOUNT TOOL_REQUEST_DISCONNECTION \
            TOOL_ISSUE_BILL_CREDIT TOOL_SET_TEMP_PROTECTION EXECUTOR APPROVER \
            GATEWAY RISK_ENGINE DISPATCHER; do
    eval "export DB_PASSWORD_$role=$(rand_hex)"
done

POSTGRES_USER=postgres POSTGRES_DB=supplier SQL_DIR=db/sql sh db/init/init.sh >/dev/null

# What the test suite reads (tests/conftest.py accepts this alias only inside GitLab CI).
export DB_HOST="$TEST_DB_SERVICE_HOST" DB_PORT=5432 TEST_DB_NAME=supplier_test
echo "db-setup: roles, supplier and supplier_test ready on $TEST_DB_SERVICE_HOST"
