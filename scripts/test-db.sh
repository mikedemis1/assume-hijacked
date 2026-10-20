#!/bin/sh
# The database the pytest suite runs against. Works from any directory.
#   sh scripts/test-db.sh start   start container ah-test-db (replaces one that already exists)
#   sh scripts/test-db.sh stop    remove it
#
# The postgres image pinned by digest (below), three log flags that keep statement parameters out
# of the log, and db/init/init.sh run by the image on an empty data directory, so the roles, supplier and
# supplier_test are what the suite expects. The init files are copied into the container with
# `docker cp` before it starts, not bind-mounted: on Docker Desktop for Windows a bind mount from a
# Git Bash path is sometimes empty (in any path form), and then init.sh silently never runs.
# Only a database for tests: the suite TRUNCATEs every table (tests/conftest.py refuses a DB_HOST
# that is not local).
#
# Settings come from .env, as in tests/conftest.py (a variable already in the environment wins):
# POSTGRES_PASSWORD, the DB_PASSWORD_* of every role (.env.example lists them) and DB_PORT
# (default 5432). The port is published on 127.0.0.1 only.
set -eu

# Work from the repository root, wherever the script is called from.
cd "$(dirname "$0")/.."

NAME=ah-test-db
# Pinned by digest. Keep in step with the postgres image in deploy/helm/assume-hijacked/values.yaml.
IMAGE=postgres:17-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24
SECRETS="POSTGRES_PASSWORD
DB_PASSWORD_TOOL_READ_TICKET
DB_PASSWORD_TOOL_LOOKUP_ACCOUNT
DB_PASSWORD_TOOL_REQUEST_DISCONNECTION
DB_PASSWORD_TOOL_ISSUE_BILL_CREDIT
DB_PASSWORD_TOOL_SET_TEMP_PROTECTION
DB_PASSWORD_EXECUTOR
DB_PASSWORD_APPROVER
DB_PASSWORD_GATEWAY
DB_PASSWORD_RISK_ENGINE
DB_PASSWORD_DISPATCHER
DB_PASSWORD_REGISTER_SYNC"

# Read NAME=value lines of .env for the names this script needs, without sourcing the file
# (a value may hold spaces). Not overriding what is already exported.
load_env() {
    [ -f .env ] || return 0
    for var in DB_PORT $SECRETS; do
        eval "[ -n \"\${$var:-}\" ]" && continue
        value=$(sed -n "s/^$var=//p" .env | tail -n 1 | tr -d '\r')
        [ -n "$value" ] && export "$var=$value"
    done
    return 0
}

start() {
    load_env
    missing=""
    for var in $SECRETS; do
        eval "[ -n \"\${$var:-}\" ]" || missing="$missing $var"
    done
    if [ -n "$missing" ]; then
        echo "test-db: not set in .env or the environment:$missing (see .env.example)" >&2
        exit 1
    fi
    port="${DB_PORT:-5432}"

    # Git Bash on Windows rewrites paths that start with / before docker sees them.
    export MSYS_NO_PATHCONV=1

    docker rm -fv "$NAME" >/dev/null 2>&1 || true
    # -e NAME without a value passes the variable on from this shell: no password on a command line.
    docker create --name "$NAME" \
        -p "127.0.0.1:$port:5432" \
        -e POSTGRES_DB=supplier \
        -e POSTGRES_PASSWORD \
        -e DB_PASSWORD_TOOL_READ_TICKET \
        -e DB_PASSWORD_TOOL_LOOKUP_ACCOUNT \
        -e DB_PASSWORD_TOOL_REQUEST_DISCONNECTION \
        -e DB_PASSWORD_TOOL_ISSUE_BILL_CREDIT \
        -e DB_PASSWORD_TOOL_SET_TEMP_PROTECTION \
        -e DB_PASSWORD_EXECUTOR \
        -e DB_PASSWORD_APPROVER \
        -e DB_PASSWORD_GATEWAY \
        -e DB_PASSWORD_RISK_ENGINE \
        -e DB_PASSWORD_DISPATCHER \
        -e DB_PASSWORD_REGISTER_SYNC \
        "$IMAGE" \
        postgres \
        -c log_min_error_statement=panic \
        -c log_parameter_max_length=0 \
        -c log_parameter_max_length_on_error=0 >/dev/null
    # Two folders: db/init into the entrypoint's init folder and
    # db/sql at /db/sql, where init.sh looks for the SQL (`docker cp db` makes /db, with sql in it).
    docker cp db/init/. "$NAME:/docker-entrypoint-initdb.d"
    docker cp db "$NAME:/"
    docker start "$NAME" >/dev/null

    # init.sh runs on a temporary server that listens on the socket only, so a TCP answer means
    # init is finished and supplier_test exists.
    tries=0
    until docker exec "$NAME" pg_isready -q -h 127.0.0.1 -U postgres -d supplier_test; do
        tries=$((tries + 1))
        if [ "$tries" -ge 90 ] || [ "$(docker inspect -f '{{.State.Running}}' "$NAME")" != "true" ]; then
            echo "test-db: the database did not come up; last log lines:" >&2
            docker logs --tail 20 "$NAME" >&2
            exit 1
        fi
        sleep 1
    done
    if ! docker exec "$NAME" psql -U postgres -d supplier_test -qtAc "SELECT 1 FROM tickets LIMIT 1" >/dev/null; then
        echo "test-db: supplier_test was not built by db/init/init.sh; last log lines:" >&2
        docker logs --tail 20 "$NAME" >&2
        exit 1
    fi
    echo "test-db: $NAME ready on 127.0.0.1:$port (databases supplier and supplier_test)"
}

case "${1:-}" in
    start) start ;;
    stop)
        # A missing container is fine; a Docker that does not answer is not.
        docker info >/dev/null 2>&1 || { echo "test-db: Docker is not running" >&2; exit 1; }
        if docker inspect --type container "$NAME" >/dev/null 2>&1; then
            docker rm -fv "$NAME" >/dev/null
            echo "test-db: $NAME removed"
        else
            echo "test-db: $NAME is not running"
        fi
        ;;
    *)
        echo "usage: sh scripts/test-db.sh start|stop" >&2
        exit 2
        ;;
esac
