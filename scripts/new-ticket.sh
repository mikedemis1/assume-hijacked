#!/bin/sh
# File one ticket for a customer in the kind database and print its id.
#   sh scripts/new-ticket.sh <customer_id> "<ticket text>"
# Runs psql inside the ah-data PostgreSQL pod with kubectl exec (cluster up, chart deployed). The
# text reaches psql as a variable (:'body'), never inside the SQL string, so quotes in it are data.
set -eu

CONTEXT=kind-ah

if [ "$#" -ne 2 ]; then
    echo "usage: sh scripts/new-ticket.sh <customer_id> \"<ticket text>\"" >&2
    exit 2
fi
customer=$1
body=$2
case $customer in
    '' | *[!0-9]*)
        echo "the customer id must be a number, got: $customer" >&2
        exit 2
        ;;
esac

# The ticket id is a plain integer column: take the next free one. psql expands :'body' and
# :customer only from standard input, so the statement goes in through stdin.
# The pod's own POSTGRES_USER and POSTGRES_DB are used (the chart sets them).
printf '%s\n' \
    "INSERT INTO tickets (id, customer_id, body)" \
    "SELECT COALESCE(MAX(id), 0) + 1, :customer, :'body' FROM tickets RETURNING id;" |
    kubectl --context "$CONTEXT" --namespace ah-data exec -i statefulset/postgres -- \
        sh -c 'psql -X -q -t -A -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v customer="$1" -v body="$2"' \
        sh "$customer" "$body"
