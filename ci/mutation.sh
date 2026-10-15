#!/bin/sh
# Mutation testing with mutmut 3 (settings in pyproject.toml [tool.mutmut]):
# https://mutmut.readthedocs.io/en/latest/
# mutmut changes the code one small edit at a time (a < becomes <=, a constant changes ...) and
# runs the tests that cover it. A mutant the tests do not notice "survived": a wall whose test
# would not catch that change. Slow, so CI runs it on schedules and by hand only.
#
# Score (ci/mutation_score.py) = (killed + timeout) / every mutant that was run (killed,
# timeout, survived, no tests, suspicious, segfault), compared at one decimal with the README.md
# line "Mutation score baseline `<MUTANTS>`: NN.N%". The job fails below it.
#
# One mutant at a time (--max-children 1): every test truncates and reseeds the same database,
# so two test runs in parallel would break each other and count as kills.
#
# MUTANTS (required): which mutants, by name pattern, one per CI matrix job: "app.agent.core*",
# "app.agent.guard*", "app.executor*" or "app.tools.lookup_account*". The four jobs run in
# parallel, each with its own database.
# PC: mutmut needs fork(), so the script runs the CI job's steps in Docker: a throwaway
# PostgreSQL container (the CI service image) on a private network, and the CI Python image
# with GITLAB_CI=true so ci/db-setup.sh builds the database exactly as in CI. Your Compose stack
# is not touched. (Sharing the Compose db container's network would not work: the postgres image
# trusts every login on 127.0.0.1, which breaks the per-role password tests.)
# MUTATION_DOCKER_ARGS: extra `docker run` options for the Python container (e.g. a CA bundle).
. ci/lib.sh

if ! in_tool_image; then
    net="mutation-$$"
    db="mutation-db-$$"
    docker network create "$net" >/dev/null
    trap 'docker rm -f "$db" >/dev/null 2>&1 || true; docker network rm "$net" >/dev/null 2>&1 || true' EXIT
    docker run -d --rm --name "$db" --network "$net" --network-alias postgres \
        -e POSTGRES_DB=supplier -e POSTGRES_PASSWORD="$CI_POSTGRES_BOOTSTRAP_PASSWORD" \
        "$POSTGRES_IMAGE" >/dev/null
    # shellcheck disable=SC2086  # MUTATION_DOCKER_ARGS is a list of options on purpose
    rerun_in "$PYTHON_IMAGE" ci/mutation.sh --network "$net" -e GITLAB_CI=true \
        -e TEST_DB_SERVICE_HOST=postgres -e POSTGRES_BOOTSTRAP_PASSWORD="$CI_POSTGRES_BOOTSTRAP_PASSWORD" \
        -e MUTANTS="${MUTANTS:-}" ${MUTATION_DOCKER_ARGS:-}
    exit
fi

if [ -z "${MUTANTS:-}" ]; then
    echo 'mutation: set MUTANTS, e.g. MUTANTS="app.agent.guard*" sh ci/mutation.sh' >&2
    exit 1
fi
marker="Mutation score baseline \`$MUTANTS\`:"
baseline=$(grep -F "$marker" README.md | sed -n 's/.*: *\([0-9][0-9.]*\)%.*/\1/p' | head -n 1)
if [ -z "$baseline" ]; then
    echo "mutation: no line '$marker NN.N%' in README.md" >&2
    exit 1
fi

install_python_tools
if in_ci; then
    . ci/db-setup.sh
fi

mutmut run --max-children 1 "$MUTANTS"
mutmut export-cicd-stats
python ci/mutation_score.py mutants/mutmut-cicd-stats.json "$baseline"
