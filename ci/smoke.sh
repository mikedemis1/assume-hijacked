#!/bin/sh
# Smoke tests (pytest -m smoke) against the real Compose stack: the agent container answers a
# ticket, an attack ticket leaks nothing, and no walled container reaches the internet or DNS.
# CI: Docker-in-Docker (https://docs.gitlab.com/ci/docker/using_docker_build/). The job writes
# a .env with random passwords, starts the stack on the job's own daemon and runs pytest in
# ci/smoke-runner.Dockerfile on that daemon's host network (the db port is published on its
# 127.0.0.1, as on a PC). CI=true makes a test that cannot prove the wall fail instead of skip.
# PC: uses your running stack and .env, and the virtualenv's pytest.
. ci/lib.sh

mkdir -p reports
if in_ci; then
    umask 077
    {
        echo "POSTGRES_PASSWORD=$(rand_hex)"
        for role in TOOL_READ_TICKET TOOL_LOOKUP_ACCOUNT TOOL_REQUEST_DISCONNECTION \
                    TOOL_ISSUE_BILL_CREDIT TOOL_SET_TEMP_PROTECTION EXECUTOR APPROVER \
                    GATEWAY RISK_ENGINE DISPATCHER REGISTER_SYNC; do
            echo "DB_PASSWORD_$role=$(rand_hex)"
        done
        echo "DB_HOST=127.0.0.1"
        echo "DB_PORT=5440"
        echo "VULNERABLE=false"
    } > .env
    umask 022
fi

wait_for_docker
docker compose up -d --build --wait
docker compose --profile manual build agent

if in_ci; then
    docker build -f ci/smoke-runner.Dockerfile -t assume-hijacked-smoke-runner .
    docker run --rm --network host -e CI=true \
        -v /var/run/docker.sock:/var/run/docker.sock -v "$PWD:$PWD" -w "$PWD" \
        assume-hijacked-smoke-runner python -m pytest -m smoke -q --junitxml=reports/smoke-junit.xml
else
    "$(python_bin)" -m pytest -m smoke -q --junitxml=reports/smoke-junit.xml
fi
