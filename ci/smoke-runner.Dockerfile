# Test runner for the smoke job (ci/smoke.sh, CI only): Python 3.12 with the locked test tools,
# plus the Docker CLI and Compose plugin, because the smoke tests drive the stack with
# `docker compose run/exec`. It runs on the job's Docker-in-Docker daemon, in that daemon's host
# network, where the db port is published on 127.0.0.1 exactly as on a PC.
FROM docker:29.8.1-cli@sha256:018edbc908e08fcc9dbf029c812c34251e9b4719e6f71ca0e5eae2a987d014ca AS docker

# Same base image and digest as the application Dockerfile.
FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1
COPY --from=docker /usr/local/bin/docker /usr/local/bin/docker
COPY --from=docker /usr/local/libexec/docker/cli-plugins/docker-compose /usr/local/libexec/docker/cli-plugins/docker-compose
WORKDIR /opt/runner
COPY requirements-dev.lock .
RUN pip install --no-cache-dir --root-user-action=ignore --require-hashes -r requirements-dev.lock
# One-shot test runner, never a service: nothing to health-check.
#checkov:skip=CKV_DOCKER_2: one-shot test runner, it exits when pytest ends; nothing to health-check
# It runs as root on purpose: the smoke tests need the Docker socket, and access to that socket
# is root on the daemon whatever the user inside. It runs only in CI, on that job's own daemon.
#checkov:skip=CKV_DOCKER_3: needs the Docker socket of the job's own dind daemon, which is root-equivalent anyway
