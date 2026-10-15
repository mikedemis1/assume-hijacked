# Shared helpers for ci/*.sh. Sourced, not run: `. ci/lib.sh`.
# Every script runs in two places:
#   - GitLab CI (GITLAB_CI=true): the job image already is the tool, so the tool runs directly.
#   - A developer PC: the script starts the same pinned image with `docker run` and runs itself
#     again inside it (IN_TOOL_IMAGE=1), so both paths run the same commands. bandit, pip-audit
#     and pytest run from the project's virtualenv instead; mutmut needs Linux (ci/mutation.sh).
# Run every script from the repository root: `sh ci/secrets.sh`.

set -eu

# Pinned images, the same references as in .gitlab-ci.yml (tests/test_ci.py checks they match).
# Tag first for humans, digest for the pull. Each tag was at least 14 days old when pinned
# (Docker Hub tag_last_pushed, checked 2026-10-15).
GITLEAKS_IMAGE="zricethezav/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"
HADOLINT_IMAGE="hadolint/hadolint:v2.15.1-alpine@sha256:a1d49ae1a4e83c1dbad26b8c1ad7588c8bd1e04f4866b34ad3cac50335198552"
CHECKOV_IMAGE="bridgecrew/checkov:3.3.21@sha256:9aefe56582004ebdac112fe85c3268dc4d3658231a8f023fb714ba9d29539d53"
TRIVY_IMAGE="aquasec/trivy:0.74.0@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969"
# Same digest as the Dockerfile base image: the tests run on the Python that ships.
PYTHON_IMAGE="python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1"
# Same digest as the db in compose.yaml: the CI test database is the one that ships.
POSTGRES_IMAGE="postgres:17-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24"
# The CI database's first password, replaced at once by ci/db-setup.sh (see .gitlab-ci.yml).
CI_POSTGRES_BOOTSTRAP_PASSWORD="bootstrap-only-replaced-by-ci-db-setup"

in_ci() {
    [ "${GITLAB_CI:-}" = "true" ]
}

# True inside the tool's image: a CI job, or the container started by rerun_in().
in_tool_image() {
    in_ci || [ "${IN_TOOL_IMAGE:-}" = "1" ]
}

# Git Bash on Windows: no MSYS path rewriting of container-side arguments such as /repo.
if command -v cygpath >/dev/null 2>&1; then
    export MSYS_NO_PATHCONV=1
fi

# Absolute path of the repository for `docker run -v` (a Windows path under Git Bash).
repo_mount() {
    if command -v cygpath >/dev/null 2>&1; then
        cygpath -w "$PWD"
    else
        printf '%s\n' "$PWD"
    fi
}

# rerun_in <image> <script> [docker run options...]: run <script> again inside <image>, with
# the repository mounted at /repo. Used on a PC only.
rerun_in() {
    image=$1
    script=$2
    shift 2
    docker run --rm -v "$(repo_mount):/repo" -w /repo -e IN_TOOL_IMAGE=1 "$@" \
        --entrypoint sh "$image" "$script"
}

# Python with the dev tools: the virtualenv on a PC, the job's interpreter in CI.
python_bin() {
    if [ -n "${PYTHON:-}" ]; then
        printf '%s\n' "$PYTHON"
    elif [ -x .venv/Scripts/python.exe ]; then
        printf '%s\n' .venv/Scripts/python.exe
    elif [ -x .venv/bin/python ]; then
        printf '%s\n' .venv/bin/python
    else
        printf '%s\n' python3
    fi
}

# CI only: the runtime packages and the dev tools from requirements-dev.lock. pip refuses any
# file whose sha256 is not in the lock, the same rule as the image build, also for files from
# its download cache (PIP_CACHE_DIR, kept between jobs by the .pip-cache template in CI).
install_python_tools() {
    python -m pip install --quiet --root-user-action=ignore \
        --require-hashes -r requirements-dev.lock
}

# Docker-in-Docker: the dind service may still be starting (and writing its TLS certificates)
# when the job script begins. Wait until `docker info` answers, at most about 30 s.
# https://docs.gitlab.com/ci/docker/docker_in_docker/
wait_for_docker() {
    tries=0
    until docker info >/dev/null 2>&1; do
        tries=$((tries + 1))
        if [ "$tries" -ge 30 ]; then
            echo "the Docker daemon did not answer within 30 s (DOCKER_HOST=${DOCKER_HOST:-unset})" >&2
            docker info >&2 || true
            return 1
        fi
        sleep 1
    done
}

# 48 random hex characters, for throwaway passwords. Plain POSIX tools: works on Alpine and Debian.
rand_hex() {
    od -An -N24 -tx1 /dev/urandom | tr -d ' \n'
}
