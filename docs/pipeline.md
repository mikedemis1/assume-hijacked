# CI pipeline

The short version is in the [README](../README.md#ci-pipeline).

## How this repo is checked

| Layer | Command | What it answers |
|-------|---------|-----------------|
| Unit and attack tests | `python -m pytest` | Does each wall refuse its attack? Needs the db container running |
| Smoke tests | `python -m pytest -m smoke` | Do the real containers behave: the agent answers, an attack ticket leaks nothing, no container reaches the internet. Needs the full stack running |
| Pipeline checks | `sh ci/<job>.sh` | Secrets in history, static analysis, vulnerable packages, Dockerfile lint, image scan. The same scripts GitLab runs (next section) |
| Mutation tests | `sh ci/mutation.sh` | Do the tests notice when a wall's code is edited? Slow, schedules and by hand only |

The tests read `.env` for the passwords and DB_PORT. Each test truncates the tables and loads the seed data again, so the tests run in their own database, `supplier_test`, which `db/init/init.sh` creates next to the stack's `supplier`. `init.sh` runs only when the database volume is empty: on a stack created before `supplier_test` existed, or after any change in `db/sql/`, run `docker compose down -v` and `docker compose up -d --build` once (this also resets the stack's data). The suite refuses to start if `TEST_DB_NAME` is `supplier` or `DB_HOST` is not local. The one exception is GitLab CI: there the database is the job's own PostgreSQL service, and `DB_HOST` may be its alias if `GITLAB_CI=true`, it equals `TEST_DB_SERVICE_HOST` from the pipeline, and it is a bare name (no dots, not an IP address).

## Jobs

`.gitlab-ci.yml` runs the checks below on every branch push or merge request (`mutation` and `smoke` have their own rules). Each job runs one script in `ci/`, and each script also runs on a PC: `sh ci/<name>.sh` from the repository root, in Git Bash on Windows, with the virtualenv from the README for `sast`, `deps`, `test` and `smoke`. The scanner images are pinned by tag and digest, each tag at least 14 days old when pinned; `ci/lib.sh` has the same references for local runs and `tests/test_ci.py` fails if the two differ.

| Job | Tool | Fails on | On a PC |
|-----|------|----------|---------|
| `secrets` | gitleaks, whole git history (`GIT_DEPTH: 0`, all branches) | any secret | gitleaks image |
| `sast` | bandit on `app/` | medium or high severity at medium or high confidence | virtualenv |
| `deps` | pip-audit on `requirements.lock` and `requirements-dev.lock` | any known vulnerability | virtualenv (set `REQUESTS_CA_BUNDLE` if your network intercepts HTTPS) |
| `lock-check` | pip-compile again, compared with both locks | a difference (non-blocking) | Python image, needs plain PyPI access (the `docker run` is in the header of `ci/lock-check.sh`) |
| `lint-container-hadolint` | hadolint on both Dockerfiles | warning or error | hadolint image |
| `lint-container-checkov` | checkov on both Dockerfiles and `.gitlab-ci.yml` | a failed check | checkov image |
| `test` | pytest against a PostgreSQL service, JUnit report | a failed test | your Compose db |
| `build-scan` | `docker build`, then trivy on the image: a full report (artifact) and the gate | HIGH or CRITICAL with a fixed version | Docker Desktop |
| `smoke` | the whole Compose stack, `pytest -m smoke` | a failed or skipped wall test | your running stack |
| `mutation` | mutmut on the walls | score below the baseline | Python image and a throwaway PostgreSQL, as in CI |

The `test` and `mutation` jobs get an empty PostgreSQL service container. It cannot mount `db/init`, so `ci/db-setup.sh` runs the same `db/init/init.sh` against it over the network. The service starts with a fixed bootstrap password written in the pipeline; the script replaces it with a random one first, and gives every role a random password. Nothing secret is stored in the repository or in CI variables. The Python jobs keep pip's download cache between pipelines, keyed on `requirements-dev.lock`; pip still checks every cached file against the lock's hashes.

Limits of the test database guard in CI. It accepts the alias in `TEST_DB_SERVICE_HOST` only with `GITLAB_CI=true` and only as a bare name, so a typo or a copied production address fails before any table is truncated. It cannot stop someone who means it: project and group CI/CD variables override the ones in `.gitlab-ci.yml`, so a maintainer can point `TEST_DB_SERVICE_HOST` somewhere else. On a self-hosted runner a bare name can also resolve through the host's DNS search domains (`postgres` becoming `postgres.corp.example`). The guard stops accidents, not a determined admin; a runner that can reach a real database should not run this pipeline.

Merge requests from forks run this pipeline with the fork's code. That exposes nothing here: no job uses secrets, protected variables or deploy credentials, and every password is made inside the job. `build-scan` and `smoke` need privileged Docker-in-Docker, and a privileged container can act as root on the runner machine, so the runner has to trust the code it runs. Use runners where that is acceptable (GitLab.com's own, or a dedicated runner for this project), and do not run fork pipelines on a shared privileged runner that also does other work.

`build-scan` and `smoke` use Docker-in-Docker, so they need a runner that allows privileged containers (GitLab.com's own runners do). `smoke` runs on the default branch, on schedules and by hand. It writes a `.env` with random passwords, starts the stack and runs pytest in `ci/smoke-runner.Dockerfile` on the same Docker daemon. Both jobs were rehearsed on a PC with a local `docker:dind` container set up like a GitLab Docker executor (TLS, alias `docker`, shared `/builds`): smoke 16 passed, build-scan clean. Both now run on GitLab.com's shared runners.

checkov has no Docker Compose framework, so `compose.yaml` is not scanned by a policy tool. Its walls are checked by the smoke tests instead.

## Mutation testing

Mutation testing changes the code one small edit at a time and reruns the tests. A change no test notices is a gap in a wall's tests. The job runs on schedules and by hand only, one mutant at a time (the tests share one database), as one job per module so the modules run in parallel, each with its own database. Each fails below its baseline, measured on 2026-10-16 with the CI setup rehearsed locally (10 to 15 minutes per module). The baselines are in the README, because `ci/mutation.sh` reads them from there.

Score = (killed + timeout) / all mutants run. The scope is in `pyproject.toml`, `[tool.mutmut]`. mutmut needs `fork()`, so on a PC `ci/mutation.sh` runs the CI job's steps in Docker: a throwaway PostgreSQL container and the Python image, on a private network. Your Compose stack is not touched. `MUTANTS="app.agent.guard*" sh ci/mutation.sh` runs one module.

## Accepted findings

- bandit B104 (`app/tools/serve.py`, bind to 0.0.0.0): the agent reaches each tool from another container, and the tool containers are only on the internal `backend` network.
- checkov CKV_DOCKER_2 (`Dockerfile`, no HEALTHCHECK): one image runs the tool servers, the executor loop and the one-shot agent, and no single check fits all three.
- checkov CKV_DOCKER_2 and CKV_DOCKER_3 (`ci/smoke-runner.Dockerfile`, no HEALTHCHECK, runs as root): a one-shot test runner that needs the Docker socket, which is root on that daemon anyway.

As of 2026-10-15, trivy reports 44 HIGH vulnerabilities in the Debian packages of the base image (util-linux, ncurses, systemd libraries, perl-base) and none has a fixed version, so the gate passes. The gate fails as soon as Debian ships a fix and the base image digest is not updated. Unfixed ones stay hidden from the gate on purpose, including `fix_deferred` ones such as perl-base CVE-2026-9538, so `build-scan` also writes a full report of every severity, fixed or not (`reports/trivy-all.json` and `reports/gl-container-scanning-report.json`, kept 90 days). Review that report by 2027-01-15 or whenever the base image digest is bumped, whichever comes first. The real fix is a smaller runtime base without util-linux, ncurses or perl (a distroless Python image, or a slim image with those packages removed).

## What has run where

On 2026-10-15 these scripts were run on a PC: `secrets`, `sast`, `deps`, `lint-container-hadolint`, `lint-container-checkov` and `test` (all green), `build-scan` (clean, as above) and `smoke` (16 passed). `lock-check` could not run: the container has no CA bundle for the antivirus HTTPS scanning, and pip failed with a certificate error. `mutation` was last run for the baselines in the README.

On 2026-10-16 the pipeline ran on GitLab.com for the first time and every push job passed, `lock-check`, `build-scan` and `smoke` included. The `mutation` job has not run on GitLab yet. `tests/test_ci.py` also checks the pipeline's structure: every job has a stage, an image and one `ci/` script, every image is pinned by digest, and the mutation job never runs on a push.
