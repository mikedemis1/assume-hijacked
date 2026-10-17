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
| `sast` | bandit on `app/` and `secops/` | medium or high severity at medium or high confidence | virtualenv |
| `deps` | pip-audit on `requirements.lock` and `requirements-dev.lock` | any known vulnerability | virtualenv (set `REQUESTS_CA_BUNDLE` if your network intercepts HTTPS) |
| `lock-check` | pip-compile again, compared with both locks | a difference (non-blocking) | Python image, needs plain PyPI access (the `docker run` is in the header of `ci/lock-check.sh`) |
| `lint-container-hadolint` | hadolint on both Dockerfiles | warning or error | hadolint image |
| `lint-container-checkov` | checkov on both Dockerfiles and `.gitlab-ci.yml` | a failed check | checkov image |
| `iac-terraform` | `terraform fmt -check`, `init -backend=false`, `validate` and `terraform test` (mock providers) on `infra/base`, `net`, `lab` and `modules/workload-identity` | a format difference, an invalid configuration, a failed test, a lock file that does not cover the providers | `terraform` binary, else the pinned image |
| `iac-tflint` | tflint with `.tflint.hcl` (bundled terraform rules and the pinned azurerm ruleset) | any finding | `tflint` binary, else the pinned image |
| `iac-checkov` | checkov on `infra/`, and on the Helm chart in `deploy/` rendered for kind and Azure | a failed check, a scan that found nothing, a file it could not parse | checkov image |
| `chart-tests` | `tests/k8s/test_chart.py` (helm lint and template, no cluster) on a pinned helm image | a failed test, and also a skipped one | your virtualenv and `helm`, else the pinned image |
| `test` | pytest against a PostgreSQL service, JUnit report | a failed test | your Compose db |
| `permissions` | `python -m secops.permassess` on the database `db/sql` builds and the networks of `compose.yaml`, compared with `security/expected-permissions.json`; reports in `reports/permissions/` | any extra or missing permission line, a plane it cannot read, an out-of-date `docs/permission-matrix.md` | your Compose db and `docker compose config` |
| `build-scan` | `docker build`, then trivy on the image: a full report (artifact) and the gate | HIGH or CRITICAL with a fixed version | Docker Desktop |
| `smoke` | the whole Compose stack, `pytest -m smoke` | a failed or skipped wall test | your running stack |
| `mutation` | mutmut on the walls | score below the baseline | Python image and a throwaway PostgreSQL, as in CI |

The `test` and `mutation` jobs get an empty PostgreSQL service container. It cannot mount `db/init`, so `ci/db-setup.sh` runs the same `db/init/init.sh` against it over the network. The service starts with a fixed bootstrap password written in the pipeline; the script replaces it with a random one first, and gives every role a random password. Nothing secret is stored in the repository or in CI variables. The Python jobs keep pip's download cache between pipelines, keyed on `requirements-dev.lock`; pip still checks every cached file against the lock's hashes.

Limits of the test database guard in CI. It accepts the alias in `TEST_DB_SERVICE_HOST` only with `GITLAB_CI=true` and only as a bare name, so a typo or a copied production address fails before any table is truncated. It cannot stop someone who means it: project and group CI/CD variables override the ones in `.gitlab-ci.yml`, so a maintainer can point `TEST_DB_SERVICE_HOST` somewhere else. On a self-hosted runner a bare name can also resolve through the host's DNS search domains (`postgres` becoming `postgres.corp.example`). The guard stops accidents, not a determined admin; a runner that can reach a real database should not run this pipeline.

Merge requests from forks run this pipeline with the fork's code. That exposes nothing here: no job uses secrets, protected variables or deploy credentials, and every password is made inside the job. `build-scan` and `smoke` need privileged Docker-in-Docker, and a privileged container can act as root on the runner machine, so the runner has to trust the code it runs. Use runners where that is acceptable (GitLab.com's own, or a dedicated runner for this project), and do not run fork pipelines on a shared privileged runner that also does other work.

`build-scan` and `smoke` use Docker-in-Docker, so they need a runner that allows privileged containers (GitLab.com's own runners do). `smoke` runs on the default branch, on schedules and by hand. It writes a `.env` with random passwords, starts the stack and runs pytest in `ci/smoke-runner.Dockerfile` on the same Docker daemon. Both jobs were rehearsed on a PC with a local `docker:dind` container set up like a GitLab Docker executor (TLS, alias `docker`, shared `/builds`): smoke 16 passed, build-scan clean. Both now run on GitLab.com's shared runners.

checkov has no Docker Compose framework, so `compose.yaml` is not scanned by a policy tool. Its walls are checked by the smoke tests instead.

## IaC checks

`sh ci/iac.sh` runs the three IaC steps in a row on a PC; in CI each step is its own job (`IAC_STEP=terraform|tflint|checkov`), because the Terraform image has no tflint and the reverse. Nothing here talks to Azure and nothing costs money.

- On this PC Terraform needs `TF_DISABLE_PLUGIN_TLS=1` in your shell (the antivirus breaks the provider plugin handshake). The scripts pass it on if it is set and never set it; nothing in `.gitlab-ci.yml` sets it.
- `terraform init` runs with `-lockfile=readonly`: the committed `.terraform.lock.hcl` (hashes for Windows and Linux) must already cover the providers.
- tflint downloads its azurerm ruleset from GitHub on `--init`; the version is pinned in `.tflint.hcl`.
- An accepted checkov finding in Terraform carries `#checkov:skip=CKV_xxx: reason` in the resource. Each skip names the lab decision behind it (Basic container registry, Free AKS tier, public endpoint behind the Key Vault firewall, and so on). For the chart, checkov cannot skip one rendered object, so `ci/iac.sh` lists four checks for the whole chart with the reason next to them.
- checkov exits 0 when it parsed nothing, so `ci/iac.sh` fails when no check passed or a file could not be parsed. Behind Docker Desktop on this PC, a directory listing sometimes fails with "Cannot allocate memory" while the machine is busy and checkov then sees an empty folder; the script tries a scan that found nothing up to five times.
- Without a `deploy/` folder the checkov step skips the chart and says so; the CI job sets `IAC_REQUIRE_DEPLOY=true`, so a pipeline without `deploy/` fails. The chart is rendered with `ci/chart-values/{kind,azure}.json`, stand-in install values that match the ones in `tests/k8s/test_chart.py`. Update both together.
- `chart-tests` uses the `alpine/helm` image, which has no Python: the script installs `python3` from Alpine and only pytest and PyYAML (and their dependencies) from `requirements-dev.lock`, hash-checked.

## Azure jobs

Five jobs are defined and switched off, in the stage `azure`: `tf-plan`, `tf-apply`, `tf-destroy-plan`, `tf-destroy` and `leftover-check`. They do not exist in a pipeline until the project variable `AZURE_ENABLED` is `true`, and then each one waits for a click (`when: manual`). Nothing is stored: each job asks GitLab for an ID token (`id_tokens`, audience `api://AzureADTokenExchange`), Entra checks it against a federated credential from `infra/base/ci-identities.tf` and returns an Azure token, which terraform reads from `ARM_OIDC_TOKEN`.

| Job | Identity | Runs on | What it does |
|-----|----------|---------|--------------|
| `tf-plan` | `ci-plan` (Reader, state blob reader) | any branch | plan `infra/net`, then `infra/lab`, with `-lock=false`; saves the plan files and a readable copy (`plans/apply/`, artifact, one day) |
| `tf-apply` | `ci-apply` (Contributor on rg-net and rg-lab) | main | needs `tf-plan` of the same pipeline and applies exactly its plan files, net then lab. It never plans |
| `tf-destroy-plan` | `ci-plan` | any branch | `plan -destroy` for lab, then net; saves them (`plans/destroy/`). Stops if a state manages a resource group |
| `tf-destroy` | `ci-apply` | main | needs `tf-destroy-plan` of the same pipeline and applies its plans, lab then net. Checks both states again first; a managed resource group, or a state it cannot read, stops it |
| `leftover-check` | `ci-plan` | any branch | lists everything in rg-lab and every billable resource type in the subscription; fails if any is left |

The order is: run `tf-plan`, read the `.txt` files in its artifact, then run `tf-apply`. Apply fails if the plan files are missing, were made for another commit, or no longer match the state (terraform refuses a stale plan). `infra/lab` reads the net state, and its plan was made before net changed: if net had changes, `tf-apply` applies net and then stops with an error before lab. Run `tf-plan` again (it now sees the new net state), read it, and run `tf-apply`. Destroy works the same way with `tf-destroy-plan` and `tf-destroy`. The plan files can hold resource values. The job log of a public project is public, so it shows only the counts (`Plan: X to add, Y to change, Z to destroy.`); terraform's full output and the readable copy stay in the artifact, which expires after one day and, with `artifacts:access: developer`, only members with the Developer role or above can download. Terraform's error messages still go to the log.

`infra/base` is not planned or applied in CI, on purpose. It holds the CI identities and the role assignments they may hand out, so a job that could apply it could widen its own rights. It needs Microsoft Graph rights for the Entra applications, which neither CI identity has, so even a plan would fail. The owner applies it from a PC; every push still runs fmt, validate, `terraform test`, tflint and checkov on it. `destroy` removes the contents of rg-net and rg-lab, never the groups and never base, because `infra/net` and `infra/lab` only read the groups, which `infra/base` creates empty.

The stacks keep their `backend "azurerm"` block commented out until the owner has migrated the state. The jobs write a `zz_backend_override.tf` with an empty backend and pass the settings with `-backend-config`; that file is ignored by git. Project variables (none is a secret): `AZURE_ENABLED`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`, `AZURE_CI_PLAN_CLIENT_ID`, `AZURE_CI_APPLY_CLIENT_ID`, `TF_STATE_STORAGE_ACCOUNT`, and the optional File variables `TFVARS_NET` and `TFVARS_LAB` for the values kept out of git (address ranges, e-mail address, admin group). `tf-apply` and `tf-destroy` share the GitLab `resource_group: azure-lab`, so only one runs at a time. None of these jobs has run against Azure yet; `tests/test_ci.py` runs the real scripts against stand-in `terraform` and `az` programs to check the order, that apply and destroy use the saved plans and never plan, the main-only rule and the destroy guard.

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
