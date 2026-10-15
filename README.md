# assume-hijacked

Your AI agent got hijacked. Now what?

AI agents act through tools (MCP servers): they read tickets, query databases, open web pages. If the agent is tricked by a prompt injection, or one of the tools is malicious, whatever those tools can reach is exposed.

This project builds a sandbox on Azure where each tool runs in its own isolated box, with only the access it needs and a firewall in front of the internet. A hijacked agent should not be able to read more data than its task needs or send anything out, and every attempt shows up in the logs.

Status: the local stack works (code and database rules, no cloud) and the GitLab pipeline is written, but it has not run on a real GitLab runner yet. The Azure phase is next.

Planned stack: Azure, Terraform, Kubernetes (AKS), FortiGate, Entra ID, Prometheus and Grafana, a CI/CD pipeline with attack tests on every deploy.

## Run it locally

The scenario is a fictional electricity supplier. Its AI support agent reads customer tickets and can look up accounts, request credits and request disconnections. We assume the model is fully hijacked and see which walls still hold. All data is fake.

```
                +--> tool-read-ticket -----------+
                +--> tool-lookup-account --------+
agent --------> +--> tool-request-disconnection -+--> PostgreSQL <-- executor
                +--> tool-issue-bill-credit -----+
                +--> tool-set-temp-protection ---+
```

- Each tool is its own container with one MCP server and its own database role. A tool can only do what its role is granted in `db/sql/03-grants.sql`, and only on the columns its code reads: `tool_lookup_account` has no `phone`, and `tool_read_ticket` is the only role that reads ticket text.
- The executor is the only component that writes credits, occupier notices and disconnection orders. Tools only file requests; the executor checks them against the rules.
- Each request tool can file only its own kind of request. The database sets the account from the ticket owner, whatever account the tool sends.
- Every role can add audit events but cannot change or delete them. The database fills in who wrote an event and when, so a tool cannot forge either, and the executor only counts its own alerts.
- Only the executor and the temp-protection function can take advisory locks, so a tool cannot call `pg_advisory_lock` on a home. Executor sessions give up on a lock after 5 seconds and on a statement after 30; the request stays as it was, an `executor_error` event is written and the batch goes on. Every login role has a connection limit (tools 5, approver 5, executor 3).
- The database checks what the executor writes (rows 4 and 7 below). A trigger on `credits` refuses a row that does not match its request or that the charges do not back: the evidence must be a real duplicate charge on that account, the credit no more than the charge and never above 500.00. A trigger on `disconnection_orders` refuses an order unless the request is at `notice_sent` and the whole story in row 7 holds. A bug in the executor can still skip its own limits (the automatic limit, the monthly and daily caps), but it cannot pay anything except a real duplicate charge, once, or order a disconnection the story does not allow. The triggers stop bugs; a hijacked executor can also change a request's status, so the status check does not stop it.
- The agent container has no database password, only the five tool URLs.
- The tools, the executor and the agent are on the `backend` network, which has no route to the internet (`internal: true`). A hijacked component cannot send data out or download anything. Only the database is also on a second network, `hostaccess`, because Docker publishes no port for a container that is only on an internal network and the tests need one. That gives the database container a route out, and the smoke tests do not probe it. `pytest -m smoke` opens a TCP connection and a DNS lookup from each of the seven containers on `backend` (five tools, the executor, the agent) and fails if one gets through.
- Every role has its own password (`DB_PASSWORD_<ROLE>` in `.env`) and a container receives only its own.
- The model is `ScriptedLLM` in `app/agent/llm.py`. It stands in for a fully hijacked model and obeys any `CALL <tool> <json>` or `SAY <text>` line written in a ticket. No real LLM and no API key are needed.

### Prerequisites

Docker Desktop and Python 3.12. Commands below are PowerShell. In Git Bash, activate with `source .venv/Scripts/activate` and copy with `cp .env.example .env`.

### Steps

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"

Copy-Item .env.example .env
# edit .env: replace every change-me-* password with your own.
# Set DB_PORT=5433 (or another free port) if PostgreSQL already uses 5432 on this PC.

docker compose up -d --build
docker compose --profile manual run --rm agent python -m app.agent.main 1
```

The agent run answers ticket 1 with the account details of its own customer. The agent service is in the `manual` profile, so `up` does not start it.

The state register sync is simulated: the seed data records one successful sync when the database is created, and nothing refreshes it. From 24 hours after the first `docker compose up`, the register counts as stale, so every move-out request goes to `manual_only`. That is the fail-closed rule working, not a bug. `docker compose down -v` and `up` again start a fresh database with a fresh sync.

If your network intercepts HTTPS (antivirus scanning, a corporate proxy) and the image build fails on a certificate error, `.env.example` has two optional settings, `PIP_CERT_FILE` and `LOCAL_WHEELS_DIR`. They are read at build time only.

### Supply chain

- `requirements.lock` lists all 30 packages the images need, each with its sha256 hashes. The image build runs `pip install --only-binary :all: --require-hashes -r requirements.lock` and then `pip install --no-deps .`, so pip refuses a package whose file does not match a hash, and installs wheels only: no dependency's `setup.py` runs in the build (every locked package had a cp312 manylinux wheel with a locked hash on 2026-10-15). Two builds install the same files.
- Both base images are pinned by digest (`python:3.12-slim@sha256:...` in the `Dockerfile`, `postgres:17-alpine@sha256:...` in `compose.yaml`), with a comment naming the tag and the date the digest was resolved. A tag can move; a digest cannot. Updating is manual: `docker buildx imagetools inspect <tag>`, copy the top `Digest`, rebuild.
- `pyproject.toml` pins the runtime dependencies, `setuptools` (build) and the dev tools (`pytest`, `bandit`, `pip-audit`, `mutmut`, `pip-tools`) with `==`. `tests/test_supply_chain.py` fails if a locked package loses its hash, a dependency is no longer pinned, or an image goes back to a tag.
- A local wheel from `LOCAL_WHEELS_DIR` is installed only if its name and version are in the lock, and with the lock's hashes. A wheel with one changed byte fails the build.

To regenerate the lock after changing a dependency, run `pip-compile` in the same Python version as the image, not on the host:

```powershell
docker run --rm -v "${PWD}:/work" -w /work python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1 sh -c "pip install pip-tools==7.6.2 && pip-compile --generate-hashes --strip-extras --output-file=requirements.lock pyproject.toml"
```

Not covered: the build backend (`setuptools==84.0.0`) is pinned but downloaded without a hash check.

`requirements-dev.lock` is the same idea for the tests and the pipeline's tools (pytest, bandit, pip-audit, mutmut, pip-tools): every package hashed, and every runtime package at the same version and hashes as `requirements.lock` (`test_dev_lock_hashes_every_tool_and_ships_the_same_runtime_packages`). Regenerate it after `requirements.lock`, so the runtime packages stay the same:

```powershell
docker run --rm -v "${PWD}:/work" -w /work python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1 sh -c "pip install pip-tools==7.6.2 && pip-compile --generate-hashes --strip-extras --allow-unsafe --extra=dev --output-file=requirements-dev.lock pyproject.toml"
```

### How this repo is checked

| Layer | Command | What it answers |
|-------|---------|-----------------|
| Unit and attack tests | `python -m pytest` | Does each wall refuse its attack? Needs the db container running |
| Smoke tests | `python -m pytest -m smoke` | Do the real containers behave: the agent answers, an attack ticket leaks nothing, no container reaches the internet. Needs the full stack running |
| Pipeline checks | `sh ci/<job>.sh` | Secrets in history, static analysis, vulnerable packages, Dockerfile lint, image scan. The same scripts GitLab runs (next section) |
| Mutation tests | `sh ci/mutation.sh` | Do the tests notice when a wall's code is edited? Slow, schedules and by hand only |

The tests read `.env` for the passwords and DB_PORT. Each test truncates the tables and loads the seed data again, so the tests run in their own database, `supplier_test`, which `db/init/init.sh` creates next to the stack's `supplier`. `init.sh` runs only when the database volume is empty: on a stack created before `supplier_test` existed, or after any change in `db/sql/`, run `docker compose down -v` and `docker compose up -d --build` once (this also resets the stack's data). The suite refuses to start if `TEST_DB_NAME` is `supplier` or `DB_HOST` is not local. The one exception is GitLab CI: there the database is the job's own PostgreSQL service, and `DB_HOST` may be its alias if `GITLAB_CI=true`, it equals `TEST_DB_SERVICE_HOST` from the pipeline, and it is a bare name (no dots, not an IP address).

### CI pipeline

```
push or merge request
  static:    secrets  sast  deps  lock-check  lint-container-hadolint  lint-container-checkov
  test:      test (pytest against a PostgreSQL service)
  build:     build-scan (image + trivy)    smoke (whole stack; default branch, schedules, by hand)
schedule or by hand
  mutation:  one job per module
```

`.gitlab-ci.yml` runs the checks below on every branch push or merge request (`mutation` and `smoke` have their own rules). Each job runs one script in `ci/`, and each script also runs on a PC: `sh ci/<name>.sh` from the repository root, in Git Bash on Windows, with the virtualenv from the steps above for `sast`, `deps`, `test` and `smoke`. The scanner images are pinned by tag and digest, each tag at least 14 days old when pinned; `ci/lib.sh` has the same references for local runs and `tests/test_ci.py` fails if the two differ.

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

`build-scan` and `smoke` use Docker-in-Docker, so they need a runner that allows privileged containers (GitLab.com's own runners do). `smoke` runs on the default branch, on schedules and by hand. It writes a `.env` with random passwords, starts the stack and runs pytest in `ci/smoke-runner.Dockerfile` on the same Docker daemon. Both jobs were rehearsed on a PC with a local `docker:dind` container set up like a GitLab Docker executor (TLS, alias `docker`, shared `/builds`): smoke 16 passed, build-scan clean. They have not run on a real GitLab runner yet.

checkov has no Docker Compose framework, so `compose.yaml` is not scanned by a policy tool. Its walls are checked by the smoke tests instead.

Mutation testing changes the code one small edit at a time and reruns the tests. A change no test notices is a gap in a wall's tests. The job runs on schedules and by hand only, one mutant at a time (the tests share one database), as one job per module so the modules run in parallel, each with its own database. Each fails below its baseline, measured on 2026-10-15 with the CI setup rehearsed locally (10 to 15 minutes per module):

- Mutation score baseline `app.agent.core*`: 91.0%
- Mutation score baseline `app.agent.guard*`: 80.6%
- Mutation score baseline `app.executor*`: 78.5%
- Mutation score baseline `app.tools.lookup_account*`: 68.0%

Score = (killed + timeout) / all mutants run. The scope is in `pyproject.toml`, `[tool.mutmut]`. mutmut needs `fork()`, so on a PC `ci/mutation.sh` runs the CI job's steps in Docker: a throwaway PostgreSQL container and the Python image, on a private network. Your Compose stack is not touched. `MUTANTS="app.agent.guard*" sh ci/mutation.sh` runs one module.

Accepted findings, each with its reason in the file:

- bandit B104 (`app/tools/serve.py`, bind to 0.0.0.0): the agent reaches each tool from another container, and the tool containers are only on the internal `backend` network.
- checkov CKV_DOCKER_2 (`Dockerfile`, no HEALTHCHECK): one image runs the tool servers, the executor loop and the one-shot agent, and no single check fits all three.
- checkov CKV_DOCKER_2 and CKV_DOCKER_3 (`ci/smoke-runner.Dockerfile`, no HEALTHCHECK, runs as root): a one-shot test runner that needs the Docker socket, which is root on that daemon anyway.

As of 2026-10-15, trivy reports 44 HIGH vulnerabilities in the Debian packages of the base image (util-linux, ncurses, systemd libraries, perl-base) and none has a fixed version, so the gate passes. The gate fails as soon as Debian ships a fix and the base image digest is not updated. Unfixed ones stay hidden from the gate on purpose, including `fix_deferred` ones such as perl-base CVE-2026-9538, so `build-scan` also writes a full report of every severity, fixed or not (`reports/trivy-all.json` and `reports/gl-container-scanning-report.json`, kept 90 days). Review that report by 2027-01-15 or whenever the base image digest is bumped, whichever comes first. The real fix is a smaller runtime base without util-linux, ncurses or perl (a distroless Python image, or a slim image with those packages removed).

On 2026-10-15 these scripts were run on a PC: `secrets`, `sast`, `deps`, `lint-container-hadolint`, `lint-container-checkov` and `test` (all green), `build-scan` (clean, as above) and `smoke` (16 passed). `lock-check` could not run: the container has no CA bundle for the antivirus HTTPS scanning, and pip failed with a certificate error. `mutation` was last run for the baselines above.

GitLab's CI Lint API needs a project token, so the pipeline was checked locally only: YAML parse and the structure tests in `tests/test_ci.py` (every job has a stage, an image and one `ci/` script; every image pinned by digest; the mutation job never runs on a push).

### Attacks and what stops them

| # | Attack | Test | What stops it |
|---|--------|------|---------------|
| 1 | Hijacked agent asks for another customer's account | `test_injected_customer_id_is_ignored`, `test_llm_cannot_choose_the_ticket`, `test_agent_drops_customer_id_itself`, `test_dropped_argument_is_logged_by_name_only`, `test_lookup_ignores_foreign_customer_id_and_logs_it`, `test_attack_ticket_through_the_real_stack_leaks_nothing_and_is_logged` (smoke: seed ticket 4 asks for customer 1002 through the real containers) | The agent code sets the ticket and drops any other argument the model adds (`customer_id`, `ticket_id`). The tool takes the customer from the ticket, not from the model. The agent logs every dropped argument by name (JSON line on stderr, so the model cannot forge one in the reply on stdout; logger `assume_hijacked.security`; a name the model chose is logged only if it looks like an identifier, else `<invalid>`; also unknown tools, tool errors, blocked replies, the step limit and unreadable tickets, never ticket text, tool results or argument values) |
| 2 | Medical or vulnerability flag reaches the LLM | `test_only_executor_can_read_flags`, `test_reply_has_no_health_data`, `test_lookup_returns_owner_and_no_health_fields` | Among the login roles, only the executor can read the flags table |
| 3 | Flag changed from YES to NO | `test_tools_cannot_change_flags_directly`, `test_temp_protection_never_downgrades` | Tools have no write access to flags; the temp-protection tool can only add protection |
| 4 | Many small credits, or a negative or zero amount | `test_salami_on_same_evidence`, `test_monthly_cap_sends_the_rest_to_staff`, `test_credit_amount_must_be_positive`, `test_non_positive_amount_is_rejected`, `test_request_amount_must_be_a_positive_number`, `test_evidence_that_is_not_a_duplicate_goes_to_staff`, `test_evidence_from_another_account_is_not_accepted`, `test_database_refuses_a_credit_that_does_not_match_its_request`, `test_database_refuses_a_credit_the_charges_do_not_back` | Executor checks evidence, amount limits and caps; reasons come from a closed list. A claim it cannot check against the charges goes to staff. The database refuses a zero, negative or NaN amount on requests and on credits, and a credit row must be for a credit request, to that request's account, for exactly its amount and the evidence the request cites. The charges must back it too: the evidence is a charge on that account with an earlier charge of the same period and amount, the credit is no more than that charge, and no credit is above 500.00, a cap no setting can raise. The database sets the credit time, so a credit cannot be dated outside the daily and monthly windows. Five or more refused credit requests for one account in an hour raise an alert |
| 5 | Flood of move-out requests | `test_flood_is_rate_limited_and_alerts`, `test_forged_alert_does_not_silence_the_flood_alert` | Executor rate limit, plus an alert. A fake ALERT written by a tool does not stop the real one |
| 6 | Same staff member approves twice | `test_same_approver_twice_is_rejected` | One approval per approver name per request is a database key, so the database refuses the same name twice. It does not know who is behind the name (see below). No code path needs two approvals today: protected homes are never handled by code |
| 7 | Disconnection at a protected home | `test_tools_cannot_order_disconnections`, `test_protected_home_never_gets_order`, `test_stale_register_means_protected`, `test_protected_home_with_notice_and_two_approvals_still_gets_no_order`, `test_database_refuses_order_at_protected_home`, `test_database_refuses_order_when_register_is_stale`, `test_database_refuses_order_unless_the_whole_story_holds`, `test_database_refuses_order_unless_the_request_is_at_notice_sent`, `test_no_order_without_approval`, `test_no_order_before_wait`, `test_no_order_before_the_move_out_date`, `test_approval_given_before_the_notice_does_not_count`, `test_executor_takes_the_home_lock`, `test_trigger_takes_the_home_lock` | Only the executor can create orders, and it refuses protected homes. A register that has not synced in 24 hours counts as protected. A database trigger checks every order row against its request: it must be a move-out at `notice_sent` (not one sent to a human as `manual_only` or `held_rate_limit`), for that request's own home (exact string), at a home that is not protected, with an occupier notice at least 72 hours old, a staff approval given after the notice, and a move-out date that has come. The trigger uses the database clock and the database sets the notice and order times, so the executor cannot pass in a time of its own. A lock per home stops a new flag and an order from interleaving. The executor's own code checks the same things first (approval, wait, date, lock), and each has its own test |
| 8 | Reply that promises money | `test_reply_never_promises_amount`, `test_guard_blocks_money_promises`, `test_guard_blocks_money_wording_without_a_number`, `test_credit_call_adds_the_notice_after_the_guard`, `test_guard_blocks_the_known_bypasses`, `test_guard_blocks_the_reviewer_bypasses`, `test_agent_blocks_a_number_the_tools_never_returned`, `test_credit_request_has_no_amount_in_message` | The reply guard fails closed. A digit number in a reply must be one a tool returned in the same conversation (compared by value, so 49, 49.00 and 49,00 are the same; the ticket text and error messages do not count). Any English or Greek number word from two to a hundred is blocked, with or without a verb (including one-word forms like `fortynine`). Currency symbols (any Unicode currency sign) and currency words are blocked. A reply with a letter that is not Latin or Greek, or a word that mixes Latin and Greek letters (lookalikes such as a Cyrillic `e`), is blocked. Money wording (credit, refund, back, off, pay, πίσω, επιστροφή ...) is blocked on its own, with or without a number: "your credit has been approved" is a promise too. Text is normalised first (NFKC, no accents, case folded). A blocked reply is replaced by a fixed text. The credit tool's answer is a fixed message with no amount. After any `issue_bill_credit` call, whether it worked or not, the agent code (not the model) adds a fixed line after the guard, in English and Greek: "No credit is confirmed until it has been checked." Limits: the number words, currency words and money verbs are lists, and a list can never be complete; a spelling nobody listed gets through, and the lists block some harmless text ("recently", "σε 5 λεπτά", "call us back"). The guard cannot tell what a number from a tool means, so `Patision 10` can be repeated in a misleading sentence that avoids every list. The robust fix is replies built from templates with structured fields instead of free text (future work). Only the executor decides money |
| 9 | A tool holds a home's lock or uses up connections to freeze the executor | `test_only_the_executor_can_take_advisory_locks`, `test_every_login_role_has_a_connection_limit`, `test_a_tool_role_cannot_open_more_connections_than_its_limit`, `test_executor_sessions_time_out_on_locks_and_statements`, `test_a_held_home_lock_fails_that_request_and_the_batch_goes_on` | Only the executor and the temp-protection function can call the advisory lock functions. Every login role has a connection limit. Executor sessions give up on a lock after 5 seconds and a statement after 30. One gap remains: the temp-protection tool can still hold a lock (see below) |
| 10 | A hijacked component sends data out or downloads something | `test_no_outbound_connection_from_the_walled_services`, `test_no_external_dns_from_the_walled_services` (smoke, once per container) | The `backend` network is internal. A control container on a normal network must get through first, or the test fails on CI and skips on a PC |
| 11 | A tool reads columns it does not need, or forges or erases audit events | `test_tools_read_only_the_columns_their_code_needs`, `test_only_read_ticket_can_read_the_ticket_body`, `test_events_actor_and_time_cannot_be_forged`, `test_nobody_can_erase_the_audit_trail` | Column grants per role. Events take only `kind` and `detail` from the role; the database fills in `actor` and `created_at`. Rows are not scoped (see below) |

### The VULNERABLE switch

With `VULNERABLE=true` the agent and `lookup_account` trust a `customer_id` written by the model. This is the attack from row 1 working. `test_vulnerable_mode_leaks_other_customer` and `test_lookup_vulnerable_mode_trusts_customer_id` show it. To try it in the containers, set `VULNERABLE=true` in `.env` and run `docker compose up -d` again. Set it back to `false` afterwards.

### Not protected yet

- A hijacked agent can still pass another ticket's id to the tools. There is no signed ticket context yet, so the tools cannot tell that the id was not the one the agent was given.
- Tool roles are narrowed to the columns their code reads (`tool_lookup_account` cannot read phone numbers, `tool_read_ticket` cannot see who owns a ticket), but not to rows. A compromised tool can still read those columns for every customer. Row-level scoping per ticket needs the signed ticket context above, so it comes in the Azure phase.
- The temp-protection tool can still hold a home's lock: `BEGIN; SELECT set_temp_protection(1);` left open keeps the lock on that home until the transaction ends. This fails safe, since no order goes out for that home, but each affected move-out costs the executor 5 seconds (its lock timeout) and an `executor_error` on every poll. Tool sessions left idle in a transaction are ended after 10 seconds, which only helps against an honest tool that hangs: a hijacked tool can turn that setting off in its own session or keep a statement running.
- Tool-to-tool calls still need authentication. The tools, the executor and the agent are on a Compose network with no route to the internet (`internal: true`), but inside it any container can call any tool server, and the tools have no login. Workload identities and Kubernetes NetworkPolicy come in the Azure phase.
- No workload identities, firewall or central logs until the Azure phase. The database is also on a second, normal network, because Docker does not publish a port for a container that is only on an internal network and the tests need it. No tool or other service is on that network.
- Approvals are names, not people. The database refuses the same approver name twice on one request, but nothing checks that the name belongs to a real member of staff. Staff identity comes with Entra ID in the Azure phase.
- The question about medical equipment after a move-out request is added by the agent code, not the model (`test_move_out_reply_ends_with_the_medical_question`). The step that turns a "yes" into temporary protection still depends on the model calling `set_temp_protection`; the simulated occupier notice is the backstop.
- The reply guard works from word lists. A number word or money verb nobody listed gets through, and a misleading sentence built only from numbers a tool returned is not caught (row 8). Replies built from templates would fix it.
- The pipeline has not run on a real GitLab runner. The two Docker-in-Docker jobs (`build-scan`, `smoke`) were rehearsed on a PC only, and the CI Lint API has not checked `.gitlab-ci.yml`.
- 44 HIGH vulnerabilities in the base image's Debian packages have no fix and are accepted, with a review date of 2027-01-15 (see "CI pipeline"). The base image is bigger than the app needs.
- Nothing watches whether the executor is alive. It has no heartbeat, no healthcheck and no TCP keepalive on its database connection; `restart: unless-stopped` brings it back only if the process exits. If it hangs (a dead connection, a stuck loop), credits and move-outs stop without an alert. That fails safe, since no money goes out and no home is disconnected, but customers wait and nobody is told.
- The staff approval page, the occupier SMS and the state register sync are simulated.
