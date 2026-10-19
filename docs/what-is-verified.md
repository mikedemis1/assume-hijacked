# Verification status

Everything below ran on a Windows laptop with Docker Desktop (6 GB) on 2026-10-19 (+03:00).
Nothing here ran in Azure or against a real model provider.

| When | Environment | Command | Result |
|---|---|---|---|
| 13:31 | Windows, Compose database, at the final commit | `python -m pytest -q` | 2105 passed, 461 smoke and kind tests deselected, 0 failed |
| 12:03 | Real Compose application, scripted model | `python -m pytest -m smoke -q` | 233 passed, no skips. Ran before the two commits that changed reply completion and the mutation setup; the kind runs below cover the final code |
| 12:53 | Windows | `mutmut` on `app.agent.core*` | 214 killed, 2 survived (99.1%) |
| 13:04 | Local kind cluster, real application, final code | `python -m pytest -m k8s tests/k8s/test_cluster.py tests/k8s/test_walls.py -q` | 216 passed |
| 13:06 | Local kind cluster, scripted model, final code | `python -m pytest -m k8s tests/k8s/test_replay.py -q` | 11 passed, one real agent Job per attack case |
| 10:36 | Local kind cluster with the monitoring release | `python -m pytest -m k8s tests/k8s/test_monitoring.py -q` (`AH_MONITORING_INSTALLED=1`) | 1 passed in 133 s: executor stopped, heartbeat alert reached Mailpit, executor restored |
| 02:51 | Windows with Helm | `sh ci/chart.sh` | 140 passed, 6 deselected, no skips |
| Earlier that day | Windows | Prometheus rule tests with pinned promtool | 22 passed; rule mutations detected |
| Earlier that day | Mock providers only | Terraform fmt, init without backend, validate, `terraform test` | All four stacks valid; mock tests pass (lab stack 41 after the provider changes) |
| Earlier that day | Windows | TFLint | All four stacks pass |
| Earlier that day | Windows | Bandit, pip-audit, Hadolint, Checkov on Dockerfile and CI | Pass; Checkov keeps documented exceptions |
| Earlier that day | Rendered chart | Checkov | 3030 passed, 0 failed, 0 skipped |
| 11:09 | Compose | `python -m secops.permassess --planes pg,compose` | Equal: 593 PostgreSQL lines, 25 Compose lines |
| 02:59 | kind, application namespaces | `python -m secops.permassess --planes k8s --k8s-exclude-namespace ah-monitoring` | Equal: 31 lines, 4 expected network lines listed as `not_deployed` |

## Notes on the runs

The Compose attack checks call the tool gateway directly with the agent's filtering bypassed, so
the gateway is tested on its own. The kind replay runs the real agent code and reads the stored
replies afterwards as the operator. `POST /reply` returns only an acknowledgement, so the agent
never learns what the reply guard did. The replay refuses to seed tickets unless the deployed LLM
gateway and its pods use the scripted backend.

The Kubernetes permission run covers the application. The monitoring release is excluded and the
exclusion is written into the report. A first, wider run showed differences in the monitoring
namespace; that is not a passing assessment of monitoring. Public API and OIDC discovery and the
read-only CA bundle are treated as baseline; writes and secret grants are still compared. The four
`not_deployed` lines are components that do not exist in the local cluster.

The two surviving mutants in the agent core are recorded in the mutmut report and have not been
looked at yet.

## Not verified

- Azure: no resource has been applied. The Terraform has only run against mock providers.
- Kata: on kind, the `kata-vm-isolation` RuntimeClass is backed by runc with sandbox node
  placement. It gives no micro-VM boundary. The AKS node pool requests Kata; that is untested.
- Entra sign-in: the console was tested with a fake identity provider and a local JWKS. A real
  browser sign-in against Entra has not been done.
- Model providers: the Anthropic and Foundry backends were tested against a fake upstream only.
  No real inference call and no provider billing have been exercised.
- The activation scripts were tested with fake commands. Their cloud-changing paths have never run.
- The evidence page was not regenerated for the final commit.

Raw logs and machine-readable results are in the ignored `reports/` folder.
