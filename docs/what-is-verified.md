# Verification status

Recorded on 2026-10-19 from the local integration checkout based on `61e3dab`.
Integration edits are still uncommitted. A full suite against the final checkout is pending.

| Environment | Check | Observed result |
|---|---|---|
| Windows, Compose database | `python -m pytest -q --ignore=tests/k8s` before the last integration fixes | 1808 passed, 220 smoke tests deselected |
| Real Compose application, scripted model | `python -m pytest -m smoke -q` | 233 passed, no skips |
| Local kind-ah, real application | `python -m pytest -m k8s tests/k8s/test_cluster.py tests/k8s/test_walls.py -q` | 216 passed; one historical replay placeholder skipped. That placeholder was subsequently replaced by the real replay below |
| Local kind-ah, scripted model | `python -m pytest -m k8s tests/k8s/test_replay.py -q` | 11 passed, one real agent Job per attack case |
| Local collectors with fake cluster controls | `python -m pytest tests/k8s/test_permission_templates.py -q` | 10 passed after the final collector fixes |
| Helm chart gate | `sh ci/chart.sh` | 140 passed, 6 deselected; no skips. This run precedes the final collector and capability changes |
| Prometheus rule checks | Monitoring tests including pinned promtool | 22 passed, one live test deselected; rule mutations were detected |
| Terraform, mock providers only | fmt, init with backend disabled, validate, test | All four stacks validated; 95 mock tests passed |
| Terraform | TFLint | All four stacks passed |
| Static scans | Bandit, dependency audit, Hadolint, Dockerfile and CI Checkov | Gates passed; Checkov retains documented exceptions |
| Rendered Kubernetes | Checkov | 3030 passed, no failures or skips |
| Actual permissions | PostgreSQL; Compose; application namespaces on kind | Equal in separate runs: 581 PostgreSQL lines, 25 Compose lines, 31 Kubernetes lines |

The Compose attack checks inspect raw intermediate gateway responses with the agent's filtering
bypassed. The kind replay runs the real agent code and inspects stored replies independently as
the operator. POST `/reply` returns an acknowledgement, keeping its reply guard result private.
The replay refuses to seed tickets unless both the deployed LLM gateway and its pods explicitly
use the scripted backend.

The Kubernetes permission command was:

```powershell
python -m secops.permassess --planes k8s --k8s-exclude-namespace ah-monitoring --out reports/permissions-kind
```

This assesses the application. The separate monitoring release is explicitly excluded and that
scope is recorded in report info. A broader first run reported differences; it is not a passing
assessment of monitoring. Public API/OIDC discovery and read-only CA bundle discovery are
baseline permissions; writes and secret grants remain compared. Four expected network lines
refer to components absent from this local environment and are listed as `not_deployed`.

## Still pending

- Final full pytest and capability tests after the last collector changes, with kind stopped
  and the Compose test database available.
- Live monitoring: installation timed out waiting for Grafana readiness. The executor-stop
  alert and delivery to Mailpit have not been demonstrated. The partial monitoring install
  remains on the local cluster.
- Updated automatic mutation baseline for the refactored agent core. The six lease-header
  regressions detect a reverted header filter, but that targeted mutation is not a mutmut score.
- Remaining implementation findings from the original build handover, including the reply-facts
  transaction race, gateway-only denial accounting and provider capability reconciliation.
- Final image inventory, evidence page and a reviewed local commit.

Azure resources have not been applied. Entra browser sign-in, real model providers and Azure
Kata have not been tested live. The local RuntimeClass uses runc with sandbox node placement.
The cloud activation scripts and full activation runbook are separate unfinished work.

Raw logs and machine-readable results are in the private local build log directory and the
ignored `reports/` folder. Test counts here describe observed runs, not a completed release.
