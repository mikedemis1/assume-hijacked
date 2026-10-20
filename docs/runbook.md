# Runbook

Two alerts. Both go to Mailpit on kind (`kubectl --context kind-ah -n ah-monitoring port-forward svc/mailpit 8025:8025`, then http://localhost:8025). The Walls board is in Grafana (`port-forward svc/kps-grafana 3000:80`, user `admin`, password in the Secret `grafana-admin`). Rules are in `deploy/monitoring/rules/assume-hijacked.yaml`.

## ExecutorHeartbeatStale

**Meaning.** The executor writes the time of its last poll every few seconds. It is more than 60 s old for a minute, or the metric is gone. The executor is the only component that carries out approved requests, so approved credits sit and wait. Nothing is lost; they run once it is back.

**Check.**

```
kubectl --context kind-ah -n ah-core get pods -l app.kubernetes.io/name=executor
kubectl --context kind-ah -n ah-core logs -l app.kubernetes.io/name=executor --tail=50
kubectl --context kind-ah -n ah-core describe pod -l app.kubernetes.io/name=executor
```

In Grafana, the first panel on Walls shows the heartbeat age. If the pod runs but the age keeps growing, the loop is stuck, most often on a database call. Check the `postgres` pod in the same namespace.

**Recover.** If the pod is crashing, fix what the log says (database unreachable and a wrong credential are the usual ones). If it runs but is stuck:

```
kubectl --context kind-ah -n ah-core rollout restart deployment -l app.kubernetes.io/name=executor
```

The alert clears about a minute after the first new poll.

## KillSwitchFired

**Meaning.** `risk_agents_paused` is 1. The risk engine paused every agent after three denials on one lease (an agent that keeps calling tools it may not use). The tool gateway refuses every call until someone resumes. The Kill switch panel on Walls shows PAUSED, and the alert stays firing until then.

**Check.** Find out why before resuming.

```
kubectl --context kind-ah -n ah-core logs -l app.kubernetes.io/name=risk-engine --tail=100
kubectl --context kind-ah -n ah-core logs -l app.kubernetes.io/name=tool-gateway --tail=100
```

The Denials by reason panel shows which wall refused. The reason of the pause is stored in `agent_control.reason`, and an `agents_paused` row is written to `events`. If the denials come from the attack suite, this is the expected result and you can resume at once.

**Recover.** A person with the SeniorApprover role resumes in the console (`kubectl --context kind-ah -n ah-staff port-forward svc/console 8084:8084`, then http://localhost:8084). Nothing else can resume: the database function `resume_agents(oid)` only accepts the console's role and an active SeniorApprover on the staff list. If the same lease trips the switch again right after, revoke the lease or stop the agent before resuming a second time.
