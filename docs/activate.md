# Activate the Azure lab

The application has been exercised locally. Azure installation, Entra browser sign-in and real
model inference remain unvalidated. [what-is-verified.md](what-is-verified.md) records the local
commands and results. Nothing in this guide has been applied to a paid subscription.

## Accounts, tools and permissions

Use a dedicated pay-as-you-go subscription, MFA and a separate daily account. The owner needs
subscription resource and role-assignment rights, plus Entra permission to create app
registrations. Bootstrap is an owner operation: CI cannot manage its own identities. Give the
operator Storage Blob Data Contributor on the state account after creating it. Azure control
plane Owner does not automatically give blob data-plane access. Wait for RBAC propagation.

Install Python 3.12, Terraform matching the committed constraints, Azure CLI, kubectl, kubelogin,
Helm 4, Docker and OpenSSL. Run from the repository root, with the virtual environment active.
Check North Europe Dalsv6 quota and Kata support for the selected AKS version before planning.
The cluster uses two system nodes and one sandbox node by default. Local kind uses runc;
successful kind tests do not establish Azure Kata isolation.

Register an Entra web application for the console. Configure the exact HTTPS callback,
`Approver` and `SeniorApprover` app roles, assign staff and create a client secret. The console
uses its validated token's object ID and app role. Arrange a trusted HTTPS endpoint that forwards
to the console Service; this chart does not install an ingress controller or obtain certificates.
An HTTP port-forward alone does not validate its Secure-cookie login flow. Keep the secret in
the console's Key Vault as `console-client-secret`, never in Terraform or Helm values.

## One input file

```powershell
Copy-Item activation.toml.example activation.toml
```

Fill in subscription and tenant, globally unique state/registry names, current budget month,
notification email, your API access CIDR and AKS administrator Entra group. The workflow uses
`rg-base`, `rg-net`, `rg-lab`, container `tfstate` and separate `base.tfstate`, `net.tfstate`,
`lab.tfstate` keys. Keep those names. Resource values are generated under the ignored
`.activation/` directory. Treat it as private: it contains state backups and kubeconfig.

The `model.backend` setting generates the chart selection, Terraform provider routes and
capability expectations together. The default is `scripted`. With Anthropic, only its API is
allowed. Foundry requires an existing account's exact HTTPS origin and full Azure resource ID;
the owner-run lab plan grants the gateway Cognitive Services User on that account. CI's delegated
role allowlist does not grant that external role. The account/model itself is not created here.

Before enabling a real backend, review spending controls and set
`model.spending_controls_reviewed = true`:

- Anthropic: set the organization's and workspace's spend limits in the Claude Console before
  provisioning its key. Read the current [API limits documentation](https://platform.claude.com/docs/en/api/rate-limits).
- Foundry: configure Cost Management budgets/alerts and the selected deployment's quotas.
  [Foundry cost guidance](https://learn.microsoft.com/en-us/azure/ai-foundry/concepts/manage-costs)
  does not establish a universal hard monetary cap for this Claude deployment.

The gateway's process-local token counters are additional controls. They reset on restart and
are not a billing guarantee. Do not supply a real provider key while relying on those counters
alone. Foundry keyless access uses [Entra authentication](https://learn.microsoft.com/azure/foundry/foundry-models/how-to/configure-entra-id).

## Plan, review, install

First authenticate and select the subscription yourself. The scripts refuse a different active
subscription or tenant; they do not switch it for you.

```powershell
az login
az account set --subscription YOUR-SUBSCRIPTION-ID
.\scripts\preflight.ps1 --config activation.toml
python -m secops.activation plan --stack base
```

Read `.activation/base.apply.txt`. Copy the SHA256 printed by the plan command only after
reviewing its resources and costs. Supply the complete subscription ID in each confirmation:

```powershell
.\scripts\install.ps1 --stack base --approved-plan REVIEWED-SHA256 --confirm "INSTALL base YOUR-SUBSCRIPTION-ID"
python -m secops.activation migrate-base --confirm "MIGRATE base YOUR-SUBSCRIPTION-ID"
```

Migration saves a unique local copy and refuses an occupied destination state blob. Confirm the
remote state is readable before continuing. Preserve that backup outside this PC too.

Run preflight again. Plan and install `net` with its own hash and `INSTALL net ...` confirmation.
Read its `aks_subnet_ids` and `log_analytics_workspace_id` from the base/net outputs: put subnet
IDs into `base.spoke_subnet_ids` and the workspace ID into `net.log_analytics_workspace_id`.
Re-plan/review/apply those updated stacks. This second pass opens vault firewalls to the actual
AKS subnets and enables DNS query logging. It is required before database setup.

Then plan and install `lab` with its own reviewed hash. Lab reads the remote base/net outputs.
There is no automatic re-plan at install: a changed configuration, source or plan file requires
a newly reviewed plan. `cost.estimated_session_eur` must fit the operator's approved session
estimate. This input check is not a cloud spending cap.

## Images, secrets and application

Import the pinned PostgreSQL and Azure CLI images into your ACR; build and push the application
image. Use the exact upstream references in `ci/lib.sh` and `compose.yaml`. For each import or
push, inspect the ACR manifest digest and fill all three `deployment.*_image` references as
`registry/repository:tag@sha256:digest`. The application command refuses placeholders and an
image in another registry. Do not use `latest`.

Generate the gateway ES256 pair using `scripts/gen-gateway-key.sh`. Store the private half in
the gateway vault as `gateway-signing-key`; put the public file path in the input file. Store
the console client secret in its own vault. For Anthropic only, set `anthropic-api-key` in the
LLM gateway vault after setting provider spending limits. Grant temporary owner secret-writing
rights only at those vault scopes and remove them after provisioning. These secrets are owner
actions; the activation command does not print or upload them.

```powershell
.\scripts\install.ps1 --stack app --confirm "INSTALL app YOUR-SUBSCRIPTION-ID"
.\scripts\verify.ps1 --stack app --confirm "VERIFY app YOUR-SUBSCRIPTION-ID"
```

The application command uses an isolated `.activation/kubeconfig`, loads Terraform outputs,
renders its database SQL inputs and installs the chart with `--wait=hookOnly`. The first
`db-migrate` hook creates schema/roles and writes workload passwords to their own vaults. CSI
then mounts each workload's password. Ordinary upgrades do not rerun schema initialization.
An existing failed first install is refused: inspect the migration Job and recover the database
deliberately before retrying. Never rerun the non-idempotent schema blindly.

For newly added DB roles, upgrade and then run `scripts/azure-rotate-db-passwords.sh` as documented
in that script; a partial rotation must be retried to restore agreement between PostgreSQL and
Key Vault. Rollout status is a readiness check. It does not prove browser login, model inference,
effective Azure permissions or every security wall.

For a full verification, run the attack probes and replay, collect PostgreSQL/Kubernetes/Azure
permissions, inspect Kata guest versus node kernel, test console sign-in and distinct approvers,
and exercise the alert path. Keep the outputs dated. A real provider test is separately billable.

## Cost envelope, checked 2026-10-19

North Europe public EUR retail meters were queried from the
[Azure Retail Prices API](https://learn.microsoft.com/en-us/rest/api/cost-management/retail-prices/azure-retail-prices).
These are estimates before tax, discounts and data charges. Monthly arithmetic uses 730 hours.

| Resource | Observed meter or allowance | Approximate month |
|---|---|---|
| Three Linux Standard_D4als_v6 nodes | EUR 0.1575/node/hour | EUR 344.93 |
| Azure Firewall Basic deployment | EUR 0.3476/hour | EUR 253.75 |
| Firewall traffic | EUR 0.0572/GB | usage dependent |
| PostgreSQL Flexible Server B1ms | EUR 0.0158/hour | EUR 11.53 |
| PostgreSQL 32 GB storage | EUR 0.1113/GB/month | EUR 3.56 |
| ACR Basic, retained in base | EUR 0.1466/day | EUR 4.46 for 30.44 days |
| Two firewall public IPv4 addresses | EUR 0.0044/address/hour | EUR 6.42 |
| Two private DNS zones | EUR 0.44/zone/month, first pricing tier | EUR 0.88 plus queries |
| State Hot LRS blob data, retained | EUR 0.0194/GB/month at first tier | tiny data volume, transactions extra |
| Log Analytics ingestion | EUR 2.4287/GB, before any free allowance | EUR 36.43 at 0.5 GB/day for 30 days |
| Private endpoint, node disks, ACNS, alerts, DNS security, transfer and vault operations | obtain current region/SKU quote before approval | additional |

The listed fixed resources alone exceed EUR 620/month if left running. A four-hour session's
listed node/firewall/PG/public-IP compute is about EUR 3.38, plus disks, networking, monitoring,
retained base and model usage. Allow extra time for creation, failed applies and teardown.
The table is a lower bound, not an all-inclusive quote. Refresh every omitted meter in the
[pricing calculator](https://azure.microsoft.com/pricing/calculator/) before approving a session.
The fixed EUR 20/EUR 50 budgets send alerts;
[pay-as-you-go has no configurable Azure spending limit](https://learn.microsoft.com/en-us/azure/cost-management-billing/manage/spending-limit).

## Stop charges and complete decommission

Ordinary session teardown preserves base. Create a destroy plan for `lab`, review its text/hash,
then apply it with a separate confirmation. Repeat for `net` after lab has no managed resources:

```powershell
python -m secops.activation plan --stack lab --destroy-plan
.\scripts\teardown.ps1 --stack lab --approved-plan REVIEWED-SHA256 --confirm "TEARDOWN lab YOUR-SUBSCRIPTION-ID"
python -m secops.activation plan --stack net --destroy-plan
.\scripts\teardown.ps1 --stack net --approved-plan REVIEWED-SHA256 --confirm "TEARDOWN net YOUR-SUBSCRIPTION-ID"
```

Base's ACR, state data/transactions, retained logs and vault operations can still bill. Inspect
AKS's node resource group, disks, IPs, firewall and private endpoints after teardown. Never delete
unrelated resources to make a check green. Independently owned Foundry resources retain their
own costs; deleting the lab's role assignment does not delete the model account.

For complete retirement, disable CI and stop other operators first. After lab and net are empty,
create a fresh encrypted/restricted backup directory outside this repository:

```powershell
python -m secops.activation decommission --backup-dir C:\PRIVATE-BACKUPS\NEW-EMPTY-DIRECTORY --confirm "DECOMMISSION YOUR-SUBSCRIPTION-ID"
python -m secops.activation plan --stack base --destroy-plan
.\scripts\teardown.ps1 --stack base --approved-plan REVIEWED-SHA256 --confirm "TEARDOWN base YOUR-SUBSCRIPTION-ID"
```

The command keeps an immutable state snapshot and a separate local-backend working copy, with
explicit retirement overrides for the storage/vault `prevent_destroy` guards. Only this external
copy runs base retirement, so it can remove state storage without deleting the state it is using.
The repository's guards remain set. Configuration and original live-state drift require a new
backup/plan. Keep the backup and local retirement state until all resources and delayed costs
have been accounted for. Soft-deleted vaults, logs, models and resources outside these states
need their own inspected disposition. This workflow has been fake-tested and has not been
executed against Azure.

If a base retirement apply only partly succeeds, retain its external working state. Review a
new `plan --stack base --destroy-plan` and confirm the new hash before retrying. After retirement
has started, recovery uses that state's original lineage and serial and the recorded empty
lab/net check; it does not need the state storage that may already have been removed. Keep CI
and other operators stopped throughout. Never copy the original snapshot over partial progress.

The lab Terraform also disables statement, slow-query and bind-parameter logging and sets
`log_min_error_statement=panic`. These settings reduce SQL arguments in infrastructure logs;
the application still records security categories. Check the effective server settings before
using real data. The [Azure PostgreSQL parameter reference](https://learn.microsoft.com/azure/postgresql/parameters/parameters-reporting-logging-when-log)
documents the available logging levels. These values are mock-tested, with no Azure application.
