# Azure

Nothing in this project has been applied to Azure. No resource exists, nothing billable has run, and everything below describes Terraform code that is only checked offline (`terraform validate`, `terraform test` with mock providers). The rule for the Azure step: a price per hour and per day for every resource and an explicit yes from the owner before anything is created.

## Two stacks

| Stack | Lifetime | Creates |
|---|---|---|
| `infra/base` | kept between sessions | Resource groups `rg-base` and an empty `rg-lab`; a storage account and container for Terraform state; Azure Container Registry; Log Analytics workspace (daily cap); one Key Vault per part that holds secrets (the list comes from `permissions/`); two subscription budgets (warn at 50 and 100 percent of actual spend); Azure Policy (deny VM sizes outside an allow-list, deny public access on PostgreSQL flexible servers); three CI identities with OIDC federation (`ci-plan`, `ci-push`, `ci-apply`) and no stored secret |
| `infra/lab` | created and destroyed per session | One VNet with three subnets (AKS system, AKS sandbox, private endpoints) and an NSG on each; private DNS zone for PostgreSQL; AKS (Free tier, Azure CNI Overlay with the Cilium data plane, Entra-only access, workload identity, system pool and a Kata sandbox pool); PostgreSQL flexible server B1ms, version 17, behind a private endpoint; one user-assigned workload identity per part with its Key Vault role; diagnostic settings, container log collection and two log alert rules (`heartbeat-missing`, `attack-events`) |

`infra/modules/workload-identity` is the module the lab uses for the identities. The lab reads `base` through `terraform_remote_state`, so `base` has to be applied first. `base` is applied by hand by the owner and never from CI: the CI identities live in it and none of them can widen its own rights.

Every Key Vault, identity and role assignment is generated from the manifests in `permissions/`. A new part with secrets gets its vault by adding a manifest.

Terraform tests (`terraform test`, mock providers) sit next to each stack under `tests/`, with fixtures for awkward manifests. CI runs `terraform fmt -check` and `terraform validate` on every stack.

## Decided at the Azure step

These are open on purpose. None of them blocks the kind work.

- **Outbound control.** Cilium FQDN and DNS rules on AKS need either the paid Advanced Container Networking Services add-on or Azure Firewall. The lab code currently turns ACNS on in `aks.tf` and has one VNet with no hub, no peering and no firewall. If the decision is Azure Firewall, a hub-and-spoke layout and the Azure DNS security policy from v1 come back. The Hubble drop panel on the Walls board depends on this too.
- **Kata node pool.** VM size and quota. The sandbox pool is configured with `KataVmIsolation` on Standard_D4als_v6 (Gen2, nested virtualization). It has never been created.
- **How CI reaches AKS.** GitLab shared runners have no fixed IP, so they cannot pass the AKS API allow-list. Options: `az aks command invoke` (to be checked in the Microsoft docs), or deploy and destroy from the owner's PC with a script while CI stops at `terraform plan`. Until then the pipeline has three jobs (lint, test, build) and no Terraform plan or apply.
- **Console sign-in.** The console accepts an HTTP callback only when `APP_ENV=local`, and plain-HTTP port-forwarding breaks the Secure cookie. Signing in on AKS needs either an app change or TLS on the port-forward, and an Entra redirect URI to match. The Entra app registration can be in Terraform or made by hand.
- **Alerts on Azure.** The two Prometheus alerts used on kind (executor heartbeat stale, kill switch fired) are in `deploy/monitoring/`. The lab's log alert rules are an earlier pair; they are aligned with the Prometheus ones at the Azure step.

## Staff

The database accepts an approval or a resume only for an object id on its `staff` table. Locally `db/sql/09-dev-staff.sql` fills it with the three dev sign-in users. On Azure the migration job sets `SEED_DEV_STAFF=no`, so the list starts empty and an admin fills it once per person, as the database admin (not the console). The table belongs to the no-login role `staff_owner`; the admin needs to be allowed to act as that role (`GRANT staff_owner TO <admin>` if not).

```sql
SET ROLE staff_owner;
INSERT INTO staff (oid, display_name, roles)
VALUES ('<Entra object id>', '<display name>', '{Approver}');   -- or '{SeniorApprover}'
RESET ROLE;
-- Leaving: UPDATE staff SET active = false WHERE oid = '<Entra object id>';
```

The roles must match the app roles assigned in Entra. No automation yet.

## Order

1. Owner upgrades from the free trial to pay-as-you-go and raises the vCPU quota (the trial has 4).
2. Prices per resource, owner says yes.
3. `terraform apply` for `base`, then for `lab`.
4. Deploy the chart with `values-azure.yaml`, run the attacks, send one real Claude ticket.
5. Record what ran, then destroy the lab the same day.

## Teardown

`terraform destroy` for `infra/lab` at the end of every session. It never touches `rg-base` or the resource groups themselves. Afterwards check by hand:

```sh
az resource list --resource-group rg-lab --output table
az resource list --resource-type Microsoft.ContainerService/managedClusters --output table
```

`rg-lab` must be empty. `rg-base` keeps the registry, workspace, vaults and state, which cost little but are not free. The budgets only send e-mail; they stop nothing.
