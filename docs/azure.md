# Azure

Both stacks were applied once, on 2026-10-21 in Sweden Central (pay-as-you-go). `infra/base` stays; `infra/lab` came up after the fixes listed in the README and was destroyed the same evening. All three nodes were Ready, including the Kata node, and db-migrate signed in to PostgreSQL with its workload identity. The app did not run yet: the first attempt stopped in the database setup (fixed and checked against a local non-superuser PostgreSQL), and the second could not create the PostgreSQL server (`RegionalAllocationFailed` in all three zones). The rule stays: a price per hour and per day for every resource and an explicit yes from me before anything is created.

## Two stacks

| Stack | Lifetime | Creates |
|---|---|---|
| `infra/base` | kept between sessions | Resource groups `rg-base` and an empty `rg-lab`; a storage account and container for Terraform state; Azure Container Registry; Log Analytics workspace (daily cap); one Key Vault per part that holds secrets (the list comes from `permissions/`); two subscription budgets (warn at 50 and 100 percent of actual spend); Azure Policy (deny VM sizes outside an allow-list, deny public access on PostgreSQL flexible servers); three CI identities with OIDC federation (`ci-plan`, `ci-push`, `ci-apply`) and no stored secret |
| `infra/lab` | created and destroyed per session | One VNet with three subnets (AKS system, AKS sandbox, private endpoints) and an NSG on each; private DNS zone for PostgreSQL; AKS (Free tier, Azure CNI Overlay with the Cilium data plane, Entra-only access, workload identity, system pool and a Kata sandbox pool); PostgreSQL flexible server B1ms, version 17, behind a private endpoint; one user-assigned workload identity per part with its Key Vault role; diagnostic settings, container log collection and two log alert rules (`heartbeat-missing`, `attack-events`) |

`infra/modules/workload-identity` is the module the lab uses for the identities. The lab reads `base` through `terraform_remote_state`, so `base` has to be applied first. `base` is applied by hand by the owner and never from CI: the CI identities live in it and none of them can widen its own rights.

Every Key Vault, identity and role assignment is generated from the manifests in `permissions/`. A new part with secrets gets its vault by adding a manifest. A manifest with a top-level `"optional": true` gets no vault, identity or federated credential unless its component is listed in the `optional_components` variable of `infra/base` and `infra/lab` (default: none). A name that matches no optional manifest stops the plan. `db-migrate` must not list a Secrets Officer role on the vault of an optional component in its manifest: those roles are derived, and a listed one would stop the plan while the component is not enabled.

Terraform tests (`terraform test`, mock providers) sit next to each stack under `tests/`, with fixtures for awkward manifests. CI runs `terraform fmt -check` and `terraform validate` on every stack.

## Decided at the Azure step

These are open on purpose. None of them blocks the kind work.

- **Outbound control.** Cilium FQDN and DNS rules on AKS need either the paid Advanced Container Networking Services add-on or Azure Firewall. The lab code currently turns ACNS on in `aks.tf` and has one VNet with no hub, no peering and no firewall. If the decision is Azure Firewall, a hub-and-spoke layout and the Azure DNS security policy from v1 come back. The Hubble drop panel on the Walls board depends on this too.
- **Kata node pool.** VM size and quota. The sandbox pool is configured with `KataVmIsolation` on Standard_D4s_v6 (Gen2, nested virtualization). It has never been created.
- **How CI reaches AKS.** GitLab shared runners have no fixed IP, so they cannot pass the AKS API allow-list. Options: `az aks command invoke` (to be checked in the Microsoft docs), or deploy and destroy from the owner's PC with a script while CI stops at `terraform plan`. Until then the pipeline has three jobs (lint, test, build) and no Terraform plan or apply.
- **Console sign-in.** The console accepts an HTTP callback only when `APP_ENV=local`, and plain-HTTP port-forwarding breaks the Secure cookie. Signing in on AKS needs either an app change or TLS on the port-forward, and an Entra redirect URI to match. The Entra app registration can be in Terraform or made by hand.
- **Alerts on Azure.** The two Prometheus alerts used on kind (executor heartbeat stale, kill switch fired) are in `deploy/monitoring/`. The lab's log alert rules are an earlier pair; they are aligned with the Prometheus ones at the Azure step.

## Staff

The database accepts an approval or a resume only for an object id on its `staff` table. The dev staff (`db/sql/09-dev-staff.sql`, public oids) are seeded only where `SEED_DEV_STAFF=yes` (local test database, CI, the kind postgres-init Job); the Azure migration sets it to `no`, and a chart test checks that. On Azure an admin fills the list once per person, as the database admin (not the console), in the `supplier` database. The table belongs to the no-login role `staff_owner`.

```sql
SET ROLE staff_owner;
INSERT INTO staff (oid, display_name, roles)
VALUES ('<Entra object id>', '<display name>', '{Approver}');   -- or '{SeniorApprover}'
-- Leaving:
UPDATE staff SET active = false WHERE oid = '<Entra object id>';
RESET ROLE;
```

The roles must match the app roles assigned in Entra. No automation yet. Whether the admin may act as `staff_owner` (a `GRANT staff_owner TO <admin>` may be needed) belongs to the Azure migration work.

## First run

What worked on 2026-10-21, from the repo root in Git Bash.

```sh
# 1. base, on local state first (the state account is created by this stack)
terraform -chdir=infra/base init && terraform -chdir=infra/base apply

# 2. move the base state to the storage account: Storage Blob Data Contributor for me on it,
#    then infra/base/backend_override.tf (git-ignored) = the backend block from versions.tf, filled in
terraform -chdir=infra/base init -migrate-state

# 3. lab
terraform -chdir=infra/lab init && terraform -chdir=infra/lab apply

# 4. vault firewalls: in infra/base/terraform.tfvars set
#      spoke_subnet_ids            = <terraform -chdir=infra/lab output aks_subnet_ids>
#      key_vault_allowed_ip_ranges = [<my public IPs>]
terraform -chdir=infra/base apply

# 5. roles for me: Key Vault Secrets Officer on rg-base (the script writes secrets) and
#    Azure Kubernetes Service RBAC Cluster Admin on the cluster (local accounts are off)
az aks get-credentials --resource-group rg-lab --name aks-assume-hijacked
kubelogin convert-kubeconfig -l azurecli

# 6. image, secrets, Helm values, install
CONSOLE_CLIENT_ID=<console app id> LLM_BACKEND=anthropic ANTHROPIC_KEY_FILE=<key file>     sh scripts/azure-deploy.sh
```

`LLM_BACKEND` defaults to `scripted`, and then no key file is needed. `SOURCE_IMAGE` reuses an image already built for kind; `LAB_OUTPUTS` is for when the lab state is locked by a running apply.

Things that cost time:

- base applied 52 of 53: the flexible federated credential for `ci-plan` failed (a preview Graph API). CI does not use it yet.
- My laptop has two public egress IPs. Both have to be in `key_vault_allowed_ip_ranges` and in the lab's `api_authorized_ip_ranges`.
- PostgreSQL deletes slowly and answers `ServerIsBusy` while a setting changes; a destroy with low parallelism, or deleting the server directly, got past it.
- If the region has no capacity for the PostgreSQL size, `postgres_sku_name` and `postgres_zone` in the lab's tfvars change it.

## Order

1. Owner upgrades from the free trial to pay-as-you-go and raises the vCPU quota (the trial has 4).
2. Prices per resource, owner says yes.
3. `terraform apply` for `base`, then for `lab`.
4. Deploy the chart with `values-azure.yaml`, run the attacks, send one real Claude ticket.
5. Record what ran, then destroy the lab the same day.

## Teardown

First remove the AKS subnets from the vault firewalls (`spoke_subnet_ids = []`, apply base), then `terraform destroy` for `infra/lab` at the end of every session. It never touches `rg-base` or the resource groups themselves. Afterwards check by hand:

```sh
az resource list --resource-group rg-lab --output table
az resource list --resource-type Microsoft.ContainerService/managedClusters --output table
```

`rg-lab` must be empty. `rg-base` keeps the registry, workspace, vaults and state, which cost little but are not free. The budgets only send e-mail; they stop nothing.
