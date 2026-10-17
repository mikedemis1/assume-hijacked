#!/bin/sh
# After tf-destroy: is anything that bills by the hour still there? Signs in as ci-plan (Reader on
# the subscription) with the job's OIDC token and lists:
#   - everything in rg-lab, and
#   - the billable types below, wherever they are in the subscription (the AKS node resource
#     group, rg-net, a resource group made by hand).
# Fails with the list if there is any, so a forgotten cluster or firewall is seen at once.
. ci/tf-common.sh

azure_env plan
command -v az >/dev/null 2>&1 || die "az is not installed; this job runs in CI, in $AZURE_CLI_IMAGE"
az login --service-principal --username "$ARM_CLIENT_ID" --tenant "$ARM_TENANT_ID" \
    --federated-token "$AZURE_ID_TOKEN" --allow-no-subscriptions --output none
az account set --subscription "$ARM_SUBSCRIPTION_ID"

lab_group="${LAB_RESOURCE_GROUP:-rg-lab}"
billable="Microsoft.ContainerService/managedClusters
Microsoft.Network/azureFirewalls
Microsoft.DBforPostgreSQL/flexibleServers
Microsoft.Network/publicIPAddresses
Microsoft.Network/privateEndpoints
Microsoft.Network/loadBalancers
Microsoft.Network/natGateways
Microsoft.Compute/virtualMachines
Microsoft.Compute/virtualMachineScaleSets
Microsoft.Compute/disks"

found=$(mktemp)
az resource list --resource-group "$lab_group" --query "[].id" --output tsv >>"$found"
for type in $billable; do
    az resource list --resource-type "$type" --query "[].id" --output tsv >>"$found"
done
# The same resource can be listed twice (once per query).
sort -u "$found" >"$found.sorted"
if [ -s "$found.sorted" ]; then
    echo "Still there after destroy:" >&2
    cat "$found.sorted" >&2
    exit 1
fi
echo "leftover-check: $lab_group is empty and no billable resource is left in the subscription"
