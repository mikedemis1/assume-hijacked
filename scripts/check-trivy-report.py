"""Check the JSON report of scripts/trivy-config.sh (run with --show-suppressed).

1. Positive control: every expected target was scanned and had checks that ran (Successes > 0),
   so an empty render or a missing directory cannot pass as "no findings".
2. The suppressed findings are exactly the three accepted in .trivyignore.yaml, so an ignore
   entry cannot start hiding something else.

    python scripts/check-trivy-report.py <report.json>
"""
import json
import re
import sys
from collections import Counter

TARGETS = {"chart-kind.yaml", "chart-azure.yaml", "infra/base", "infra/lab", "Dockerfile",
           "tests/attacks/Dockerfile"}
# (rule, target, what it is found on)
SUPPRESSED = Counter({
    ("KSV-0109", "chart-kind.yaml", "ConfigMap 'db-sql'"): 1,
    ("KSV-0109", "chart-azure.yaml", "ConfigMap 'db-sql'"): 1,
    ("AZU-0012", "infra/base/main.tf", "azurerm_storage_account.state"): 1,
    ("AZU-0051", "infra/lab/nsg.tf", "azurerm_network_security_group.subnet[\"snet-aks-system\"]"): 1,
})


def suppressed(results: list[dict]) -> Counter:
    found = Counter()
    for result in results:
        for finding in result.get("ExperimentalModifiedFindings", []):
            meta = finding["Finding"]
            if meta["Status"] != "FAIL":  # a passed check is listed too when its ID is ignored
                continue
            # Terraform findings name the resource; Kubernetes ones only in the message.
            resource = meta.get("CauseMetadata", {}).get("Resource") or re.match(r"\w+ '[^']+'", meta["Message"])[0]
            found[(meta["ID"], result["Target"], resource)] += 1
    return found


def main(path: str) -> list[str]:
    with open(path, encoding="utf-8") as report:
        results = json.load(report)["Results"]
    problems = []
    ran = {r["Target"] for r in results if r.get("MisconfSummary", {}).get("Successes", 0) > 0}
    problems += [f"{t}: no check ran on it" for t in sorted(TARGETS - ran)]
    found = suppressed(results)
    if found != SUPPRESSED:
        problems.append(f"suppressed findings differ:\n  found    {dict(found)}\n  expected {dict(SUPPRESSED)}")
    return problems


if __name__ == "__main__":
    errors = main(sys.argv[1])
    if errors:
        sys.exit("\n".join(errors))
