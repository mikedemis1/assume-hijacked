"""Mutation score check for ci/mutation.sh: python ci/mutation_score.py <stats.json> <baseline>.

Score = (killed + timeout) / every mutant that was run (killed, timeout, survived, no tests,
suspicious, segfault), in percent. The README records baselines with one decimal, so the score
is compared at that precision: 174 of 216 is 80.56%, recorded as 80.6%, and must pass.
"""
from __future__ import annotations

import json
import sys


def score(stats: dict) -> float:
    caught = stats["killed"] + stats["timeout"]
    run = caught + stats["survived"] + stats["no_tests"] + stats["suspicious"] + stats["segfault"]
    if run == 0:
        raise ValueError("no mutant was run")
    return 100 * caught / run


def meets_baseline(value: float, baseline: float) -> bool:
    return round(value, 1) >= baseline


def main(stats_path: str, baseline_text: str) -> int:
    baseline = float(baseline_text)
    with open(stats_path, encoding="utf-8") as f:
        s = json.load(f)
    value = score(s)
    print(f"mutation: {s['killed']} killed, {s['timeout']} timeout, {s['survived']} survived, "
          f"{s['no_tests']} no tests, {s['suspicious']} suspicious, {s['segfault']} segfault, "
          f"{s['skipped']} skipped")
    print(f"mutation score {value:.1f}% (baseline {baseline:.1f}%)")
    if not meets_baseline(value, baseline):
        print(f"mutation: score {value:.1f}% is below the baseline {baseline:.1f}%", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
