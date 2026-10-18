"""python -m secops.evidence [--reports reports] [--out reports/evidence.html] [--strict]
                          [--collect-images ROOT] [--commit SHA]

Writes one static HTML page from the JSON reports in --reports (see secops/evidence/__init__.py
for the files and the rules). --collect-images first writes <reports>/image-digests.json from
the files under ROOT that name images.

Exit code 0 when the page is written. With --strict, 1 unless every required section passed
(a section that was not run counts as not passed).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from secops import evidence


def plain(text: str, limit: int = 300) -> str:
    """A summary can quote report data (a plane name, a ticket name). In a CI log a control
    character could move the cursor, clear the screen or start a fake line, so every character
    that is not printable is written as its code point, and the line is cut at limit."""
    out = "".join(c if c.isprintable() else f"<U+{ord(c):04X}>" for c in text)
    return out if len(out) <= limit else out[:limit] + "..."


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m secops.evidence",
                                     description="Build the static evidence report.")
    parser.add_argument("--reports", type=Path, default=Path("reports"))
    parser.add_argument("--out", type=Path, default=Path("reports/evidence.html"))
    parser.add_argument("--commit", default=os.environ.get("CI_COMMIT_SHA"),
                        help="commit the reports belong to (default: CI_COMMIT_SHA)")
    parser.add_argument("--collect-images", type=Path, metavar="ROOT",
                        help="write image-digests.json from the files under ROOT first")
    parser.add_argument("--strict", action="store_true",
                        help="exit 1 unless every required section passed")
    args = parser.parse_args(argv)

    if args.collect_images is not None:
        args.reports.mkdir(parents=True, exist_ok=True)
        doc = evidence.collect_images(args.collect_images)
        (args.reports / "image-digests.json").write_text(json.dumps(doc, indent=1) + "\n",
                                                         encoding="utf-8")

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    report = evidence.build(args.reports, generated=generated, commit=args.commit)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(evidence.render(report), encoding="utf-8")
    for s in report.sections:
        print(f"{s.key}: {s.status} ({plain(s.summary)})")
    print(f"result: {report.overall}, written to {plain(str(args.out))}")
    if args.strict and report.overall != evidence.OVERALL_PASS:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
