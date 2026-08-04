#!/usr/bin/env python3
"""coverage_gate.py -- fail CI if ATT&CK technique coverage regresses.

``tools/resources/coverage_resource.py`` computes the corpus's technique
coverage on every read, so the number in the README/DEMO.md cannot go stale
against the rules -- but nothing was watching whether the number itself
DROPS, or whether a rule silently stopped contributing coverage (an
``untagged`` rule: valid YAML, no `attack.*` tag, contributes nothing to
the resource this repo's own README calls its coverage evidence).

Same ratchet shape as tools/static_audit/mcp_tool_docs_baseline.json in the
WRG monorepo this corpus mirrors from: a floor that can only move up, and a
ceiling that can only move down, both explicit so drift shows as a diff to
this file rather than a silent number change nobody reviewed.

Usage:
    python scripts/coverage_gate.py         # check against the floor/ceiling below
    python scripts/coverage_gate.py --show  # print current measured values, exit 0
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.resources.coverage_resource import collect_coverage

# Measured 2026-08-03: total_techniques=66, untagged=0, unparseable=0.
# Update these ONLY as a deliberate decision alongside the corpus change that
# moved them -- not to silence a failing gate.
MIN_TECHNIQUES = 66
MAX_UNTAGGED = 0
MAX_UNPARSEABLE = 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--show", action="store_true",
                        help="print current measured values and exit 0")
    args = parser.parse_args(argv)

    data = collect_coverage()
    techniques = data["total_techniques"]
    untagged = data["untagged"]
    unparseable = data["unparseable"]

    if args.show:
        print(f"total_rules: {data['total_rules']}")
        print(f"total_techniques: {techniques}")
        print(f"untagged: {len(untagged)}")
        print(f"unparseable: {len(unparseable)}")
        return 0

    problems: list[str] = []
    if techniques < MIN_TECHNIQUES:
        problems.append(
            f"distinct ATT&CK techniques covered dropped to {techniques} "
            f"(floor {MIN_TECHNIQUES}) -- if this is a deliberate corpus "
            f"change, update MIN_TECHNIQUES in this file alongside it"
        )
    if len(untagged) > MAX_UNTAGGED:
        problems.append(
            f"{len(untagged)} rule(s) contribute no ATT&CK coverage "
            f"(ceiling {MAX_UNTAGGED}): {untagged}"
        )
    if len(unparseable) > MAX_UNPARSEABLE:
        problems.append(
            f"{len(unparseable)} rule(s) failed to parse "
            f"(ceiling {MAX_UNPARSEABLE}): {unparseable}"
        )

    if problems:
        print("[coverage-gate] FAIL")
        for p in problems:
            print(f"  - {p}")
        return 1

    print(
        f"[coverage-gate] ok -- {techniques} techniques covered, "
        f"0 untagged, 0 unparseable"
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
