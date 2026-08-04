#!/usr/bin/env python3
"""duplicate_rule_check.py -- advisory report of rules sharing the same
(technique tags, logsource) fingerprint.

CONTRIBUTING.md states a value ("more rules is not the goal") with nothing
mechanical checking it as the corpus grows. This does not enforce that value
-- two rules can legitimately share a fingerprint (CONTRIBUTING.md itself:
ransomware actors share T1486; a `template_*` and an `observed_*` rule for
the same technique are different things on purpose) -- it surfaces the
groups worth a human glance, same spirit as coverage_resource.py's
`untagged` list: named, not silently absent.

Advisory only, never a CI gate: fingerprint collisions are expected in a
corpus this size and a hard gate would either need a large exception list
from day one or train everyone to ignore it.

Usage:
    python scripts/duplicate_rule_check.py
    python scripts/duplicate_rule_check.py --json out.json
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES_DIR = REPO_ROOT / "resources" / "examples"
_ATTACK_PREFIX = "attack."
_TECHNIQUE_PREFIX = "attack.t"


def _fingerprint(doc: dict[str, Any]) -> tuple[tuple[str, ...], str, str] | None:
    tags = doc.get("tags") or []
    techniques = sorted(
        str(t).strip().lower()[len(_ATTACK_PREFIX):]
        for t in tags
        if str(t).strip().lower().startswith(_TECHNIQUE_PREFIX)
    )
    if not techniques:
        return None
    logsource = doc.get("logsource") or {}
    product = str(logsource.get("product") or "")
    category = str(logsource.get("category") or "")
    return (tuple(techniques), product, category)


def find_groups() -> dict[tuple[Any, ...], list[str]]:
    groups: dict[tuple[Any, ...], list[str]] = defaultdict(list)
    for path in sorted(EXAMPLES_DIR.rglob("*.yml")):
        rel = path.relative_to(EXAMPLES_DIR).as_posix()
        try:
            docs = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
        except yaml.YAMLError:
            continue
        for doc in docs:
            if not isinstance(doc, dict):
                continue
            fp = _fingerprint(doc)
            if fp is not None:
                groups[fp].append(rel)
                break  # one fingerprint per file (base rule, not correlation tail)
    return {fp: files for fp, files in groups.items() if len(files) > 1}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--json", metavar="PATH", default=None,
                        help="write findings as JSON instead of only printing")
    args = parser.parse_args(argv)

    groups = find_groups()

    if not groups:
        print("[duplicate-check] no rules share an identical "
              "(technique-tags, logsource) fingerprint")
    else:
        print(f"[duplicate-check] {len(groups)} fingerprint group(s) worth a look "
              "(not necessarily a problem -- see this script's own docstring):")
        for (techniques, product, category), files in sorted(groups.items()):
            print(f"  {', '.join(t.upper() for t in techniques)} "
                  f"(product={product or '-'}, category={category or '-'}):")
            for f in files:
                print(f"    - {f}")

    if args.json:
        payload = [
            {"techniques": list(fp[0]), "product": fp[1], "category": fp[2], "files": files}
            for fp, files in sorted(groups.items())
        ]
        Path(args.json).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"[duplicate-check] wrote {args.json}")

    return 0  # advisory: never fails the build


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
