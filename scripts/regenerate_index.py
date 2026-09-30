"""Regenerate ``resources/examples/INDEX.json`` from the rule files on disk.

INDEX.json indexes every rule three ways: by tactic directory, by logsource
``category`` (detection type) and by logsource ``product`` (target platform).
Rule files are only read; INDEX.json is the only file written.

A base-rule + correlation-rule pair is two YAML documents in one file. The base
document (the first) carries the real ``logsource``, so a multi-document file is
indexed by its first document, the same way a plain single-document rule is.

Usage::

    python scripts/regenerate_index.py [--generated-at YYYY-MM-DD]

``tests/test_index_consistency.py`` regenerates the index in memory and compares
it with the committed file, so a rule added, removed or moved without running
this script fails CI.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "resources" / "examples"


def scan_disk_rules(examples_dir: Path) -> list[tuple[str, str, dict[str, Any]]]:
    """Return ``(category, filename, first_document)`` for every rule file."""
    rules: list[tuple[str, str, dict[str, Any]]] = []
    for path in sorted(examples_dir.rglob("*.yml")):
        category = path.relative_to(examples_dir).parts[0]
        docs = [d for d in yaml.safe_load_all(path.read_text(encoding="utf-8")) if d]
        rules.append((category, path.name, docs[0] if docs else {}))
    return rules


def build_index(rules: list[tuple[str, str, dict[str, Any]]], generated_at: str) -> dict[str, Any]:
    """Build the three-dimensional index for ``rules``; every list is sorted."""
    categories: dict[str, list[str]] = {}
    by_detection_type: dict[str, list[str]] = {}
    by_target_platform: dict[str, list[str]] = {}
    for category, filename, doc in rules:
        relpath = f"{category}/{filename}"
        logsource = doc.get("logsource", {}) if isinstance(doc, dict) else {}
        categories.setdefault(category, []).append(relpath)
        by_detection_type.setdefault(logsource.get("category") or "unspecified", []).append(relpath)
        by_target_platform.setdefault(logsource.get("product") or "unspecified", []).append(relpath)
    for table in (categories, by_detection_type, by_target_platform):
        for key in table:
            table[key] = sorted(table[key])
    return {
        "_schema_version": 1,
        "_generated_at": generated_at,
        "total_rules": len(rules),
        "categories": dict(sorted(categories.items())),
        "by_detection_type": dict(sorted(by_detection_type.items())),
        "by_target_platform": dict(sorted(by_target_platform.items())),
    }


def regenerate_index_from_disk(examples_dir: Path, generated_at: str) -> dict[str, Any]:
    """Rebuild the index for ``examples_dir`` without writing it."""
    return build_index(scan_disk_rules(examples_dir), generated_at)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument(
        "--generated-at",
        default=datetime.now(timezone.utc).date().isoformat(),
        help="ISO date stamped as _generated_at (default: today, UTC)",
    )
    args = parser.parse_args(argv)
    index = regenerate_index_from_disk(EXAMPLES_DIR, generated_at=args.generated_at)
    (EXAMPLES_DIR / "INDEX.json").write_text(
        json.dumps(index, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    print(f"INDEX.json regenerated: {index['total_rules']} rules in {len(index['categories'])} categories")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
