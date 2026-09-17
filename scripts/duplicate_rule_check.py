#!/usr/bin/env python3
"""duplicate_rule_check.py -- advisory reports for potentially duplicated
Sigma rules.

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
    python scripts/duplicate_rule_check.py --exact-actor-logic
"""
from __future__ import annotations

import argparse
import hashlib
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
_ACTOR_PREFIX = "wrg.observed.actor."


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


def find_groups(
    examples_dir: Path = EXAMPLES_DIR,
) -> dict[tuple[Any, ...], list[str]]:
    groups: dict[tuple[Any, ...], list[str]] = defaultdict(list)
    for path in sorted(examples_dir.rglob("*.yml")):
        rel = path.relative_to(examples_dir).as_posix()
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


def _actor_tags(docs: list[dict[str, Any]]) -> list[str]:
    """Return actor labels from all documents in a multi-document rule."""
    return sorted({
        str(tag).strip().lower()
        for doc in docs
        for tag in (doc.get("tags") or [])
        if str(tag).strip().lower().startswith(_ACTOR_PREFIX)
    })


def _logic_digest(docs: list[dict[str, Any]]) -> str:
    """Hash only detection-relevant structure, excluding rule identity/text.

    This intentionally does not try to infer semantic equivalence. For
    example, ``gt: 10`` and ``gte: 11`` remain different structures even
    where a backend might treat their integer match sets alike.
    """
    local_base_names = {
        str(doc["name"])
        for doc in docs
        if isinstance(doc.get("name"), str)
    }
    normalized = {
        "documents": [
            _normalized_logic_document(doc, local_base_names)
            for doc in docs
        ]
    }
    rendered = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()


def _normalized_logic_document(
    doc: dict[str, Any], local_base_names: set[str]
) -> dict[str, Any]:
    """Remove a local base-rule name from an otherwise semantic correlation.

    A correlation's ``rules`` field normally points to the base rule in the
    same YAML file. That generated name varies by actor and should not block
    an exact logic comparison. References to anything else stay intact.
    """
    normalized = {
        key: doc[key]
        for key in ("logsource", "detection", "correlation")
        if key in doc
    }
    correlation = normalized.get("correlation")
    if not isinstance(correlation, dict):
        return normalized
    rules = correlation.get("rules")
    if not isinstance(rules, list):
        return normalized
    replaced_rules = [
        "<local_base_rule>" if str(rule) in local_base_names else rule
        for rule in rules
    ]
    if replaced_rules != rules:
        normalized["correlation"] = {**correlation, "rules": replaced_rules}
    return normalized


def _sidecar_digest(path: Path) -> str | None:
    """Hash an adjacent sample when present; do not interpret its contents."""
    sample_path = path.with_suffix(".sample.json")
    if not sample_path.is_file():
        return None
    return hashlib.sha256(sample_path.read_bytes()).hexdigest()


def find_exact_actor_logic_groups(
    examples_dir: Path = EXAMPLES_DIR,
) -> list[dict[str, Any]]:
    """Find exact structural duplicates among actor-labelled observed rules.

    Matching logic or sidecar bytes do not establish actor attribution,
    source provenance, or safe consolidation.
    """
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for path in sorted(examples_dir.rglob("observed_*.yml")):
        try:
            docs = [
                doc
                for doc in yaml.safe_load_all(path.read_text(encoding="utf-8"))
                if isinstance(doc, dict)
            ]
        except (OSError, UnicodeDecodeError, yaml.YAMLError):
            continue
        actors = _actor_tags(docs)
        if not actors:
            continue
        digest = _logic_digest(docs)
        groups[digest].append({
            "path": path.relative_to(examples_dir).as_posix(),
            "actor_tags": actors,
            "adjacent_sample_sha256": _sidecar_digest(path),
        })

    return [
        {"logic_sha256": digest, "rules": rules}
        for digest, rules in sorted(groups.items())
        if len(rules) > 1
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--json", metavar="PATH", default=None,
                        help="write findings as JSON instead of only printing")
    parser.add_argument(
        "--examples-dir",
        type=Path,
        default=EXAMPLES_DIR,
        help="Sigma examples root to inspect (default: repository corpus)",
    )
    parser.add_argument(
        "--exact-actor-logic",
        action="store_true",
        help=("report exact detection/correlation structure duplicates among "
              "actor-labelled observed rules"),
    )
    args = parser.parse_args(argv)

    if not args.examples_dir.is_dir():
        print(f"[duplicate-check] examples directory unavailable: {args.examples_dir}", file=sys.stderr)
        return 2

    if args.exact_actor_logic:
        groups = find_exact_actor_logic_groups(args.examples_dir)
        if not groups:
            print("[duplicate-check] no exact actor-labelled logic duplicates")
        else:
            print(f"[duplicate-check] {len(groups)} exact actor-labelled "
                  "logic group(s) worth source review:")
            for group in groups:
                print(f"  {group['logic_sha256'][:12]}:")
                for rule in group["rules"]:
                    actors = ", ".join(rule["actor_tags"]) or "-"
                    sample = rule["adjacent_sample_sha256"]
                    sample_text = sample[:12] if sample else "none"
                    print(f"    - {rule['path']} (actors={actors}; "
                          f"sample_sha256={sample_text})")
        print("[duplicate-check] exact structural equality only; threshold "
              "equivalence, source attribution, and consolidation are "
              "not assessed")
        payload: Any = {
            "groups": groups,
            "limitations": (
                "Exact structural equality only; threshold equivalence, source "
                "attribution, and consolidation are not assessed."
            ),
        }
    else:
        groups = find_groups(args.examples_dir)

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
        payload = [
            {"techniques": list(fp[0]), "product": fp[1], "category": fp[2], "files": files}
            for fp, files in sorted(groups.items())
        ]

    if args.json:
        Path(args.json).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"[duplicate-check] wrote {args.json}")

    return 0  # advisory: never fails the build


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
