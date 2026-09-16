#!/usr/bin/env python3
"""Inventory mechanical evidence facts for ``observed_*`` Sigma rules.

This script intentionally does not infer that a source proves a rule.  It
reports facts that can be established locally (references, logsource, ATT&CK
tags and companion notes), then leaves attribution, platform and telemetry
manifestation as ``not_assessed`` for human source review.

Usage:
    python scripts/observed_evidence_inventory.py
    python scripts/observed_evidence_inventory.py --json output.json
"""
from __future__ import annotations

import argparse
import json
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLES_DIR = REPO_ROOT / "resources" / "examples"
NOTES_DIR = REPO_ROOT / "docs" / "detection-notes"
_RULE_PATH_RE = re.compile(r"resources/examples/[A-Za-z0-9_./-]+\.ya?ml")


def _is_mitre_reference(url: str) -> bool:
    """Return whether *url* is an ATT&CK taxonomy reference.

    ATT&CK is useful technique context, but it is not primary evidence that a
    named actor performed a rule's selected activity or that it manifests in
    the selected telemetry.
    """
    try:
        host = (urlsplit(url).hostname or "").lower()
    except ValueError:
        return False
    return host == "attack.mitre.org" or host.endswith(".attack.mitre.org")


def _covered_rule_paths(notes_dir: Path) -> set[str]:
    """Return rule paths mentioned by any detection note."""
    if not notes_dir.is_dir():
        return set()
    covered: set[str] = set()
    for note in notes_dir.glob("*.md"):
        covered.update(_RULE_PATH_RE.findall(note.read_text(encoding="utf-8")))
    return covered


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _documents(path: Path) -> list[dict[str, Any]]:
    """Load mapping documents, ignoring empty YAML document separators."""
    return [
        doc
        for doc in yaml.safe_load_all(path.read_text(encoding="utf-8"))
        if isinstance(doc, dict)
    ]


def _references(documents: Iterable[dict[str, Any]]) -> list[str]:
    """Collect ordered unique reference URLs from every document in a rule."""
    result: list[str] = []
    for document in documents:
        for reference in _string_list(document.get("references")):
            if reference not in result:
                result.append(reference)
    return result


def build_inventory(examples_dir: Path, notes_dir: Path) -> list[dict[str, Any]]:
    """Build records without making source-quality claims.

    ``observed_*`` is a provenance claim.  This inventory makes missing or
    MITRE-only references visible, but all three CONTRIBUTING.md source-review
    matches deliberately remain human-assessed fields.
    """
    covered = _covered_rule_paths(notes_dir)
    records: list[dict[str, Any]] = []

    for path in sorted(examples_dir.rglob("observed_*.yml")):
        documents = _documents(path)
        if not documents:
            continue
        first = documents[0]
        relpath = "resources/examples/" + path.relative_to(examples_dir).as_posix()
        references = _references(documents)
        external_references = [ref for ref in references if not _is_mitre_reference(ref)]
        tags = sorted(
            {
                tag
                for document in documents
                for tag in _string_list(document.get("tags"))
                if tag.startswith("attack.")
            }
        )
        logsource = first.get("logsource")
        records.append(
            {
                "path": relpath,
                "title": first.get("title", path.stem),
                "status": first.get("status"),
                "document_count": len(documents),
                "has_correlation": any("correlation" in document for document in documents),
                "attack_tags": tags,
                "logsource": logsource if isinstance(logsource, dict) else {},
                "reference_count": len(references),
                "external_reference_count": len(external_references),
                "reference_hygiene": (
                    "has_non_mitre_reference"
                    if external_references
                    else "mitre_only_or_missing"
                ),
                "has_companion_note": relpath in covered,
                "attribution_evidence": "not_assessed",
                "platform_evidence": "not_assessed",
                "telemetry_manifestation_evidence": "not_assessed",
            }
        )
    return records


def summarize(records: list[dict[str, Any]]) -> dict[str, int]:
    """Summarize mechanical inventory facts, not evidence quality."""
    return {
        "observed_rule_files": len(records),
        "with_non_mitre_reference": sum(
            record["reference_hygiene"] == "has_non_mitre_reference"
            for record in records
        ),
        "mitre_only_or_missing_reference": sum(
            record["reference_hygiene"] == "mitre_only_or_missing"
            for record in records
        ),
        "with_companion_note": sum(record["has_companion_note"] for record in records),
        "awaiting_human_source_review": len(records),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path, help="write the inventory JSON to this path")
    args = parser.parse_args()

    records = build_inventory(EXAMPLES_DIR, NOTES_DIR)
    summary = summarize(records)
    payload = {"summary": summary, "records": records}

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    print("[observed-evidence-inventory]")
    for key, value in summary.items():
        print(f"  {key}: {value}")
    print("  evidence fields remain not_assessed until a human reviews the source.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
