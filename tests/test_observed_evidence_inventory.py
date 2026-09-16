"""Tests for the observed-rule mechanical evidence inventory."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "observed_evidence_inventory.py"
SPEC = importlib.util.spec_from_file_location("observed_evidence_inventory", SCRIPT)
assert SPEC and SPEC.loader
inventory = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = inventory
SPEC.loader.exec_module(inventory)


def test_inventory_distinguishes_reference_hygiene_from_evidence_proof(
    tmp_path: Path,
) -> None:
    examples = tmp_path / "examples"
    rule = examples / "initial_access" / "observed_example.yml"
    rule.parent.mkdir(parents=True)
    rule.write_text(
        "title: Example\n"
        "status: test\n"
        "references:\n"
        "- https://attack.mitre.org/techniques/T1190/\n"
        "- https://vendor.example/report\n"
        "logsource:\n"
        "  product: windows\n"
        "tags:\n"
        "- attack.t1190\n",
        encoding="utf-8",
    )
    notes = tmp_path / "notes"
    notes.mkdir()
    notes.joinpath("example.md").write_text(
        "resources/examples/initial_access/observed_example.yml\n",
        encoding="utf-8",
    )

    records = inventory.build_inventory(examples, notes)

    assert records == [
        {
            "path": "resources/examples/initial_access/observed_example.yml",
            "title": "Example",
            "status": "test",
            "document_count": 1,
            "has_correlation": False,
            "attack_tags": ["attack.t1190"],
            "logsource": {"product": "windows"},
            "reference_count": 2,
            "external_reference_count": 1,
            "reference_hygiene": "has_non_mitre_reference",
            "has_companion_note": True,
            "attribution_evidence": "not_assessed",
            "platform_evidence": "not_assessed",
            "telemetry_manifestation_evidence": "not_assessed",
        }
    ]


def test_inventory_marks_mitre_only_rules_without_inferring_quality(tmp_path: Path) -> None:
    examples = tmp_path / "examples"
    rule = examples / "discovery" / "observed_mitre_only.yml"
    rule.parent.mkdir(parents=True)
    rule.write_text(
        "title: MITRE only\n"
        "references:\n"
        "- https://attack.mitre.org/techniques/T1087/\n",
        encoding="utf-8",
    )

    records = inventory.build_inventory(examples, tmp_path / "missing-notes")
    summary = inventory.summarize(records)

    assert records[0]["reference_hygiene"] == "mitre_only_or_missing"
    assert records[0]["telemetry_manifestation_evidence"] == "not_assessed"
    assert summary == {
        "observed_rule_files": 1,
        "with_non_mitre_reference": 0,
        "mitre_only_or_missing_reference": 1,
        "with_companion_note": 0,
        "awaiting_human_source_review": 1,
    }
