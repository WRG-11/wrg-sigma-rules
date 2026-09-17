"""Tests for the observed-rule mechanical evidence inventory."""
from __future__ import annotations

import json
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
            "first_document_reference_count": 2,
            "later_document_reference_count": 0,
            "references": [
                "https://attack.mitre.org/techniques/T1190/",
                "https://vendor.example/report",
            ],
            "first_document_references": [
                "https://attack.mitre.org/techniques/T1190/",
                "https://vendor.example/report",
            ],
            "later_document_references": [],
            "has_wrg_breach_catalog_mention": False,
            "reference_hygiene": "has_non_mitre_reference",
            "has_companion_note": True,
            "source_review": None,
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
        "with_wrg_breach_catalog_mention": 0,
        "with_references_only_in_later_document": 0,
        "awaiting_human_source_review": 1,
    }


def test_cli_uses_explicit_corpus_and_notes_directories(tmp_path: Path) -> None:
    examples = tmp_path / "examples"
    rule = examples / "impact" / "observed_example.yml"
    rule.parent.mkdir(parents=True)
    rule.write_text(
        "title: Example\nreferences:\n- https://vendor.example/report\n",
        encoding="utf-8",
    )
    notes = tmp_path / "notes"
    notes.mkdir()
    report = tmp_path / "inventory.json"

    assert inventory.main(
        [
            "--examples-dir",
            str(examples),
            "--notes-dir",
            str(notes),
            "--json",
            str(report),
        ]
    ) == 0

    payload = json.loads(report.read_text(encoding="utf-8"))
    assert payload["summary"]["observed_rule_files"] == 1
    assert "do not prove attribution" in payload["limitations"]


def test_cli_refuses_a_missing_examples_directory(tmp_path: Path, capsys) -> None:
    assert inventory.main(["--examples-dir", str(tmp_path / "missing")]) == 2
    assert "examples directory unavailable" in capsys.readouterr().out


def test_inventory_marks_literal_catalog_mentions_and_later_references(
    tmp_path: Path,
) -> None:
    examples = tmp_path / "examples"
    rule = examples / "initial_access" / "observed_example.yml"
    rule.parent.mkdir(parents=True)
    rule.write_text(
        "title: Base\n"
        "description: Derived from the WRG breach catalog.\n"
        "detection: {selection: {}, condition: selection}\n"
        "---\n"
        "title: Correlation\n"
        "references:\n"
        "- https://vendor.example/advisory\n"
        "correlation: {type: event_count}\n",
        encoding="utf-8",
    )

    record = inventory.build_inventory(examples, tmp_path / "notes")[0]

    assert record["has_wrg_breach_catalog_mention"] is True
    assert record["first_document_reference_count"] == 0
    assert record["later_document_reference_count"] == 1
    assert record["first_document_references"] == []
    assert record["later_document_references"] == ["https://vendor.example/advisory"]
    assert inventory.summarize([record])["with_references_only_in_later_document"] == 1


def test_inventory_uses_a_cited_structured_source_review(tmp_path: Path) -> None:
    examples = tmp_path / "examples"
    rule = examples / "initial_access" / "observed_example.yml"
    rule.parent.mkdir(parents=True)
    rule.write_text(
        "title: Example\nreferences:\n- https://vendor.example/advisory\n",
        encoding="utf-8",
    )
    reviews = tmp_path / "reviews"
    reviews.mkdir()
    reviews.joinpath("example.yml").write_text(
        "schema_version: 1\n"
        "reviews:\n"
        "- rule: resources/examples/initial_access/observed_example.yml\n"
        "  source: https://vendor.example/advisory\n"
        "  reviewed_on: '2026-09-17'\n"
        "  attribution_evidence:\n"
        "    status: supported\n"
        "    quote: The advisory attributes this activity.\n"
        "  platform_evidence:\n"
        "    status: not_supported\n"
        "    quote: The advisory describes a different platform.\n"
        "  telemetry_manifestation_evidence:\n"
        "    status: not_assessed\n",
        encoding="utf-8",
    )

    loaded = inventory.load_source_reviews(reviews)
    records = inventory.build_inventory(examples, tmp_path / "notes", loaded)

    assert records[0]["attribution_evidence"] == "supported"
    assert records[0]["platform_evidence"] == "not_supported"
    assert records[0]["telemetry_manifestation_evidence"] == "not_assessed"
    assert records[0]["source_review"] == {
        "source": "https://vendor.example/advisory",
        "reviewed_on": "2026-09-17",
    }
    assert inventory.summarize(records)["awaiting_human_source_review"] == 1


def test_source_review_rejects_claim_without_nonempty_quote(tmp_path: Path) -> None:
    reviews = tmp_path / "reviews"
    reviews.mkdir()
    reviews.joinpath("invalid.yml").write_text(
        "schema_version: 1\n"
        "reviews:\n"
        "- rule: resources/examples/initial_access/observed_example.yml\n"
        "  source: https://vendor.example/advisory\n"
        "  reviewed_on: '2026-09-17'\n"
        "  attribution_evidence: {status: supported, quote: ''}\n"
        "  platform_evidence: {status: not_assessed}\n"
        "  telemetry_manifestation_evidence: {status: not_assessed}\n",
        encoding="utf-8",
    )

    try:
        inventory.load_source_reviews(reviews)
    except ValueError as exc:
        assert "needs a source quote" in str(exc)
    else:  # pragma: no cover - assertion guard
        raise AssertionError("expected malformed source review to be rejected")


def test_source_review_rejects_invalid_date_and_url(tmp_path: Path) -> None:
    reviews = tmp_path / "reviews"
    reviews.mkdir()
    reviews.joinpath("invalid.yml").write_text(
        "schema_version: 1\n"
        "reviews:\n"
        "- rule: resources/examples/initial_access/observed_example.yml\n"
        "  source: https://\n"
        "  reviewed_on: '2026-02-30'\n"
        "  attribution_evidence: {status: not_assessed}\n"
        "  platform_evidence: {status: not_assessed}\n"
        "  telemetry_manifestation_evidence: {status: not_assessed}\n",
        encoding="utf-8",
    )

    try:
        inventory.load_source_reviews(reviews)
    except ValueError as exc:
        assert "invalid source URL" in str(exc)
    else:  # pragma: no cover - assertion guard
        raise AssertionError("expected malformed source-review URL to be rejected")

    content = reviews.joinpath("invalid.yml").read_text(encoding="utf-8")
    reviews.joinpath("invalid.yml").write_text(
        content.replace("https://", "https://vendor.example/advisory"), encoding="utf-8"
    )
    try:
        inventory.load_source_reviews(reviews)
    except ValueError as exc:
        assert "YYYY-MM-DD" in str(exc)
    else:  # pragma: no cover - assertion guard
        raise AssertionError("expected impossible source-review date to be rejected")


def test_inventory_rejects_review_for_unknown_rule(tmp_path: Path) -> None:
    examples = tmp_path / "examples"
    examples.mkdir()
    reviews = {
        "resources/examples/initial_access/observed_missing.yml": {
            "_source": "https://vendor.example/advisory",
            "_reviewed_on": "2026-09-17",
            "attribution_evidence": "not_assessed",
            "platform_evidence": "not_assessed",
            "telemetry_manifestation_evidence": "not_assessed",
        }
    }

    try:
        inventory.build_inventory(examples, tmp_path / "notes", reviews)
    except ValueError as exc:
        assert "targets unavailable observed rule" in str(exc)
    else:  # pragma: no cover - assertion guard
        raise AssertionError("expected unavailable source-review target to be rejected")


def test_inventory_rejects_review_source_absent_from_rule(tmp_path: Path) -> None:
    examples = tmp_path / "examples"
    rule = examples / "initial_access" / "observed_example.yml"
    rule.parent.mkdir(parents=True)
    rule.write_text(
        "title: Example\nreferences:\n- https://vendor.example/actual\n",
        encoding="utf-8",
    )
    reviews = {
        "resources/examples/initial_access/observed_example.yml": {
            "_source": "https://vendor.example/unlisted",
            "_reviewed_on": "2026-09-17",
            "attribution_evidence": "supported",
            "platform_evidence": "supported",
            "telemetry_manifestation_evidence": "supported",
        }
    }

    try:
        inventory.build_inventory(examples, tmp_path / "notes", reviews)
    except ValueError as exc:
        assert "URL absent from the rule references" in str(exc)
    else:  # pragma: no cover - assertion guard
        raise AssertionError("expected an unlisted source-review URL to be rejected")
