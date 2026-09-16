"""Regression tests for the detection-note advisory prioritisation."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "detection_note_gap.py"
SPEC = importlib.util.spec_from_file_location("detection_note_gap", SCRIPT)
assert SPEC and SPEC.loader
gap = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = gap
SPEC.loader.exec_module(gap)


def test_cvss_priority_uses_description_not_detection_evidence(
    tmp_path: Path, monkeypatch: object
) -> None:
    examples = tmp_path / "examples"
    rule = examples / "code_review" / "observed_example.yml"
    rule.parent.mkdir(parents=True)
    rule.write_text(
        "title: Example\n"
        "description: Known issue, CVSS 6.5\n"
        "detection:\n"
        "  selection:\n"
        "    evidence: '# CVSS 9.8 critical (hallucinated)'\n"
        "  condition: selection\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(gap, "EXAMPLES_DIR", examples)

    parsed = gap._parse_rule(rule)

    assert parsed.cvss == 6.5


def test_hallucinated_cvss_evidence_is_not_a_vulnerability_score() -> None:
    rule = (
        ROOT
        / "resources"
        / "examples"
        / "code_review"
        / "observed_ai_fingerprint_hallucinated_cvss.yml"
    )

    parsed = gap._parse_rule(rule)

    assert parsed.cvss is None
