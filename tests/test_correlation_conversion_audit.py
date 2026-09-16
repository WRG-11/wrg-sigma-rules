"""Tests for the correlation conversion audit."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "correlation_conversion_audit.py"
SPEC = importlib.util.spec_from_file_location("correlation_conversion_audit", SCRIPT)
assert SPEC and SPEC.loader
audit = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = audit
SPEC.loader.exec_module(audit)


def test_audit_records_capability_and_missing_backend_separately(tmp_path: Path) -> None:
    examples = tmp_path / "examples"
    correlation = examples / "lateral_movement" / "correlation.yml"
    correlation.parent.mkdir(parents=True)
    correlation.write_text(
        "title: base\n"
        "detection:\n"
        "  selection: {}\n"
        "  condition: selection\n"
        "---\n"
        "title: correlation\n"
        "correlation:\n"
        "  type: event_count\n"
        "  rules: [base]\n"
        "  timespan: 1h\n"
        "  condition:\n"
        "    gte: 2\n",
        encoding="utf-8",
    )
    examples.joinpath("lateral_movement", "ordinary.yml").write_text(
        "title: ordinary\n",
        encoding="utf-8",
    )

    def converter(_: str, *, target: str) -> dict[str, object]:
        return {
            "splunk": {"query": "ok"},
            "elastic": {"error": "unsupported", "kind": "backend_capability_gap"},
            "opensearch": {"error": "missing", "kind": "backend_missing"},
        }[target]

    payload = audit.audit_correlation_rules(
        examples,
        targets=("splunk", "elastic", "opensearch"),
        converter=converter,
    )

    assert payload["summary"] == {
        "correlation_rule_files": 1,
        "targets": ["splunk", "elastic", "opensearch"],
        "outcomes_by_target": {
            "splunk": {"converted": 1},
            "elastic": {"backend_capability_gap": 1},
            "opensearch": {"backend_missing": 1},
        },
        "semantic_equivalence": "not_assessed",
    }
    assert payload["records"] == [
        {
            "path": "resources/examples/lateral_movement/correlation.yml",
            "outcomes": {
                "splunk": "converted",
                "elastic": "backend_capability_gap",
                "opensearch": "backend_missing",
            },
        }
    ]
