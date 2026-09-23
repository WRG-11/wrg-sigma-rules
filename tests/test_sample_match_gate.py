"""Regression tests for the correlation sidecar evaluator."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "sample_match_gate.py"
_SPEC = importlib.util.spec_from_file_location("sample_match_gate", _SCRIPT)
assert _SPEC and _SPEC.loader
gate = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = gate
_SPEC.loader.exec_module(gate)


def test_event_count_correlation_requires_threshold_per_group() -> None:
    docs = [
        {
            "name": "base",
            "detection": {
                "selection": {"EventID": 4625},
                "condition": "selection",
            },
        },
        {
            "correlation": {
                "type": "event_count",
                "rules": ["base"],
                "group-by": ["SourceIP"],
                "condition": {"gt": 2},
            }
        },
    ]
    assert gate._correlation_fires(
        docs,
        [
            {"EventID": 4625, "SourceIP": "198.51.100.10"},
            {"EventID": 4625, "SourceIP": "198.51.100.10"},
            {"EventID": 4625, "SourceIP": "198.51.100.10"},
        ],
    )
    assert not gate._correlation_fires(
        docs,
        [
            {"EventID": 4625, "SourceIP": "198.51.100.10"},
            {"EventID": 4625, "SourceIP": "198.51.100.11"},
            {"EventID": 4625, "SourceIP": "198.51.100.12"},
        ],
    )
def test_temporal_ordered_correlation_requires_order_group_and_timespan() -> None:
    docs = [
        {"name": "first", "detection": {"selection": {"EventID": 1}, "condition": "selection"}},
        {"name": "second", "detection": {"selection": {"EventID": 2}, "condition": "selection"}},
        {
            "correlation": {
                "type": "temporal_ordered",
                "rules": ["first", "second"],
                "group-by": ["Computer"],
                "timespan": "5m",
            }
        },
    ]
    assert gate._correlation_fires(
        docs,
        [
            {"EventID": 1, "Computer": "host-a", "timestamp": "2026-09-11T12:00:00+00:00"},
            {"EventID": 2, "Computer": "host-a", "timestamp": "2026-09-11T12:02:00+00:00"},
        ],
    )
    assert not gate._correlation_fires(
        docs,
        [
            {"EventID": 1, "Computer": "host-a", "timestamp": "2026-09-11T12:00:00+00:00"},
            {"EventID": 2, "Computer": "host-a", "timestamp": "2026-09-11T12:06:00+00:00"},
        ],
    )
    assert not gate._correlation_fires(
        docs,
        [
            {"EventID": 1, "Computer": "host-a", "timestamp": "2026-09-11T12:00:00+00:00"},
            {"EventID": 2, "Computer": "host-b", "timestamp": "2026-09-11T12:02:00+00:00"},
        ],
    )
    with pytest.raises(gate.EvaluatorError, match="non-decreasing timestamp order"):
        gate._correlation_fires(
            docs,
            [
                {"EventID": 1, "Computer": "host-a", "timestamp": "2026-09-11T12:02:00+00:00"},
                {"EventID": 2, "Computer": "host-a", "timestamp": "2026-09-11T12:00:00+00:00"},
            ],
        )


def test_value_count_and_temporal_correlations_measure_distinct_values_and_windows() -> None:
    value_count_docs = [
        {"name": "base", "detection": {"selection": {"EventID": 4625}, "condition": "selection"}},
        {
            "correlation": {
                "type": "value_count", "rules": ["base"], "group-by": ["IpAddress"],
                "condition": {"field": "TargetUserName", "gt": 2},
            }
        },
    ]
    assert gate._correlation_fires(
        value_count_docs,
        [
            {"EventID": 4625, "IpAddress": "198.51.100.10", "TargetUserName": name}
            for name in ("alex", "bea", "chen")
        ],
    )
    assert not gate._correlation_fires(
        value_count_docs,
        [
            {"EventID": 4625, "IpAddress": "198.51.100.10", "TargetUserName": "alex"},
            {"EventID": 4625, "IpAddress": "198.51.100.10", "TargetUserName": "alex"},
            {"EventID": 4625, "IpAddress": "198.51.100.10", "TargetUserName": "bea"},
        ],
    )
    temporal_docs = [
        {"name": "first", "detection": {"selection": {"EventID": 1}, "condition": "selection"}},
        {"name": "second", "detection": {"selection": {"EventID": 2}, "condition": "selection"}},
        {"correlation": {"type": "temporal", "rules": ["first", "second"], "group-by": ["Computer"], "timespan": "5m"}},
    ]
    assert gate._correlation_fires(
        temporal_docs,
        [
            {"EventID": 2, "Computer": "host-a", "timestamp": "2026-09-11T12:00:00+00:00"},
            {"EventID": 1, "Computer": "host-a", "timestamp": "2026-09-11T12:02:00+00:00"},
        ],
    )
    assert not gate._correlation_fires(
        temporal_docs,
        [
            {"EventID": 2, "Computer": "host-a", "timestamp": "2026-09-11T12:00:00+00:00"},
            {"EventID": 1, "Computer": "host-a", "timestamp": "2026-09-11T12:06:00+00:00"},
        ],
    )


def test_test_status_correlation_rejects_legacy_single_event_sidecar(tmp_path: Path) -> None:
    rule = tmp_path / "correlation.yml"
    rule.write_text(
        """title: Base
name: base
id: 11111111-1111-4111-8111-111111111111
status: test
logsource: {category: process_creation}
detection:
  selection: {EventID: 1}
  condition: selection
---
title: Correlation
id: 22222222-2222-4222-8222-222222222222
status: test
correlation:
  type: event_count
  rules: [base]
  group-by: [SourceIP]
  timespan: 5m
  condition: {gt: 2}
""",
        encoding="utf-8",
    )
    rule.with_suffix(".sample.json").write_text(
        '[{"expect_match": true, "event": {"EventID": 1}}]',
        encoding="utf-8",
    )
    result = gate.check_rule(rule)
    assert not result.ok
    assert any("requires an 'events' sequence" in item for item in result.sample_results)


def test_require_correlation_samples_covers_experimental_rules(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rule = tmp_path / "correlation.yml"
    rule.write_text(
        """title: Correlation
id: 22222222-2222-4222-8222-222222222222
status: experimental
correlation:
  type: event_count
  rules: [base]
  group-by: [SourceIP]
  timespan: 5m
  condition: {gt: 2}
""",
        encoding="utf-8",
    )
    monkeypatch.setattr(gate, "EXAMPLES_DIR", tmp_path)
    assert gate.main(["--require-correlation-samples"]) == 1


def test_require_new_experimental_samples_rejects_unlisted_rule(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rule = tmp_path / "experimental.yml"
    rule.write_text(
        """title: Experimental
id: 22222222-2222-4222-8222-222222222222
status: experimental
logsource: {category: process_creation}
detection:
  selection: {EventID: 1}
  condition: selection
""",
        encoding="utf-8",
    )
    baseline = tmp_path / "baseline.json"
    baseline.write_text('{"missing_experimental_samples": []}', encoding="utf-8")
    monkeypatch.setattr(gate, "EXAMPLES_DIR", tmp_path)
    assert gate.main([
        "--require-new-experimental-samples", "--experimental-baseline", str(baseline)
    ]) == 1


def test_sidecar_rejects_non_boolean_expectation(tmp_path: Path) -> None:
    rule = tmp_path / "rule.yml"
    rule.write_text(
        """title: Rule
id: 11111111-1111-4111-8111-111111111111
status: test
logsource: {category: process_creation}
detection:
  selection: {EventID: 1}
  condition: selection
""",
        encoding="utf-8",
    )
    rule.with_suffix(".sample.json").write_text(
        '[{"expect_match": "true", "event": {"EventID": 1}}]',
        encoding="utf-8",
    )
    result = gate.check_rule(rule)
    assert not result.ok
    assert any("expect_match must be a boolean" in item for item in result.sample_results)
