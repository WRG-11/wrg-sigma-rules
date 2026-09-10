"""Regression tests for the event_count sidecar evaluator."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


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
