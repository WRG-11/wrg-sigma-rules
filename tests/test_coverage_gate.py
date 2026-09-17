"""Regression tests for the ATT&CK coverage ratchet."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "coverage_gate.py"
SPEC = importlib.util.spec_from_file_location("coverage_gate", SCRIPT)
assert SPEC and SPEC.loader
coverage_gate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = coverage_gate
SPEC.loader.exec_module(coverage_gate)


def _coverage(techniques: int) -> dict[str, object]:
    return {
        "total_rules": 0,
        "total_techniques": techniques,
        "untagged": [],
        "unparseable": [],
    }


def test_coverage_gate_accepts_the_current_technique_floor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        coverage_gate,
        "collect_coverage",
        lambda: _coverage(coverage_gate.MIN_TECHNIQUES),
    )

    assert coverage_gate.main([]) == 0


def test_coverage_gate_rejects_a_one_technique_regression(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        coverage_gate,
        "collect_coverage",
        lambda: _coverage(coverage_gate.MIN_TECHNIQUES - 1),
    )

    assert coverage_gate.main([]) == 1
