"""Tests for the advisory duplicate-rule reporting script."""
from __future__ import annotations

import json
import importlib.util
from pathlib import Path


_ROOT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location(
    "duplicate_rule_check", _ROOT / "scripts" / "duplicate_rule_check.py"
)
assert _SPEC and _SPEC.loader
duplicate_rule_check = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(duplicate_rule_check)


def _write_rule(path: Path, *, actor: str, threshold: int) -> None:
    path.write_text(
        f"""title: A title that must not affect the digest
name: base_{actor}
tags:
  - wrg.observed.actor.{actor}
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
  condition: selection
correlation:
  type: event_count
  rules:
    - base_{actor}
  group-by:
    - SourceIP
  timespan: 10m
  condition:
    gte: {threshold}
""",
        encoding="utf-8",
    )


def test_exact_actor_logic_groups_ignore_identity_but_not_thresholds(tmp_path: Path) -> None:
    examples = tmp_path / "examples"
    examples.mkdir()
    first = examples / "observed_first.yml"
    second = examples / "observed_second.yml"
    _write_rule(first, actor="first", threshold=11)
    _write_rule(second, actor="second", threshold=11)
    _write_rule(examples / "observed_different_threshold.yml", actor="third", threshold=12)
    first.with_suffix(".sample.json").write_text('{"event": 1}', encoding="utf-8")
    second.with_suffix(".sample.json").write_text('{"event": 1}', encoding="utf-8")

    groups = duplicate_rule_check.find_exact_actor_logic_groups(examples)

    assert len(groups) == 1
    rules = groups[0]["rules"]
    assert [rule["path"] for rule in rules] == [
        "observed_first.yml",
        "observed_second.yml",
    ]
    assert rules[0]["actor_tags"] == ["wrg.observed.actor.first"]
    assert rules[0]["adjacent_sample_sha256"] == rules[1]["adjacent_sample_sha256"]


def test_exact_actor_logic_ignores_unlabelled_observed_rules(tmp_path: Path) -> None:
    examples = tmp_path / "examples"
    examples.mkdir()
    _write_rule(examples / "observed_first.yml", actor="first", threshold=11)
    (examples / "observed_unlabelled.yml").write_text(
        (examples / "observed_first.yml").read_text(encoding="utf-8").replace(
            "  - wrg.observed.actor.first\n", ""
        ),
        encoding="utf-8",
    )

    assert duplicate_rule_check.find_exact_actor_logic_groups(examples) == []


def test_cli_exact_audit_uses_explicit_examples_directory(tmp_path: Path) -> None:
    examples = tmp_path / "examples"
    examples.mkdir()
    _write_rule(examples / "observed_first.yml", actor="first", threshold=11)
    _write_rule(examples / "observed_second.yml", actor="second", threshold=11)
    report = tmp_path / "nested" / "duplicate-report.json"

    assert duplicate_rule_check.main(
        ["--exact-actor-logic", "--examples-dir", str(examples), "--json", str(report)]
    ) == 0

    payload = json.loads(report.read_text(encoding="utf-8"))
    assert payload["contract"] == {"tool": "duplicate_rule_check", "version": 1}
    assert len(payload["groups"]) == 1
    assert [rule["path"] for rule in payload["groups"][0]["rules"]] == [
        "observed_first.yml",
        "observed_second.yml",
    ]


def test_cli_default_report_offers_a_versioned_json_envelope(tmp_path: Path) -> None:
    examples = tmp_path / "examples"
    examples.mkdir()
    (examples / "first.yml").write_text(
        "tags: [attack.t1190]\nlogsource: {product: windows}\n",
        encoding="utf-8",
    )
    (examples / "second.yml").write_text(
        "tags: [attack.t1190]\nlogsource: {product: windows}\n",
        encoding="utf-8",
    )
    report = tmp_path / "default.json"

    assert duplicate_rule_check.main(
        ["--examples-dir", str(examples), "--json", str(report), "--json-envelope"]
    ) == 0

    payload = json.loads(report.read_text(encoding="utf-8"))
    assert payload["contract"] == {"tool": "duplicate_rule_check", "version": 1}
    assert len(payload["groups"]) == 1
    assert "not assessed" in payload["limitations"]


def test_cli_refuses_a_missing_examples_directory(tmp_path: Path, capsys) -> None:
    assert duplicate_rule_check.main(["--examples-dir", str(tmp_path / "missing")]) == 2
    assert "examples directory unavailable" in capsys.readouterr().err
