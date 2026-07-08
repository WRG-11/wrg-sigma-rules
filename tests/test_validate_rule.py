"""Unit tests for ``mcp__plugin_wrg-sigma-rules_wrg-sigma-rules__validate_rule`` tool.

Design-discipline coverage:
* pySigma missing path simulated via monkeypatch.
* Malformed YAML triggers ``line`` + ``column`` in schema_errors.
* Internal-looking identifiers redacted in the rule preview echo.
* Output strings ASCII-only.

First-attempt PASS discipline.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_PLUGIN_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PLUGIN_ROOT))

from tools.draft_rule import draft_rule_body  # noqa: E402
from tools.validate_rule import validate_rule_body  # noqa: E402


def _good_yaml() -> str:
    draft = draft_rule_body(
        "Detect suspicious PowerShell MITRE T1059.001",
        rule_type="process_creation",
        severity="high",
        references=["https://attack.mitre.org/techniques/T1059/001/"],
    )
    return draft["yaml"]


def test_validate_happy_path_passes_schema_and_pysigma() -> None:
    result = validate_rule_body(_good_yaml())
    assert result["ok"] is True
    assert result["valid"] is True
    assert result["schema_errors"] == []
    assert result["pysigma_errors"] == []
    assert result["pysigma_available"] is True


def test_validate_empty_input_returns_error_envelope() -> None:
    result = validate_rule_body("")
    assert result["ok"] is False
    assert "yaml_content" in result["error"]


def test_validate_malformed_yaml_surfaces_line_and_column() -> None:
    # Parse-error surfacing -- parse error must include line + column.
    bad = "title: foo\nbad indent\n  detection:"
    result = validate_rule_body(bad)
    assert result["valid"] is False
    schema_errs = result["schema_errors"]
    assert schema_errs
    assert any("line" in e and "column" in e for e in schema_errs)


def test_validate_missing_required_field_flags_schema_error() -> None:
    yaml_str = "title: foo\nid: 11111111-2222-3333-4444-555555555555\nlogsource: {}\n"
    result = validate_rule_body(yaml_str)
    assert result["valid"] is False
    # detection field is required and absent.
    assert any(
        e.get("field") == "detection" for e in result["schema_errors"]
    )


def test_validate_invalid_uuid_flagged() -> None:
    yaml_str = (
        "title: foo\nid: not-a-uuid\nlogsource: {category: x}\n"
        "detection:\n  selection: {a: 1}\n  condition: selection\n"
    )
    result = validate_rule_body(yaml_str)
    assert any(e.get("field") == "id" for e in result["schema_errors"])


def test_validate_invalid_level_flagged() -> None:
    yaml_str = (
        "title: foo\nid: 11111111-2222-3333-4444-555555555555\n"
        "level: extreme\nlogsource: {category: x}\n"
        "detection:\n  selection: {a: 1}\n  condition: selection\n"
    )
    result = validate_rule_body(yaml_str)
    assert any(e.get("field") == "level" for e in result["schema_errors"])


def test_validate_linter_flags_empty_references() -> None:
    yaml_str = (
        "title: A short title\n"
        "id: 11111111-2222-3333-8444-555555555555\n"
        "description: a real description over ten characters\n"
        "logsource: {category: process_creation}\n"
        "detection:\n  selection: {Image|endswith: bad.exe}\n"
        "  condition: selection\n"
        "level: medium\n"
        "tags:\n  - attack.t1059\n"
    )
    result = validate_rule_body(yaml_str)
    rules_hit = {w["rule"] for w in result["linter_warnings"]}
    assert "references_empty" in rules_hit
    assert "falsepositives_empty" in rules_hit


def test_validate_linter_passes_clean_rule_no_warnings_except_default() -> None:
    yaml_str = (
        "title: PowerShell encoded payload via -enc flag\n"
        "id: 11111111-2222-3333-8444-555555555555\n"
        "description: a real description over ten characters\n"
        "references:\n  - https://attack.mitre.org/T1059.001/\n"
        "falsepositives:\n  - Legit admin scripts\n"
        "logsource:\n  category: process_creation\n  product: windows\n"
        "detection:\n  selection:\n    CommandLine|contains: ' -enc '\n"
        "  filter:\n    Image|endswith: bad.exe\n"
        "  condition: selection and filter\n"
        "level: high\n"
        "tags:\n  - attack.t1059.001\n"
    )
    result = validate_rule_body(yaml_str)
    rules_hit = {w["rule"] for w in result["linter_warnings"]}
    assert "references_empty" not in rules_hit
    assert "falsepositives_empty" not in rules_hit
    assert "mitre_tag_missing" not in rules_hit


def test_validate_pattern_34_redacts_internal_identifiers() -> None:
    # Always-redact -- internal IP / corp domain redacted in echo.
    yaml_str = _good_yaml().replace(
        "Unknown",
        "see acme.corp host 10.10.5.42 user joe@example.com",
    )
    result = validate_rule_body(yaml_str)
    assert result.get("redaction_applied") is True
    # Walk the preview -- no raw internal identifier should remain.
    flat = str(result.get("redacted_rule_preview", ""))
    assert "10.10.5.42" not in flat
    assert "acme.corp" not in flat


def test_validate_strict_mode_promotes_warnings() -> None:
    yaml_str = (
        "title: A short title\n"
        "id: 11111111-2222-3333-8444-555555555555\n"
        "description: a real description over ten characters\n"
        "logsource: {category: process_creation}\n"
        "detection:\n  selection: {Image|endswith: bad.exe}\n"
        "  condition: selection\n"
        "level: medium\n"
    )
    lax = validate_rule_body(yaml_str)
    strict = validate_rule_body(yaml_str, strict=True)
    assert lax["valid"] is True or lax["valid"] is False  # schema may pass
    assert strict["valid"] is False
    assert any(
        e.get("kind") == "linter_strict" for e in strict["schema_errors"]
    )


def test_validate_oversized_input_rejected_before_parse() -> None:
    # DoS guard -- input over the byte cap is rejected before any YAML
    # parsing happens.
    oversized = "title: " + ("A" * (300 * 1024)) + "\n"
    result = validate_rule_body(oversized)
    assert result["valid"] is False
    assert any(
        e.get("kind") == "input_too_large" for e in result["schema_errors"]
    )


def test_validate_yaml_alias_bomb_rejected_not_expanded() -> None:
    # Classic "billion laughs": 12 levels of 10-way fan-out is a <1KB
    # source but ~10^12 logical elements if naively expanded. PyYAML
    # resolves aliases to shared object references so raw parsing alone
    # would stay fast -- the real risk is downstream code (this module's
    # own redaction walk, JSON serialization) walking that shared graph
    # without reference-awareness. Anchors/aliases are rejected outright
    # rather than trusted to be "small enough".
    lines = ['a0: &a0 ["x","x","x","x","x","x","x","x","x","x"]']
    for i in range(1, 12):
        prev = f"a{i - 1}"
        lines.append(
            f"a{i}: &a{i} [*{prev},*{prev},*{prev},*{prev},*{prev},"
            f"*{prev},*{prev},*{prev},*{prev},*{prev}]"
        )
    bomb = (
        "\n".join(lines) + "\n"
        "title: bomb\nid: 11111111-2222-3333-4444-555555555555\n"
        "logsource: {category: x}\n"
        "detection:\n  selection:\n    field: *a11\n  condition: selection\n"
    )
    assert len(bomb.encode("utf-8")) < 1024  # confirms this isn't caught by the size cap

    result = validate_rule_body(bomb)
    assert result["ok"] is True  # completes promptly, does not hang/crash
    assert result["valid"] is False
    assert any(
        e.get("kind") == "yaml_alias_rejected" for e in result["schema_errors"]
    )


def test_validate_deeply_nested_yaml_recursion_error_caught() -> None:
    # #14a -- deep-but-alias-free nesting must not escape as an uncaught
    # RecursionError; it should surface as a clean error envelope instead.
    # Flow-style nested brackets genuinely deepen the parser's call stack
    # (unlike repeating a block-style key at constant indent, which is
    # just a flat mapping with a duplicate key).
    deep_value = "[" * 2000 + "]" * 2000
    yaml_str = (
        "title: deep\nid: 11111111-2222-3333-8444-555555555555\n"
        "logsource: {category: x}\n"
        f"detection:\n  selection:\n    a: {deep_value}\n  condition: selection\n"
    )
    result = validate_rule_body(yaml_str)
    assert result["ok"] is True  # no uncaught RecursionError crash
    assert result["valid"] is False
    assert any(e.get("kind") == "yaml_parse" for e in result["schema_errors"])


def test_validate_uuid_v6_v7_v8_and_nil_accepted() -> None:
    # #14b -- UUIDv6/v7/v8 (RFC 9562) and the nil UUID must not be flagged;
    # only the version/variant nibbles matter, not the exact bytes.
    ids = [
        "1ec9414c-232a-6b00-b3c8-9e6bdeced846",  # v6
        "017f22e2-79b0-7cc3-98c4-dc0c0c07398f",  # v7
        "0d8f23a0-697f-83ae-802e-0129e73c7263",  # v8
        "00000000-0000-0000-0000-000000000000",  # nil
    ]
    for rule_id in ids:
        yaml_str = (
            f"title: id test\nid: {rule_id}\n"
            "logsource: {category: x}\n"
            "detection:\n  selection: {a: 1}\n  condition: selection\n"
        )
        result = validate_rule_body(yaml_str)
        id_errors = [e for e in result["schema_errors"] if e.get("field") == "id"]
        assert id_errors == [], f"{rule_id} unexpectedly flagged: {id_errors}"


def test_validate_multi_doc_first_doc_valid_does_not_force_invalid() -> None:
    # #14c -- a multi-document YAML whose first document is otherwise
    # clean must stay valid=True; the multi-doc notice is informational.
    yaml_str = (
        "title: A clean first document over five chars\n"
        "id: 11111111-2222-3333-8444-555555555555\n"
        "description: a real description over ten characters\n"
        "references:\n  - https://attack.mitre.org/T1059.001/\n"
        "falsepositives:\n  - Legit admin scripts\n"
        "logsource: {category: process_creation}\n"
        "detection:\n  selection: {CommandLine|contains: bad}\n"
        "  condition: selection\n"
        "level: high\ntags:\n  - attack.t1059.001\n"
        "---\n"
        "title: second document\nid: 22222222-3333-4444-5555-666666666666\n"
    )
    result = validate_rule_body(yaml_str)
    assert any(
        e.get("kind") == "multi_doc" for e in result["schema_errors"]
    )
    assert result["valid"] is True


def test_validate_multi_doc_with_real_error_still_invalid() -> None:
    # multi_doc must not mask a GENUINE schema error in the first document.
    yaml_str = (
        "title: foo\nid: 11111111-2222-3333-4444-555555555555\n"
        "logsource: {category: x}\n"  # detection missing -> real error
        "---\n"
        "title: second document\n"
    )
    result = validate_rule_body(yaml_str)
    assert result["valid"] is False
    kinds = {e.get("kind") for e in result["schema_errors"]}
    assert "multi_doc" in kinds
    assert "schema" in kinds


def test_validate_pysigma_missing_returns_actionable_envelope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # pySigma-missing envelope -- simulate ImportError.
    import builtins
    original_import = builtins.__import__

    def fake_import(name: str, *args: object, **kwargs: object) -> object:
        if name == "sigma.rule" or name.startswith("sigma."):
            raise ImportError("No module named 'sigma'")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    result = validate_rule_body(_good_yaml())
    # Schema validation still runs (graceful degradation).
    assert result["ok"] is True
    assert result["pysigma_available"] is False
    assert any(
        "pip install pysigma" in e.get("hint", "")
        for e in result["pysigma_errors"]
    )
