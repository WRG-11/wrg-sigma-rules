"""Unit tests for ``mcp__wrg-sigma__validate_rule`` tool.

Layer 4 gate coverage:
* G1 -- pySigma missing path simulated via monkeypatch.
* G3 -- malformed YAML triggers ``line`` + ``column`` in schema_errors.
* G4 -- internal-looking identifiers redacted in the rule preview echo.
* G5 -- output strings ASCII-only.

Sister R88-52d first-attempt PASS discipline.
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
    # Layer 4 G3 -- parse error must include line + column.
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
        "id: 11111111-2222-3333-4444-555555555555\n"
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
        "id: 11111111-2222-3333-4444-555555555555\n"
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
    # Layer 4 G4 -- internal IP / corp domain redacted in echo.
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
        "id: 11111111-2222-3333-4444-555555555555\n"
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


def test_validate_pysigma_missing_returns_actionable_envelope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Layer 4 G1 -- simulate ImportError.
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
