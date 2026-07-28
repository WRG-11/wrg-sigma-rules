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


def test_validate_non_string_id_flagged_cleanly() -> None:
    """G dogfood-audit: a bare (unquoted) numeric id -- e.g. ``id: 12345`` --
    used to skip the schema-level id check entirely (it was gated behind
    ``isinstance(rule["id"], str)``, same as the format check), so the only
    signal was pysigma's raw internal crash message ("'int' object has no
    attribute 'replace'") instead of the tool's own clean, actionable
    vocabulary every other type-mismatch field uses (logsource/detection)."""
    yaml_str = (
        "title: foo\nid: 12345\nlogsource: {category: x}\n"
        "detection:\n  selection: {a: 1}\n  condition: selection\n"
    )
    result = validate_rule_body(yaml_str)
    assert result["valid"] is False
    id_errors = [e for e in result["schema_errors"] if e.get("field") == "id"]
    assert id_errors, "non-string id must be flagged at the schema-check layer"
    assert "string" in id_errors[0]["message"].lower()


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


def test_validate_flags_deprecated_pipe_aggregation_condition() -> None:
    """G dogfood-audit: `condition: selection | count() by X > N in Ym` (the
    pre-correlation-rule aggregation pipe syntax) parses fine under pySigma's
    SigmaRule.from_yaml -- validate_rule reported valid=true for all 8 real
    corpus rules using this pattern -- but EVERY backend (Splunk, Elastic)
    rejects it at conversion time ("pipe syntax ... deprecated ... replaced
    by Sigma correlations"), live-verified. validate_rule must warn about
    this convertibility gap instead of giving false confidence."""
    yaml_str = (
        "title: Ransomware extension burst\n"
        "id: 11111111-2222-3333-8444-555555555555\n"
        "description: a real description over ten characters\n"
        "references:\n  - https://attack.mitre.org/T1486/\n"
        "falsepositives:\n  - none\n"
        "logsource:\n  category: file_event\n  product: windows\n"
        "detection:\n  selection:\n    TargetFilename|endswith: '.locked'\n"
        "  condition: selection | count() by Image > 20 in 5m\n"
        "level: high\n"
        "tags:\n  - attack.t1486\n"
    )
    result = validate_rule_body(yaml_str)
    rules_hit = {w["rule"] for w in result["linter_warnings"]}
    assert "deprecated_pipe_condition" in rules_hit


def test_validate_field_modifier_pipe_is_not_flagged_as_deprecated_condition() -> None:
    """The field-modifier pipe (``CommandLine|contains``) is normal, current
    sigma syntax -- must not be confused with a pipe INSIDE the condition
    string. Reuses the same rule as the "clean" happy-path test above."""
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
    assert "deprecated_pipe_condition" not in rules_hit


def test_validate_pattern_34_redacts_internal_identifiers() -> None:
    """Always-redact -- internal IP / corp domain redacted in echo.

    The identifiers are injected into `description` rather than by
    string-replacing a word out of the draft output. This test used to
    replace the literal "Unknown" that draft_rule wrote into
    `falsepositives`; when that placeholder was changed, the replace
    silently matched nothing and the test asserted redaction on a rule
    that contained no identifiers to redact.
    """
    import yaml

    doc = yaml.safe_load(_good_yaml())
    doc["description"] = "see acme.corp host 10.10.5.42 user joe@example.com"
    yaml_str = yaml.safe_dump(doc, sort_keys=False)
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


_CORRELATION_YAML = """\
title: LSASS access burst (base)
name: lsass_access_burst_base
id: 22222222-2222-3222-8222-222222222222
status: test
description: a real description over ten characters
references:
  - https://attack.mitre.org/T1003/
falsepositives:
  - Legit admin scripts
logsource:
  category: process_access
  product: windows
detection:
  selection:
    TargetImage|endswith: lsass.exe
  condition: selection
level: medium
tags:
  - attack.t1003
---
title: LSASS access burst correlation
id: 11111111-1111-3111-8111-111111111111
status: test
description: a real description over ten characters
references:
  - https://attack.mitre.org/T1003/
falsepositives:
  - Legit admin scripts
correlation:
  type: event_count
  rules:
    - lsass_access_burst_base
  group-by:
    - SourceImage
  timespan: 5m
  condition:
    gt: 5
level: high
tags:
  - attack.t1003
"""


def test_validate_correlation_rule_pair_is_pysigma_valid() -> None:
    """Smoke test: a well-formed base-rule + correlation-rule 2-document
    YAML must report valid=True. On its own this does not discriminate the
    fix (see test_validate_broken_correlation_document_is_actually_checked
    below for the version that does) -- doc[0] alone is a self-sufficient
    valid rule by construction, so this passed even before the fix."""
    result = validate_rule_body(_CORRELATION_YAML)
    assert result["pysigma_errors"] == []
    assert result["valid"] is True


def test_validate_broken_correlation_document_is_actually_checked() -> None:
    """G: THE discriminating test. Same base rule as _CORRELATION_YAML
    (independently valid), but the correlation document itself is broken
    (invalid timespan, no rules: reference). Before the fix,
    _pysigma_validate reduced EVERY multi-doc input down to doc[0] alone --
    so this silently reported valid=True, never having looked at the
    correlation document at all. Live-verified pre-fix: pysigma_errors=[],
    valid=True even with a nonsense timespan and a missing rule reference."""
    yaml_str = (
        "title: LSASS access burst (base)\n"
        "name: lsass_access_burst_base\n"
        "id: 22222222-2222-3222-8222-222222222222\n"
        "status: test\n"
        "description: a real description over ten characters\n"
        "references:\n  - https://attack.mitre.org/T1003/\n"
        "falsepositives:\n  - Legit admin scripts\n"
        "logsource:\n  category: process_access\n  product: windows\n"
        "detection:\n  selection:\n    TargetImage|endswith: lsass.exe\n"
        "  condition: selection\n"
        "level: medium\ntags:\n  - attack.t1003\n"
        "---\n"
        "title: LSASS access burst correlation\n"
        "id: 11111111-1111-3111-8111-111111111111\n"
        "status: test\n"
        "description: a real description over ten characters\n"
        "references:\n  - https://attack.mitre.org/T1003/\n"
        "falsepositives:\n  - Legit admin scripts\n"
        "correlation:\n"
        "  type: event_count\n"
        "  timespan: not-a-valid-timespan\n"
        "  group-by:\n    - SourceImage\n"
        "  condition:\n    gt: 5\n"
        "level: high\ntags:\n  - attack.t1003\n"
    )
    result = validate_rule_body(yaml_str)
    assert result["pysigma_errors"] != []
    assert result["valid"] is False


def test_validate_generic_multi_doc_still_reduces_to_first_doc_only() -> None:
    """Regression guard: ORDINARY multi-doc input (no correlation: block --
    e.g. a stray/incomplete second document) must keep the existing,
    tested behaviour of validating doc[0] alone. Only a genuine
    correlation-rule pair gets the full-collection pysigma parse."""
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
    assert result["pysigma_errors"] == []
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


def _rule_with_falsepositives(entries: list[str]) -> str:
    import yaml

    return yaml.safe_dump(
        {
            "title": "Encoded PowerShell execution",
            "id": "11111111-1111-4111-8111-111111111111",
            "status": "experimental",
            "description": "Detects encoded PowerShell command execution",
            "references": ["https://attack.mitre.org/techniques/T1059/001/"],
            "logsource": {"category": "process_creation", "product": "windows"},
            "detection": {
                "selection": {"Image|endswith": r"\powershell.exe"},
                "filter": {"CommandLine|contains": "-NoProfile"},
                "condition": "selection and not filter",
            },
            "falsepositives": entries,
            "level": "high",
            "tags": ["attack.t1059.001"],
        },
        sort_keys=False,
    )


def _lint_rules(yaml_text: str) -> list[str]:
    result = validate_rule_body(yaml_text)
    return [
        w.get("rule")
        for w in (result.get("linter_warnings") or [])
        if isinstance(w, dict)
    ]


def test_placeholder_falsepositives_are_flagged() -> None:
    """A populated-but-meaningless block passes the empty check while giving
    an analyst nothing to tune on, so it needs its own warning."""
    for placeholder in (
        "Unknown",
        "N/A",
        "TODO -- replace with a concrete benign scenario",
        "Pattern library v1 -- review for environment-specific tuning before deployment",
    ):
        rules = _lint_rules(_rule_with_falsepositives([placeholder]))
        assert "falsepositives_placeholder" in rules, (
            f"not flagged: {placeholder!r}"
        )
        assert "falsepositives_empty" not in rules, (
            "the block is populated; the empty warning would be wrong"
        )


def test_real_falsepositive_scenario_is_not_flagged() -> None:
    rules = _lint_rules(
        _rule_with_falsepositives(
            ["Administrative deployment scripts invoking powershell.exe with -enc"]
        )
    )
    assert "falsepositives_placeholder" not in rules


def test_scenario_containing_the_word_unknown_is_not_flagged() -> None:
    """Matched on the whole entry, not as a substring search -- otherwise a
    real scenario mentioning an unknown parent process trips the rule."""
    rules = _lint_rules(
        _rule_with_falsepositives(
            ["Legitimate tooling whose parent process is unknown to the asset inventory"]
        )
    )
    assert "falsepositives_placeholder" not in rules


def test_mixed_list_with_one_real_scenario_is_not_flagged() -> None:
    """A rule listing a real scenario plus a leftover TODO has already done
    the work the warning asks for."""
    rules = _lint_rules(
        _rule_with_falsepositives(
            ["Backup software writing those paths nightly", "TODO -- add more"]
        )
    )
    assert "falsepositives_placeholder" not in rules


def test_draft_scaffolding_left_in_detection_is_flagged() -> None:
    """draft_rule emits REPLACE_ME for values the author must supply; a
    shipped rule containing it matches the literal placeholder string."""
    import yaml

    doc = yaml.safe_load(_rule_with_falsepositives(["Real benign scenario here"]))
    doc["detection"]["selection"]["Image|endswith"] = "REPLACE_ME.exe"
    rules = _lint_rules(yaml.safe_dump(doc, sort_keys=False))
    assert "draft_scaffold_left_in" in rules


def test_clean_rule_has_neither_falsepositive_warning() -> None:
    rules = _lint_rules(
        _rule_with_falsepositives(["Administrative deployment scripts"])
    )
    assert "falsepositives_placeholder" not in rules
    assert "falsepositives_empty" not in rules
