"""Unit tests for ``mcp__plugin_wrg-sigma-rules_wrg-sigma-rules__draft_rule`` tool.

Design-discipline coverage:
* pySigma-missing envelope -- ``test_pysigma_missing_returns_actionable_envelope``
  uses monkeypatch to simulate ImportError.
* YAML line + column -- covered via the validate_rule tests; draft
  itself produces parseable YAML by construction.
* Always-redact -- ``test_pattern_34_redaction_applied`` /
  ``test_pattern_34_internal_domain_redacted``.
* ASCII-only -- ``test_ascii_only_output``.

10-case happy + edge + error coverage pattern.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_PLUGIN_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PLUGIN_ROOT))

from tools.draft_rule import draft_rule_body  # noqa: E402


def test_draft_rule_happy_path_process_creation() -> None:
    result = draft_rule_body(
        "Detect suspicious PowerShell encoded command MITRE T1059.001",
        rule_type="process_creation",
        severity="high",
        references=["https://attack.mitre.org/techniques/T1059/001/"],
    )
    assert result["ok"] is True
    assert "yaml" in result
    assert "T1059.001" in result["mitre_mapping"]
    assert result["validation"]["available"] is True
    assert result["validation"]["valid"] is True


def test_draft_rule_empty_description_returns_error() -> None:
    result = draft_rule_body("")
    assert result["ok"] is False
    assert "description" in result["error"].lower()


def test_draft_rule_invalid_severity_returns_error() -> None:
    result = draft_rule_body(
        "Some threat", severity="extreme"
    )
    assert result["ok"] is False
    assert "severity" in result["error"].lower()
    assert "valid_severity" in result


def test_pattern_34_redaction_applied() -> None:
    # Always-redact -- internal IP must be replaced with placeholder.
    result = draft_rule_body(
        "C2 beaconing from 10.10.5.42 to attacker server",
        rule_type="network_connection",
    )
    assert result["ok"] is True
    assert "10.10.5.42" not in result["yaml"]
    assert "<internal-ip>" in result["yaml"]
    assert any(
        "redact" in note.lower() for note in result["draft_notes"]
    )


def test_pattern_34_internal_domain_redacted() -> None:
    # Always-redact -- ``.corp`` / ``.internal`` suffixes redacted.
    result = draft_rule_body(
        "User joe@acme.corp received phishing link from finance.lan",
        rule_type="authentication",
    )
    assert result["ok"] is True
    assert "joe@acme.corp" not in result["yaml"]
    assert "finance.lan" not in result["yaml"]


def test_ascii_only_output() -> None:
    # ASCII-only -- em-dashes + non-ASCII inputs scrubbed in YAML body.
    result = draft_rule_body(
        "Detect command-line encoded payload — T1027",
        rule_type="process_creation",
    )
    assert result["ok"] is True
    assert all(ord(c) < 128 for c in result["yaml"])


def test_pysigma_missing_returns_actionable_envelope(monkeypatch: pytest.MonkeyPatch) -> None:
    # pySigma-missing envelope -- simulate pySigma not installed.
    import builtins
    original_import = builtins.__import__

    def fake_import(name: str, *args: object, **kwargs: object) -> object:
        if name == "sigma.rule" or name.startswith("sigma."):
            raise ImportError("No module named 'sigma'")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    result = draft_rule_body(
        "Detect suspicious PowerShell command",
        rule_type="process_creation",
    )
    # YAML still produced (best-effort) but validation block degrades.
    assert result["ok"] is True
    assert "yaml" in result
    assert result["validation"]["available"] is False
    assert "pip install pysigma" in result["validation"]["hint"]


def test_deterministic_uuid_for_same_inputs() -> None:
    a = draft_rule_body(
        "Identical threat description", rule_type="process_creation"
    )
    b = draft_rule_body(
        "Identical threat description", rule_type="process_creation"
    )
    assert a["yaml"].split("\n")[1] == b["yaml"].split("\n")[1]


def test_mitre_ttps_declared_wins_over_description_scan() -> None:
    result = draft_rule_body(
        "Generic threat T1059 mentioned in description",
        rule_type="process_creation",
        mitre_ttps=["T9999"],
    )
    # Declared takes precedence even when the value is exotic.
    assert "T9999" in result["mitre_mapping"]


def test_logsource_platform_override() -> None:
    # ``target_platform=linux`` should swap ``product:`` to linux.
    result = draft_rule_body(
        "Detect suspicious bash subshell invocation",
        rule_type="process_creation",
        target_platform="linux",
    )
    assert result["ok"] is True
    assert "product: linux" in result["yaml"]


def test_yaml_emit_neutralizes_reference_newline_injection() -> None:
    # SIGMA-LM-001: a newline embedded in a reference must not break out of the
    # YAML list context and inject a sibling top-level key. The control char is
    # collapsed to inline whitespace instead.
    result = draft_rule_body(
        "Detect process spawning child",
        references=["http://legit.example/a\n  injected_key: pwned"],
    )
    assert result["ok"] is True
    lines = result["yaml"].splitlines()
    # No emitted line may begin with the injected key (the injection vector).
    assert not any(line.lstrip().startswith("injected_key") for line in lines)
    # The payload survives, collapsed onto the single reference list item.
    assert any(
        line.lstrip().startswith("- ") and "injected_key: pwned" in line
        for line in lines
    )


def test_yaml_emit_leaves_normal_url_reference_unquoted() -> None:
    # Behaviour-neutral: a clean URL reference (which contains ':') stays an
    # unquoted list item -- YAML's plain-scalar rule only requires quoting
    # a colon followed by whitespace, which "https://..." never is.
    result = draft_rule_body(
        "Detect suspicious activity",
        references=["https://attack.mitre.org/techniques/T1059/"],
    )
    assert result["ok"] is True
    lines = result["yaml"].splitlines()
    assert any(
        line.lstrip() == "- https://attack.mitre.org/techniques/T1059/"
        for line in lines
    )
    assert "'https://attack.mitre.org" not in result["yaml"]


def test_yaml_emit_round_trips_reference_with_colon_and_hash() -> None:
    # Round-trip property: the prior hand-rolled emitter only
    # quoted problem characters in TOP-LEVEL scalars -- a list item
    # containing ':' re-parsed as a nested one-key mapping instead of a
    # plain string, and an inline ' #' anywhere silently truncated the rest
    # of the value as a YAML comment. safe_dump quotes correctly in every
    # position, so the parsed rule must reproduce the input exactly.
    import yaml

    tricky_refs = [
        "Note: see section 3:15 for details",
        "http://example.com/path #not-a-comment",
    ]
    result = draft_rule_body("Detect suspicious activity", references=tricky_refs)
    assert result["ok"] is True
    parsed = yaml.safe_load(result["yaml"])
    assert parsed["references"] == tricky_refs
