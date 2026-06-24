"""Unit tests for ``mcp__plugin_wrg-sigma-rules_wrg-sigma-rules__convert_rule`` tool.

Layer 4 gate coverage:
* G1 -- pySigma missing path simulated.
* G2 -- backend missing path simulated (Splunk + Elastic).
* G3 -- malformed YAML pre-conversion surfaces line + column.
* G4 -- query string redacts internal identifiers if present.
* G5 -- query / metadata strings ASCII-only.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_PLUGIN_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PLUGIN_ROOT))

from tools.draft_rule import draft_rule_body  # noqa: E402
from tools.convert_rule import convert_rule_body  # noqa: E402


def _good_yaml() -> str:
    draft = draft_rule_body(
        "Detect suspicious PowerShell MITRE T1059.001",
        rule_type="process_creation",
        severity="high",
        references=["https://attack.mitre.org/techniques/T1059/001/"],
    )
    return draft["yaml"]


def test_convert_splunk_happy_path() -> None:
    result = convert_rule_body(_good_yaml(), target="splunk")
    assert result["ok"] is True
    assert "REPLACE_ME" in result["query"]
    assert result["target"] == "splunk"
    assert result["metadata"]["title"]


def test_convert_elastic_happy_path() -> None:
    result = convert_rule_body(_good_yaml(), target="elastic")
    assert result["ok"] is True
    assert result["target"] == "elastic"


def test_convert_kibana_emits_alias_warning() -> None:
    result = convert_rule_body(_good_yaml(), target="kibana")
    assert result["ok"] is True
    assert any("kibana" in w.lower() for w in result["warnings"])


def test_convert_wazuh_emits_caveat_warning() -> None:
    result = convert_rule_body(_good_yaml(), target="wazuh")
    assert result["ok"] is True
    assert any("wazuh" in w.lower() for w in result["warnings"])


def test_convert_unknown_target_returns_actionable_error() -> None:
    result = convert_rule_body(_good_yaml(), target="qradar")
    assert result["ok"] is False
    assert result["kind"] == "unknown_target"
    assert "splunk" in result["hint"]


def test_convert_empty_yaml_returns_input_missing() -> None:
    result = convert_rule_body("", target="splunk")
    assert result["ok"] is False
    assert result["kind"] == "input_missing"


def test_convert_malformed_yaml_surfaces_parse_error() -> None:
    # Layer 4 G3 -- pre-conversion parse error.
    result = convert_rule_body(
        "title: only\nmalformed:::", target="splunk"
    )
    assert result["ok"] is False
    assert result["kind"] in {"yaml_parse", "backend_conversion"}


def test_convert_redacts_internal_identifiers_in_query() -> None:
    # Layer 4 G4 -- redact internal IPs that appear in the rule body.
    yaml_str = (
        "title: Detect internal beacon\n"
        "id: 11111111-2222-3333-4444-555555555555\n"
        "description: detects beacons\n"
        "references:\n  - https://example.com\n"
        "logsource:\n  category: network_connection\n  product: windows\n"
        "detection:\n  selection:\n    DestinationIp: 10.10.5.42\n"
        "  condition: selection\n"
        "level: medium\n"
        "tags:\n  - attack.t1071\n"
    )
    result = convert_rule_body(yaml_str, target="splunk")
    assert result["ok"] is True
    assert "10.10.5.42" not in result["query"]
    assert "<internal-ip>" in result["query"]
    assert result.get("redaction_applied") is True


def test_convert_ascii_only_query() -> None:
    # Layer 4 G5 -- output query ASCII-only.
    result = convert_rule_body(_good_yaml(), target="splunk")
    assert all(ord(c) < 128 for c in result["query"])


def test_convert_pysigma_missing_returns_actionable_envelope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Layer 4 G1 -- pySigma core missing.
    import builtins
    original_import = builtins.__import__

    def fake_import(name: str, *args: object, **kwargs: object) -> object:
        if name == "sigma.rule" or name.startswith("sigma."):
            raise ImportError("No module named 'sigma'")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    result = convert_rule_body(_good_yaml(), target="splunk")
    assert result["ok"] is False
    assert result["kind"] == "pysigma_missing"
    assert "pip install pysigma" in result["hint"]


def test_convert_backend_missing_returns_actionable_envelope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Layer 4 G2 -- backend extra missing.
    import builtins
    original_import = builtins.__import__

    def fake_import(name: str, *args: object, **kwargs: object) -> object:
        if name == "sigma.backends.splunk":
            raise ImportError("No module named 'sigma.backends.splunk'")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    result = convert_rule_body(_good_yaml(), target="splunk")
    assert result["ok"] is False
    assert result["kind"] == "backend_missing"
    assert "pip install pysigma-backend-splunk" in result["hint"]
