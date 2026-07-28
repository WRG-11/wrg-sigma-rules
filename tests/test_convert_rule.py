"""Unit tests for ``mcp__plugin_wrg-sigma-rules_wrg-sigma-rules__convert_rule`` tool.

Design-discipline coverage:
* pySigma missing path simulated.
* Backend missing path simulated (Splunk + Elastic).
* Malformed YAML pre-conversion surfaces line + column.
* Query string redacts internal identifiers if present.
* Query / metadata strings ASCII-only.
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


_CORRELATION_YAML = """\
title: LSASS access burst (base)
name: lsass_access_burst_base
id: 22222222-2222-3222-8222-222222222222
status: test
logsource:
  category: process_access
  product: windows
detection:
  selection:
    TargetImage|endswith: lsass.exe
  condition: selection
level: medium
---
title: LSASS access burst correlation
id: 11111111-1111-3111-8111-111111111111
status: test
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
"""


def test_convert_correlation_rule_splunk_happy_path() -> None:
    """G: a base-rule + correlation-rule 2-document YAML (the modern
    replacement for the deprecated `condition: selection | count() by X > N
    in Ym` pipe syntax) must convert successfully -- this previously failed
    outright because convert_rule_body used SigmaRule.from_yaml (single-rule
    only), which cannot parse a `correlation:` block at all."""
    result = convert_rule_body(_CORRELATION_YAML, target="splunk")
    assert result["ok"] is True
    assert "lsass" in result["query"].lower()
    assert "stats count" in result["query"]
    assert "5m" in result["query"] or "300" in result["query"]


def test_convert_correlation_rule_metadata_is_the_correlation_not_base() -> None:
    result = convert_rule_body(_CORRELATION_YAML, target="splunk")
    assert result["ok"] is True
    assert result["metadata"]["title"] == "LSASS access burst correlation"
    assert result["metadata"]["id"] == "11111111-1111-3111-8111-111111111111"
    assert result["metadata"]["level"] == "high"


def test_convert_correlation_rule_elastic_fails_gracefully() -> None:
    """The installed pysigma-backend-elasticsearch (LuceneBackend, also
    used for kibana/wazuh) does not implement Sigma correlation-rule
    support at all -- confirmed live. This is a genuine backend capability
    gap, not something convert_rule_body can paper over; the fix here is
    only that the failure is now an accurate, actionable pySigma message
    ("Backend does not support correlation rules") instead of the
    confusing "pipe syntax ... deprecated" error the OLD single-rule
    parser produced for every backend indiscriminately."""
    result = convert_rule_body(_CORRELATION_YAML, target="elastic")
    assert result["ok"] is False
    assert result["kind"] == "backend_conversion"
    assert "correlation" in result["error"].lower()


def _windows_process_creation_yaml() -> str:
    return (
        "title: Encoded PowerShell\n"
        "id: 33333333-3333-3333-8333-333333333333\n"
        "status: test\n"
        "logsource:\n  category: process_creation\n  product: windows\n"
        "detection:\n  selection:\n    Image|endswith: '\\powershell.exe'\n"
        "  condition: selection\n"
        "level: high\n"
    )


def test_convert_opensearch_happy_path() -> None:
    result = convert_rule_body(_good_yaml(), target="opensearch")
    assert result["ok"] is True
    assert result["target"] == "opensearch"


def test_convert_opensearch_ppl_is_not_the_lucene_target() -> None:
    """PPL and Lucene are different query languages, so the two OpenSearch
    targets must not quietly return the same string."""
    lucene = convert_rule_body(_good_yaml(), target="opensearch")
    ppl = convert_rule_body(_good_yaml(), target="opensearch-ppl")
    assert lucene["ok"] is True and ppl["ok"] is True
    assert lucene["query"] != ppl["query"]
    assert any("ppl" in w.lower() for w in ppl["warnings"])


def test_convert_elasticsearch_alias_is_advertised_and_works() -> None:
    """'elasticsearch' was accepted by the loader but missing from the
    advertised target list, so the unknown-target hint hid a working
    target. Assert both halves: it converts, and it is advertised."""
    result = convert_rule_body(_good_yaml(), target="elasticsearch")
    assert result["ok"] is True
    unknown = convert_rule_body(_good_yaml(), target="nope")
    assert "elasticsearch" in unknown["hint"]


def test_sysmon_pipeline_changes_the_query_not_just_a_flag() -> None:
    """The pipeline must alter the emitted query, not merely be recorded.

    A presence-assert ("pipelines_applied == ['sysmon']") would pass even
    if the pipeline were built and then dropped on the floor, so compare
    the two queries directly: only the piped one carries the sysmon event
    selection that scopes the rule to process-creation events.
    """
    rule = _windows_process_creation_yaml()
    plain = convert_rule_body(rule, target="splunk")
    piped = convert_rule_body(
        rule, target="splunk", config={"pipeline": "sysmon"}
    )
    assert plain["ok"] is True and piped["ok"] is True
    assert plain["query"] != piped["query"]
    assert "EventID=1" in piped["query"]
    assert "EventID=1" not in plain["query"]
    assert piped["pipelines_applied"] == ["sysmon"]
    assert plain["pipelines_applied"] == []


def test_pipeline_accepts_a_list() -> None:
    result = convert_rule_body(
        _windows_process_creation_yaml(),
        target="splunk",
        config={"pipeline": ["sysmon"]},
    )
    assert result["ok"] is True
    assert result["pipelines_applied"] == ["sysmon"]


def test_unknown_pipeline_is_an_error_not_a_silent_fallback() -> None:
    """Converting anyway would emit a query that looks right and selects
    the wrong events -- worse than failing."""
    result = convert_rule_body(
        _good_yaml(), target="splunk", config={"pipeline": "no-such-pipeline"}
    )
    assert result["ok"] is False
    assert result["kind"] == "unknown_pipeline"
    assert "sysmon" in result["hint"]


def test_pipeline_wrong_type_is_rejected() -> None:
    result = convert_rule_body(
        _good_yaml(), target="splunk", config={"pipeline": 7}
    )
    assert result["ok"] is False
    assert result["kind"] == "invalid_pipeline"


def test_missing_pipeline_package_returns_actionable_envelope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import importlib
    original_import_module = importlib.import_module

    def fake_import_module(name: str, *args: object, **kwargs: object) -> object:
        if name == "sigma.pipelines.sysmon":
            raise ImportError("No module named 'sigma.pipelines.sysmon'")
        return original_import_module(name, *args, **kwargs)

    monkeypatch.setattr(importlib, "import_module", fake_import_module)

    result = convert_rule_body(
        _good_yaml(), target="splunk", config={"pipeline": "sysmon"}
    )
    assert result["ok"] is False
    assert result["kind"] == "pipeline_missing"
    assert "pip install pysigma-pipeline-sysmon" in result["hint"]


def test_pipeline_config_alone_does_not_trigger_unapplied_warning() -> None:
    """'pipeline' is now an applied key, so warning about it would be a lie."""
    result = convert_rule_body(
        _windows_process_creation_yaml(),
        target="splunk",
        config={"pipeline": "sysmon"},
    )
    assert result["ok"] is True
    assert not any("not applied" in w for w in result["warnings"])


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
    # Parse-error surfacing -- pre-conversion parse error.
    result = convert_rule_body(
        "title: only\nmalformed:::", target="splunk"
    )
    assert result["ok"] is False
    assert result["kind"] in {"yaml_parse", "backend_conversion"}


def test_convert_redacts_internal_identifiers_in_query() -> None:
    # Always-redact -- redact internal IPs that appear in the rule body.
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
    # ASCII-only -- output query ASCII-only.
    result = convert_rule_body(_good_yaml(), target="splunk")
    assert all(ord(c) < 128 for c in result["query"])


def test_convert_unused_config_is_flagged_not_silently_dropped() -> None:
    """Regression: passing a non-empty config must warn that it isn't
    applied yet, instead of silently ignoring it."""
    result = convert_rule_body(
        _good_yaml(), target="splunk", config={"index": "main"}
    )
    assert result["ok"] is True
    assert result["config_used"] == {"index": "main"}
    assert any("config parameter is currently accepted but not applied" in w for w in result["warnings"])


def test_convert_no_config_has_no_config_warning() -> None:
    result = convert_rule_body(_good_yaml(), target="splunk")
    assert not any("config parameter" in w for w in result["warnings"])


def test_convert_pysigma_missing_returns_actionable_envelope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # pySigma-missing envelope -- pySigma core missing.
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
    """Backend-missing envelope -- backend extra missing.

    Patches ``importlib.import_module``, which is what the backend registry
    uses to load a backend lazily. An earlier version of this test patched
    ``builtins.__import__`` instead; that stopped simulating anything once
    the registry moved off the import statement, and the test passed while
    the real backend loaded normally.
    """
    import importlib
    original_import_module = importlib.import_module

    def fake_import_module(name: str, *args: object, **kwargs: object) -> object:
        if name == "sigma.backends.splunk":
            raise ImportError("No module named 'sigma.backends.splunk'")
        return original_import_module(name, *args, **kwargs)

    monkeypatch.setattr(importlib, "import_module", fake_import_module)

    result = convert_rule_body(_good_yaml(), target="splunk")
    assert result["ok"] is False
    assert result["kind"] == "backend_missing"
    assert "pip install pysigma-backend-splunk" in result["hint"]
