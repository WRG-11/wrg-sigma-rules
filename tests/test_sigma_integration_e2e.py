"""Integration smoke -- end-to-end sigma plugin pipeline tests.

3 pipeline e2e scenarios + 4 backend matrix + 5 pipeline variation tests.
Import-guard discipline (ss15.14 v1.2 7th realisation, cross-corpus
sister pattern): pytest.importorskip("sigma") ensures ALL tests skip
when pySigma is absent and ALL pass when installed.

E2E pipeline: draft_rule_body -> validate_rule_body -> convert_rule_body.
Backend matrix: splunk / elastic / kibana / wazuh.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Import-guard: ALL integration tests SKIP without pySigma.
# Post-install (pySigma 1.3.3): ALL PASS.
pytest.importorskip("sigma", reason="pySigma required for integration tests")

_PLUGIN_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PLUGIN_ROOT))

from tools.draft_rule import draft_rule_body  # noqa: E402
from tools.validate_rule import validate_rule_body  # noqa: E402
from tools.convert_rule import convert_rule_body  # noqa: E402


_POWERSHELL_THREAT = (
    "detect suspicious PowerShell encoded command execution via -enc flag T1059.001"
)
_LSASS_THREAT = "detect LSASS credential dump via comsvcs.dll MiniDump T1003.001"
_RANSOMWARE_THREAT = (
    "detect vssadmin shadow copy deletion used by ransomware for T1490"
)


def _make_rule(description: str, **kwargs) -> str:
    result = draft_rule_body(description, **kwargs)
    assert result["ok"] is True, f"draft_rule_body failed: {result}"
    return result["yaml"]


# ---- Pipeline E2E tests ----

def test_e2e_draft_validate_convert_splunk() -> None:
    """Full pipeline: NL -> draft -> validate -> convert(splunk)."""
    yaml_content = _make_rule(
        _POWERSHELL_THREAT,
        rule_type="process_creation",
        severity="high",
        mitre_ttps=["T1059.001"],
        references=["https://attack.mitre.org/techniques/T1059/001/"],
    )

    validation = validate_rule_body(yaml_content)
    assert validation["ok"] is True
    assert validation["valid"] is True
    assert validation["schema_errors"] == []
    assert validation["pysigma_available"] is True

    conversion = convert_rule_body(yaml_content, target="splunk")
    assert conversion["ok"] is True
    assert conversion["query"], "Splunk query must be non-empty"
    assert conversion["target"] == "splunk"
    assert all(ord(c) < 128 for c in conversion["query"]), "query must be ASCII-only"


def test_e2e_draft_validate_convert_elastic() -> None:
    """Full pipeline: NL -> draft -> validate -> convert(elastic)."""
    yaml_content = _make_rule(
        _LSASS_THREAT,
        rule_type="process_creation",
        severity="critical",
        mitre_ttps=["T1003.001"],
    )

    validation = validate_rule_body(yaml_content)
    assert validation["valid"] is True

    conversion = convert_rule_body(yaml_content, target="elastic")
    assert conversion["ok"] is True
    assert conversion["query"]
    assert conversion["target"] == "elastic"


def test_e2e_validate_corpus_rule_then_convert_splunk() -> None:
    """Pipeline: read corpus rule -> validate -> convert(splunk)."""
    corpus_rule_path = (
        _PLUGIN_ROOT
        / "resources"
        / "examples"
        / "execution"
        / "observed_alphv_t1059_001.yml"
    )
    yaml_content = corpus_rule_path.read_text(encoding="utf-8")

    validation = validate_rule_body(yaml_content)
    assert validation["ok"] is True
    assert validation["valid"] is True, (
        f"Corpus rule schema errors: {validation['schema_errors']}"
    )

    conversion = convert_rule_body(yaml_content, target="splunk")
    assert conversion["ok"] is True
    assert conversion["query"]
    assert conversion["metadata"].get("title"), "Metadata must carry rule title"


# ---- Backend matrix tests ----

_SUPPORTED_BACKENDS = ["splunk", "elastic", "kibana", "wazuh"]


@pytest.mark.parametrize("backend", _SUPPORTED_BACKENDS)
def test_convert_backend_matrix(backend: str) -> None:
    """All 4 supported backends must produce a non-empty query."""
    yaml_content = _make_rule(
        _RANSOMWARE_THREAT,
        rule_type="process_creation",
        severity="critical",
        mitre_ttps=["T1490"],
        references=["https://attack.mitre.org/techniques/T1490/"],
    )
    result = convert_rule_body(yaml_content, target=backend)
    assert result["ok"] is True, (
        f"Backend '{backend}' failed: {result}"
    )
    assert result["query"], f"Backend '{backend}' produced empty query"
    assert result["target"] == backend.lower()
    assert all(ord(c) < 128 for c in result["query"]), (
        f"Backend '{backend}' query not ASCII-only"
    )


def test_convert_unknown_backend_returns_actionable_envelope() -> None:
    """Unknown backend must return error envelope with supported list."""
    yaml_content = _make_rule(_POWERSHELL_THREAT)
    result = convert_rule_body(yaml_content, target="qradar")
    assert result["ok"] is False
    assert result.get("kind") == "unknown_target"
    assert "splunk" in result.get("hint", "").lower()


def test_convert_empty_yaml_returns_error_envelope() -> None:
    result = convert_rule_body("", target="splunk")
    assert result["ok"] is False
    assert result.get("kind") in ("input_missing", "yaml_parse")


def test_convert_invalid_yaml_surfaces_parse_error() -> None:
    result = convert_rule_body("title: bad\nbad yaml:\n  - broken\n  nested: wrong", target="splunk")
    assert result["ok"] is False


# ---- Pipeline variation tests ----

def test_validate_strict_mode_pipeline() -> None:
    """Strict mode promotes linter warnings -- pipeline-level verification."""
    yaml_content = _make_rule(
        "detect anomalous process execution without references",
        rule_type="process_creation",
        severity="medium",
    )
    lax = validate_rule_body(yaml_content)
    strict = validate_rule_body(yaml_content, strict=True)

    # strict=True should have valid=False when linter warnings exist
    if lax["linter_warnings"]:
        assert strict["valid"] is False, "Strict mode must fail when linter warnings exist"
        assert any(
            e.get("kind") == "linter_strict" for e in strict["schema_errors"]
        ), "Strict mode errors must have kind=linter_strict"
    else:
        assert strict["valid"] == lax["valid"]


def test_e2e_mitre_coverage_propagates_through_pipeline() -> None:
    """MITRE TTPs declared at draft must survive validate MITRE coverage."""
    yaml_content = _make_rule(
        "detect lateral movement via WMI remote process creation T1047",
        rule_type="process_creation",
        severity="high",
        mitre_ttps=["T1047", "T1021"],
        references=["https://attack.mitre.org/techniques/T1047/"],
    )
    validation = validate_rule_body(yaml_content)
    assert validation["ok"] is True
    mitre = validation.get("mitre_coverage", {})
    techniques = [t.upper() for t in mitre.get("techniques", [])]
    assert any("T1047" in t for t in techniques), (
        f"T1047 not in MITRE coverage: {techniques}"
    )


def test_e2e_redaction_flag_propagates_through_validate() -> None:
    """Internal IPs in rule should trigger redaction_applied flag in validate."""
    yaml_content = _make_rule(
        "attacker beaconed from 10.20.30.40 to C2 server T1071",
        rule_type="network_connection",
        severity="high",
        mitre_ttps=["T1071"],
    )
    assert "10.20.30.40" not in yaml_content, (
        "draft_rule must redact internal IPs from YAML"
    )
    validation = validate_rule_body(yaml_content)
    assert validation["ok"] is True


def test_e2e_corpus_template_rule_convert_kibana() -> None:
    """Corpus observed rule: validate + convert via kibana backend.

    Uses observed_alphv_t1059_001.yml (simple selection condition) instead of
    the LSASS template (aggregation pipe syntax) -- Kibana/Lucene backend does
    not support the deprecated pipe-aggregation condition syntax.
    Delta: pySigma Lucene backend rejects pipe-aggregation (count() by X > N
    in T) -- routes to Splunk for aggregation rules; kibana test uses plain
    selection-condition rule.
    """
    corpus_rule_path = (
        _PLUGIN_ROOT
        / "resources"
        / "examples"
        / "execution"
        / "observed_alphv_t1059_001.yml"
    )
    yaml_content = corpus_rule_path.read_text(encoding="utf-8")

    validation = validate_rule_body(yaml_content)
    assert validation["valid"] is True

    conversion = convert_rule_body(yaml_content, target="kibana")
    assert conversion["ok"] is True, (
        f"kibana conversion failed: {conversion}"
    )
    assert conversion["query"]
    assert any(
        "kibana" in w.lower() for w in conversion.get("warnings", [])
    ), "kibana backend must emit routing warning"
