"""Golden NL->YAML draft tests -- structure-check invariants for 25 threat descriptions.

Tests verify that draft_rule_body produces well-formed YAML for diverse
threat scenarios. Assertions check STRUCTURAL invariants (required keys,
logsource shape, detection block, MITRE tag presence) NOT exact string
match -- the tool is deterministic but LLM-assisted enrichment at the
skill layer may vary description wording.

No pySigma importorskip here: draft_rule_body gracefully degrades without
pySigma (Layer 4 G1). Tests assert on the G1 envelope when pySigma is absent.

Sister R88-52b breach_corpus test design; V_api_shape Rule 2 pre-read
discipline applied (B done report + draft_rule.py read BEFORE writing).
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

_PLUGIN_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PLUGIN_ROOT))

from tools.draft_rule import draft_rule_body  # noqa: E402

_GOLDEN_CASES: list[dict[str, Any]] = [
    {
        "id": "powershell_encoded_windows",
        "description": "detect suspicious PowerShell encoded command execution via -enc flag",
        "rule_type": "process_creation",
        "target_platform": "windows",
        "severity": "high",
        "expected_logsource": {"category": "process_creation", "product": "windows"},
        "expected_detection_keys": {"selection", "condition"},
    },
    {
        "id": "lsass_dump_mimikatz",
        "description": "detect LSASS memory dump via comsvcs.dll MiniDump T1003.001",
        "rule_type": "process_creation",
        "target_platform": "windows",
        "severity": "critical",
        "mitre_ttps": ["T1003.001"],
        "expected_mitre_tags": ["attack.t1003.001"],
    },
    {
        "id": "ransomware_shadow_copy_delete",
        "description": "detect vssadmin shadow copy deletion used by ransomware T1490",
        "rule_type": "process_creation",
        "target_platform": "windows",
        "severity": "critical",
        "mitre_ttps": ["T1490"],
        "expected_mitre_tags": ["attack.t1490"],
    },
    {
        "id": "lateral_movement_rdp",
        "description": "detect anomalous RDP logon from unexpected source host T1021.001",
        "rule_type": "authentication",
        "target_platform": "windows",
        "severity": "medium",
        "mitre_ttps": ["T1021.001"],
        "expected_logsource": {"category": "authentication", "product": "windows"},
    },
    {
        "id": "dns_c2_beacon",
        "description": "detect high-frequency DNS queries indicating C2 beaconing over DNS T1071.004",
        "rule_type": "dns",
        "target_platform": "windows",
        "severity": "high",
        "mitre_ttps": ["T1071.004"],
        "expected_logsource": {"category": "dns", "product": "windows"},
    },
    {
        "id": "webshell_spawn",
        "description": "detect suspicious child process spawned from web server process T1190",
        "rule_type": "process_creation",
        "target_platform": "windows",
        "severity": "high",
        "mitre_ttps": ["T1190"],
    },
    {
        "id": "linux_bash_reverse_shell",
        "description": "detect bash reverse shell invocation on Linux host T1059.004",
        "rule_type": "process_creation",
        "target_platform": "linux",
        "severity": "high",
        "mitre_ttps": ["T1059.004"],
        "expected_logsource": {"category": "process_creation", "product": "linux"},
    },
    {
        "id": "exfil_mega_upload",
        "description": "detect data exfiltration via MEGA cloud upload utility T1567",
        "rule_type": "network_connection",
        "target_platform": "windows",
        "severity": "high",
        "mitre_ttps": ["T1567"],
        "expected_logsource": {"category": "network_connection", "product": "windows"},
    },
    {
        "id": "registry_persistence_run_key",
        "description": "detect suspicious registry run key modification for persistence T1547.001",
        "rule_type": "registry_event",
        "target_platform": "windows",
        "severity": "medium",
        "mitre_ttps": ["T1547.001"],
        "expected_logsource": {"category": "registry_event", "product": "windows"},
    },
    {
        "id": "brute_force_high_volume",
        "description": "detect high volume failed logon attempts indicating brute force T1110",
        "rule_type": "authentication",
        "target_platform": "windows",
        "severity": "medium",
        "mitre_ttps": ["T1110"],
    },
    {
        "id": "file_event_office_macro_drop",
        "description": "detect Office macro dropping executable file to disk T1204.002",
        "rule_type": "file_event",
        "target_platform": "windows",
        "severity": "high",
        "mitre_ttps": ["T1204.002"],
        "expected_logsource": {"category": "file_event", "product": "windows"},
    },
    {
        "id": "cloud_trail_iam_anomaly",
        "description": "detect anomalous IAM role creation indicating cloud persistence T1098",
        "rule_type": "cloud_audit",
        "target_platform": "cloud",
        "severity": "high",
        "mitre_ttps": ["T1098"],
        "expected_logsource": {"product": "aws"},
    },
    {
        "id": "proxy_suspicious_ua",
        "description": "detect suspicious User-Agent string indicating C2 framework tool T1071.001",
        "rule_type": "proxy",
        "severity": "medium",
        "mitre_ttps": ["T1071.001"],
        "expected_logsource": {"category": "proxy"},
    },
    {
        "id": "macos_persistence_launchd",
        "description": "detect suspicious LaunchDaemon creation for macOS persistence T1543.004",
        "rule_type": "file_event",
        "target_platform": "macos",
        "severity": "high",
        "mitre_ttps": ["T1543.004"],
        "expected_logsource": {"product": "macos"},
    },
    {
        "id": "explicit_title_override",
        "description": "low quality description that should be overridden",
        "rule_type": "process_creation",
        "title": "My Custom Rule Title for Supply Chain Detection",
        "severity": "low",
        "check_title_contains": "Custom Rule Title",
    },
    {
        "id": "redaction_rfc1918_ip",
        "description": "attacker pivoted from 10.0.5.200 to jump host 192.168.1.50 T1021",
        "rule_type": "network_connection",
        "severity": "high",
        "mitre_ttps": ["T1021"],
        "redaction_expected": True,
        "forbidden_in_yaml": ["10.0.5.200", "192.168.1.50"],
    },
    {
        "id": "redaction_email_and_corp_domain",
        "description": "phishing email from attacker@threat.corp targeting finance.internal T1566.001",
        "rule_type": "authentication",
        "severity": "high",
        "mitre_ttps": ["T1566.001"],
        "redaction_expected": True,
        "forbidden_in_yaml": ["attacker@threat.corp", "finance.internal"],
    },
    {
        "id": "multiple_ttps_declared",
        "description": "multi-stage attack combining privilege escalation and lateral movement",
        "rule_type": "process_creation",
        "mitre_ttps": ["T1078", "T1021.001", "T1059.001"],
        "severity": "critical",
        "expected_mitre_tags": ["attack.t1078", "attack.t1021.001", "attack.t1059.001"],
    },
    {
        "id": "mitre_extracted_from_description",
        "description": "MITRE T1059 command interpreter abuse observed in attack chain T1059.001",
        "rule_type": "process_creation",
        "severity": "high",
        "check_mitre_nonempty": True,
    },
    {
        "id": "ascii_only_unicode_input",
        "description": "detect Turkish threat actor using Gizli komut -- em-dash bypass — T1059",
        "rule_type": "process_creation",
        "severity": "medium",
        "check_ascii_only_yaml": True,
    },
    {
        "id": "references_preserved",
        "description": "detect PrintNightmare spooler privilege escalation T1068",
        "rule_type": "process_creation",
        "severity": "critical",
        "mitre_ttps": ["T1068"],
        "references": [
            "https://attack.mitre.org/techniques/T1068/",
            "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-1675",
        ],
        "check_references_in_yaml": True,
    },
    {
        "id": "severity_informational",
        "description": "informational baseline capture of normal admin tool usage",
        "rule_type": "process_creation",
        "severity": "informational",
        "check_level": "informational",
    },
    {
        "id": "severity_low",
        "description": "low severity DNS lookup for unusual TLD research tracking",
        "rule_type": "dns",
        "severity": "low",
        "check_level": "low",
    },
    {
        "id": "unknown_rule_type_fallback",
        "description": "detect anomalous database query pattern T1213",
        "rule_type": "database_event",
        "severity": "medium",
        "mitre_ttps": ["T1213"],
        "check_has_condition": True,
    },
    {
        "id": "deterministic_id_stability",
        "description": "detect suspicious PowerShell encoded command execution via -enc flag",
        "rule_type": "process_creation",
        "target_platform": "windows",
        "severity": "high",
        "check_deterministic_id": True,
    },
]


def _run_draft(case: dict[str, Any]) -> dict[str, Any]:
    kwargs: dict[str, Any] = {}
    if "rule_type" in case:
        kwargs["rule_type"] = case["rule_type"]
    if "target_platform" in case:
        kwargs["target_platform"] = case["target_platform"]
    if "severity" in case:
        kwargs["severity"] = case["severity"]
    if "mitre_ttps" in case:
        kwargs["mitre_ttps"] = case["mitre_ttps"]
    if "references" in case:
        kwargs["references"] = case["references"]
    if "title" in case:
        kwargs["title"] = case["title"]
    return draft_rule_body(case["description"], **kwargs)


@pytest.mark.parametrize("case", _GOLDEN_CASES, ids=[c["id"] for c in _GOLDEN_CASES])
def test_draft_golden_structure(case: dict[str, Any]) -> None:
    result = _run_draft(case)
    assert result["ok"] is True, f"[{case['id']}] draft failed: {result}"
    assert "yaml" in result
    assert "mitre_mapping" in result
    assert "draft_notes" in result
    assert "validation" in result

    parsed = yaml.safe_load(result["yaml"])
    assert isinstance(parsed, dict), f"[{case['id']}] YAML did not parse to dict"

    # Required sigma fields
    for required_key in ("title", "id", "status", "logsource", "detection"):
        assert required_key in parsed, (
            f"[{case['id']}] missing required sigma field '{required_key}'"
        )

    # Detection must have condition
    detection = parsed.get("detection", {})
    assert "condition" in detection, (
        f"[{case['id']}] detection block missing 'condition'"
    )

    # Logsource must be a mapping
    logsource = parsed.get("logsource", {})
    assert isinstance(logsource, dict), f"[{case['id']}] logsource not a dict"


@pytest.mark.parametrize("case", _GOLDEN_CASES, ids=[c["id"] for c in _GOLDEN_CASES])
def test_draft_golden_assertions(case: dict[str, Any]) -> None:
    result = _run_draft(case)
    assert result["ok"] is True
    parsed = yaml.safe_load(result["yaml"])
    logsource = parsed.get("logsource", {})

    if "expected_logsource" in case:
        for key, expected_value in case["expected_logsource"].items():
            assert logsource.get(key) == expected_value, (
                f"[{case['id']}] logsource.{key}={logsource.get(key)!r} "
                f"!= {expected_value!r}"
            )

    if "expected_mitre_tags" in case:
        tags = [t.lower() for t in (parsed.get("tags") or [])]
        for expected_tag in case["expected_mitre_tags"]:
            assert expected_tag.lower() in tags, (
                f"[{case['id']}] expected MITRE tag '{expected_tag}' "
                f"not in tags: {tags}"
            )

    if "redaction_expected" in case:
        for forbidden in case.get("forbidden_in_yaml", []):
            assert forbidden not in result["yaml"], (
                f"[{case['id']}] '{forbidden}' must be redacted from YAML"
            )
        assert any(
            "redact" in note.lower() for note in result["draft_notes"]
        ), f"[{case['id']}] expected redaction note in draft_notes"

    if "check_title_contains" in case:
        assert case["check_title_contains"] in parsed.get("title", ""), (
            f"[{case['id']}] explicit title not preserved: {parsed.get('title')!r}"
        )

    if "check_mitre_nonempty" in case:
        assert result["mitre_mapping"], (
            f"[{case['id']}] expected non-empty mitre_mapping"
        )

    if "check_ascii_only_yaml" in case:
        assert all(ord(c) < 128 for c in result["yaml"]), (
            f"[{case['id']}] non-ASCII character in YAML output"
        )

    if "check_level" in case:
        assert parsed.get("level") == case["check_level"], (
            f"[{case['id']}] level={parsed.get('level')!r} "
            f"!= {case['check_level']!r}"
        )

    if "check_has_condition" in case:
        detection = parsed.get("detection", {})
        assert "condition" in detection, (
            f"[{case['id']}] unknown rule_type fallback missing 'condition'"
        )

    if "check_references_in_yaml" in case:
        refs = parsed.get("references", [])
        assert refs, f"[{case['id']}] references not preserved in YAML"

    if "check_deterministic_id" in case:
        result2 = _run_draft(case)
        yaml_lines1 = result["yaml"].splitlines()
        yaml_lines2 = result2["yaml"].splitlines()
        id_line1 = next((l for l in yaml_lines1 if l.startswith("id:")), None)
        id_line2 = next((l for l in yaml_lines2 if l.startswith("id:")), None)
        assert id_line1 == id_line2, (
            f"[{case['id']}] non-deterministic id: {id_line1!r} vs {id_line2!r}"
        )


def test_draft_invalid_severity_returns_error() -> None:
    result = draft_rule_body("some threat", severity="extreme")
    assert result["ok"] is False
    assert "severity" in result["error"].lower()
    assert "valid_severity" in result


def test_draft_empty_description_returns_error() -> None:
    result = draft_rule_body("")
    assert result["ok"] is False
    assert "description" in result["error"].lower()


def test_draft_whitespace_description_returns_error() -> None:
    result = draft_rule_body("   ")
    assert result["ok"] is False
