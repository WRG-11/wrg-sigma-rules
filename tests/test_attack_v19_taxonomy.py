"""The corpus uses MITRE ATT&CK Enterprise v19 tactics and no retired identifiers.

ATT&CK v19 split the former Defense Evasion tactic into Stealth (TA0005) and
Defense Impairment (TA0112), and revoked several techniques this corpus used:
T1562.001 (now T1685), T1070.001 (now T1685.005) and T1656 (now T1684.001).
The corpus also carried T1656.002, an identifier that exists in no ATT&CK
release. The README and plugin manifest describe the directories as "one per
MITRE ATT&CK Enterprise tactic plus code_review"; this file is what keeps that
sentence true.

What this does NOT check: that a technique still exists in whatever ATT&CK
release is current when you read this. The retired set below is the one
measured against enterprise-attack 19.2; a later release can retire more.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

_EXAMPLES = Path(__file__).resolve().parents[1] / "resources" / "examples"

# x-mitre-tactic shortnames in enterprise-attack 19.2, underscore form.
V19_TACTICS = frozenset({
    "reconnaissance", "resource_development", "initial_access", "execution",
    "persistence", "privilege_escalation", "stealth", "defense_impairment",
    "credential_access", "discovery", "lateral_movement", "collection",
    "command_and_control", "exfiltration", "impact",
})
NON_ATTACK_CATEGORIES = frozenset({"code_review"})

RETIRED_TAGS = frozenset({
    "attack.defense_evasion", "attack.defense-evasion",
    "attack.t1562.001", "attack.t1070.001", "attack.t1656", "attack.t1656.002",
})


def _rules() -> list[Path]:
    return sorted(_EXAMPLES.rglob("*.yml"))


def test_directories_are_v19_tactics_plus_code_review() -> None:
    dirs = {p.name for p in _EXAMPLES.iterdir() if p.is_dir()}
    assert dirs == V19_TACTICS | NON_ATTACK_CATEGORIES


def test_no_rule_carries_a_retired_attack_tag() -> None:
    offenders = []
    for path in _rules():
        tags = re.findall(r"^\s*-\s*(attack\.[a-z0-9_.-]+)\s*$", path.read_text(encoding="utf-8"), re.M)
        bad = sorted(set(tags) & RETIRED_TAGS)
        if bad:
            offenders.append((path.relative_to(_EXAMPLES).as_posix(), bad))
    assert not offenders, offenders


def test_wrg_tactic_tag_matches_directory() -> None:
    offenders = []
    for path in _rules():
        tags = set(re.findall(r"^\s*-\s*wrg\.tactic\.([a-z_]+)\s*$", path.read_text(encoding="utf-8"), re.M))
        if tags and tags != {path.parent.name}:
            offenders.append((path.relative_to(_EXAMPLES).as_posix(), sorted(tags)))
    assert not offenders, offenders


def test_retired_set_would_catch_a_real_regression(tmp_path: Path) -> None:
    """Canary: the tag scan must see a retired tag in the form rules use."""
    sample = tmp_path / "x.yml"
    sample.write_text("tags:\n  - attack.defense_evasion\n  - attack.t1562.001\n", encoding="utf-8")
    tags = set(re.findall(r"^\s*-\s*(attack\.[a-z0-9_.-]+)\s*$", sample.read_text(encoding="utf-8"), re.M))
    assert tags & RETIRED_TAGS == {"attack.defense_evasion", "attack.t1562.001"}
