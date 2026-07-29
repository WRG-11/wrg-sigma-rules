"""Tests for the ATT&CK coverage resource.

The resource was advertised in README's Resources list for a long time
without existing in code, so these tests assert both halves: the report
says something true about the corpus, AND a real MCP client can reach it.
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

_PLUGIN_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PLUGIN_ROOT))

from tools.resources.coverage_resource import (  # noqa: E402
    collect_coverage,
    coverage_matrix_body,
)

_EXAMPLES = _PLUGIN_ROOT / "resources" / "examples"


def test_rule_total_matches_the_corpus_on_disk() -> None:
    """A hardcoded expected number would rot the next time a rule lands,
    so compare against the filesystem rather than a literal."""
    on_disk = len(list(_EXAMPLES.rglob("*.yml")))
    assert collect_coverage()["total_rules"] == on_disk


def test_technique_count_matches_an_independent_recount() -> None:
    """Recount the tags here by a different route than the module uses,
    so a bug in its parsing cannot agree with itself."""
    seen: set[str] = set()
    for path in _EXAMPLES.rglob("*.yml"):
        for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")):
            if not isinstance(doc, dict):
                continue
            for tag in doc.get("tags") or []:
                text = str(tag).strip().lower()
                if text.startswith("attack.t"):
                    seen.add(text[len("attack."):].upper())
    assert collect_coverage()["total_techniques"] == len(seen)
    assert seen  # guard: an empty corpus would make the assert vacuous


def test_every_tactic_directory_appears() -> None:
    dirs = {p.name for p in _EXAMPLES.iterdir() if p.is_dir()}
    assert set(collect_coverage()["tactics"]) == dirs


def test_body_is_markdown_and_ascii_only() -> None:
    body = coverage_matrix_body()
    assert body.startswith("# WRG Sigma Corpus -- MITRE ATT&CK Coverage")
    body.encode("ascii")


def test_body_reports_a_known_technique_and_tactic() -> None:
    body = coverage_matrix_body()
    # T1486 (Data Encrypted for Impact) is carried by the LockBit rule under
    # impact/ -- if the report cannot name it, it is not reading the corpus.
    assert "T1486" in body
    assert "impact" in body


def test_observed_and_template_split_sums_to_total() -> None:
    data = collect_coverage()
    split = sum(
        t["observed"] + t["template"] + t["other"]
        for t in data["tactics"].values()
    )
    assert split == data["total_rules"]


def test_report_is_honest_about_not_being_a_gap_analysis() -> None:
    """The skill that consumes this brings the ATT&CK matrix; the resource
    must not imply it knows what is missing."""
    body = coverage_matrix_body()
    assert "not a gap analysis" in body


def test_coverage_resource_wired_into_server() -> None:
    """Registered on the real server object, not merely importable --
    the exact gap that left this URI advertised but unreachable."""
    import asyncio

    import server as server_module

    uris = {str(r.uri) for r in asyncio.run(server_module.mcp.list_resources())}
    assert "wrg-sigma://coverage/mitre-attack-matrix" in uris
