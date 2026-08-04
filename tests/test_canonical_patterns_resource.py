"""Smoke + content tests for the canonical sigma pattern URI resource.

Sister convention reused from an internal MCP-server resource test
surface (1st canonical Resource layer test surface; this file is the
2nd application of the Resources extension lifecycle).

Test surface covers:

* Body content invariants -- canonical_patterns_body() returns markdown
  INDEX + canonical_pattern_by_id_body() returns individual pattern markdown.
* Normalisation -- accepts ``"1"`` + ``"01"`` + ``"Pattern 1"`` etc.
* ASCII-only discipline matches Pattern 33 Rule 5.
* Unknown ID returns structured JSON envelope.
* All 5 patterns reachable (01 -- 05).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# Add the plugin's tools/ directory to sys.path so the resource module is
# importable without installing the plugin as a package. Mirrors the
# scaffolding convention used by an internal MCP-server test suite.
_PLUGIN_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PLUGIN_ROOT))

# server.py belongs to the public repo's distribution shell and is
# not mirrored here (tools/sigma_public_resync.ps1 is path-driven, by design).
# This test asserts wiring ON that module, so in this layout it has no subject.
# Conditioned on the file itself, never on "we are in the monorepo" -- it
# activates by itself the day the mirror carries server.py.
requires_server_module = pytest.mark.skipif(
    not (_PLUGIN_ROOT / "server.py").is_file(),
    reason="server.py is not mirrored here (public-repo distribution shell)",
)


from tools.resources.canonical_patterns_resource import (  # noqa: E402
    canonical_pattern_by_id_body,
    canonical_patterns_body,
)


def test_canonical_patterns_body_returns_index_markdown() -> None:
    body = canonical_patterns_body()
    # Markdown header
    assert body.startswith("# WRG Canonical Sigma Detection Patterns")
    # 5 pattern table entries present
    assert "[Command-line encoded payload]" in body
    assert "[Credential access via OS internals]" in body
    assert "[Living-off-the-land binary abuse]" in body
    assert "[C2 beaconing network signal]" in body
    assert "[Cross-platform supply chain compromise]" in body
    # Selection heuristic block present
    assert "Pattern selection heuristic" in body


def test_canonical_patterns_body_ascii_only() -> None:
    canonical_patterns_body().encode("ascii")


def test_canonical_pattern_by_id_returns_pattern_1() -> None:
    body = canonical_pattern_by_id_body("01")
    assert body.startswith("# Pattern 1 -- Command-line encoded payload")
    assert "T1027" in body
    assert "T1059.001" in body


def test_canonical_pattern_by_id_normalizes_bare_digit() -> None:
    body_bare = canonical_pattern_by_id_body("1")
    body_padded = canonical_pattern_by_id_body("01")
    assert body_bare == body_padded


def test_canonical_pattern_by_id_normalizes_prefix() -> None:
    for variant in ("Pattern 2", "pattern-2", "p02", "2", "02"):
        body = canonical_pattern_by_id_body(variant)
        assert body.startswith("# Pattern 2 -- Credential access via OS internals"), (
            f"variant '{variant}' failed: {body[:200]}"
        )


def test_canonical_pattern_by_id_all_5_present() -> None:
    expected_titles = {
        "01": "# Pattern 1 -- Command-line encoded payload",
        "02": "# Pattern 2 -- Credential access via OS internals",
        "03": "# Pattern 3 -- Living-off-the-land binary abuse",
        "04": "# Pattern 4 -- C2 beaconing network signal",
        "05": "# Pattern 5 -- Cross-platform supply chain compromise",
    }
    for pid, expected_title in expected_titles.items():
        body = canonical_pattern_by_id_body(pid)
        assert body.startswith(expected_title), f"id '{pid}' wrong title: {body[:200]}"


def test_canonical_pattern_by_id_ascii_only() -> None:
    for pid in ("01", "02", "03", "04", "05"):
        canonical_pattern_by_id_body(pid).encode("ascii")


def test_canonical_pattern_by_id_unknown_returns_envelope() -> None:
    body = canonical_pattern_by_id_body("99")
    doc = json.loads(body)
    assert doc["ok"] is False
    assert "not found" in doc["error"]
    assert "01" in doc["available_ids"]
    assert "05" in doc["available_ids"]


def test_canonical_pattern_by_id_empty_returns_envelope() -> None:
    body = canonical_pattern_by_id_body("xyz")  # no digits
    doc = json.loads(body)
    assert doc["ok"] is False
    assert "at least one digit" in doc["error"]


def test_canonical_pattern_by_id_includes_canonical_yaml_shape() -> None:
    # Pattern 1 should contain a YAML shape block
    body = canonical_pattern_by_id_body("01")
    assert "```yaml" in body
    assert "logsource:" in body
    assert "detection:" in body
    assert "condition:" in body


def test_canonical_pattern_by_id_includes_severity_guidance() -> None:
    # All patterns should have severity guidance
    for pid in ("01", "02", "03", "04", "05"):
        body = canonical_pattern_by_id_body(pid)
        assert "Severity guidance" in body, f"pattern {pid} missing severity guidance"


def test_canonical_pattern_by_id_includes_reference_rules() -> None:
    # All patterns should reference at least one rule from the examples corpus
    for pid in ("01", "02", "03", "04", "05"):
        body = canonical_pattern_by_id_body(pid)
        assert "Reference rules from corpus" in body, (
            f"pattern {pid} missing reference rules"
        )


@requires_server_module
def test_canonical_pattern_resources_wired_into_server() -> None:
    # Note: every test above calls the *_body() functions directly,
    # bypassing the MCP machinery entirely -- they would all still pass even
    # if register_canonical_pattern_resources() were never called by any
    # real server (which was the case until this fix: server.py registered
    # the 3 tools but not this resource module, so a real MCP client could
    # never actually reach wrg-sigma://patterns/canonical-5). Import the
    # real server module and assert the resource + template are genuinely
    # registered on it, closing that gap.
    import asyncio

    import server as server_module

    def _template_uri(template: object) -> str:
        # mcp 1.x names this field `uriTemplate`; 2.x renamed it to
        # `uri_template`. server.py works on both SDKs, so the assertion
        # must too -- reading only one name turns an SDK rename into a
        # false failure about resource registration.
        for attr in ("uriTemplate", "uri_template"):
            value = getattr(template, attr, None)
            if value is not None:
                return str(value)
        raise AssertionError(
            f"resource template exposes no URI-template attribute: {template!r}"
        )

    resource_uris = {
        str(r.uri) for r in asyncio.run(server_module.mcp.list_resources())
    }
    template_uris = {
        _template_uri(t)
        for t in asyncio.run(server_module.mcp.list_resource_templates())
    }
    assert "wrg-sigma://patterns/canonical-5" in resource_uris
    assert "wrg-sigma://patterns/canonical-5/{pattern_id}" in template_uris


def test_canonical_pattern_missing_file_returns_honest_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``_PATTERN_FILES`` naming an ID whose file does not exist on disk is a
    distinct failure mode from an unknown ID (that one is caught earlier, by
    the dict lookup itself): the catalog entry is right and the file behind
    it is missing. This must not raise -- it returns the same structured
    envelope shape as every other error branch here."""
    from tools.resources import canonical_patterns_resource as cpr

    monkeypatch.setitem(cpr._PATTERN_FILES, "09", "09_does_not_exist.md")

    body = canonical_pattern_by_id_body("09")
    payload = json.loads(body)
    assert payload["ok"] is False
    assert "missing" in payload["error"].lower()
    assert "09_does_not_exist.md" in payload["expected_path"]
