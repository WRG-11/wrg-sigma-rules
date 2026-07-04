"""Smoke + content tests for the canonical sigma pattern URI resource.

Sister convention to ``apps/wrg_mcp_server/tests/test_resources.py``
(1st canonical Resource layer test surface; this file is the
2nd application of Pattern 33 Rule 6 Resources extension lifecycle).

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

# Add the plugin's tools/ directory to sys.path so the resource module is
# importable without installing the plugin as a package. Mirrors the
# scaffolding convention used by wrg_mcp_server tests.
_PLUGIN_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PLUGIN_ROOT))

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
