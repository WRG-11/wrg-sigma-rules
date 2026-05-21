"""MCP Resource module exposing the 5 canonical sigma detection patterns.

Sister to ``wrg_mcp_server.tools.resources`` (D R88-52d 1st canonical
Resource layer for WRG core; this module is the 2nd application of
Pattern 33 Rule 6 Resources extension lifecycle).

Resources exposed:

* ``wrg-sigma://patterns/canonical-5`` -- INDEX.md (overview + selection
  heuristic).
* ``wrg-sigma://patterns/canonical-5/{pattern_id}`` -- Individual pattern
  markdown by zero-padded numeric ID (``01`` -- ``05``).

Test surface: ``canonical_patterns_body()`` and
``canonical_pattern_by_id_body(pattern_id)`` exposed at module level so
unit tests can assert content without invoking the MCP machinery.

ASCII-only discipline (Pattern 33 Rule 5 cross-platform safe).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


# Pattern files live in plugins/wrg-sigma-rules/resources/canonical-patterns/
# relative to this module: ../../resources/canonical-patterns/
_PATTERNS_DIR = (
    Path(__file__).resolve().parent.parent.parent
    / "resources"
    / "canonical-patterns"
)

# Pattern ID -> filename map. Manually maintained so unknown IDs return
# an envelope error rather than scanning the filesystem.
_PATTERN_FILES: dict[str, str] = {
    "01": "01-command-line-encoded-payload.md",
    "02": "02-credential-access-os-internals.md",
    "03": "03-lolbin-abuse.md",
    "04": "04-c2-beaconing-network-signal.md",
    "05": "05-supply-chain-compromise.md",
}


def canonical_patterns_body() -> str:
    """Return the INDEX.md content for the 5 canonical sigma patterns.

    Returns the raw markdown file content. Use this resource as a
    starting point for sigma rule writing: read the INDEX, pick the
    closest matching pattern, then drill in via the
    ``{pattern_id}`` templated URI.
    """
    index_path = _PATTERNS_DIR / "INDEX.md"
    if not index_path.exists():
        return json.dumps(
            {
                "ok": False,
                "error": "canonical patterns INDEX.md not found",
                "expected_path": str(index_path),
            },
            indent=2,
        )
    text = index_path.read_text(encoding="utf-8")
    # Defensive ASCII coercion -- the migration script enforces this
    # upstream but a redundant check at the resource boundary catches
    # any future drift.
    return text.encode("ascii", errors="replace").decode("ascii")


def canonical_pattern_by_id_body(pattern_id: str) -> str:
    """Return individual canonical pattern markdown by numeric ID.

    Accepts ``"01"`` through ``"05"`` (zero-padded) or bare ``"1"`` /
    ``"5"`` (normalised). Unknown IDs return a JSON envelope with the
    available ID list. ASCII-only output.
    """
    raw = pattern_id.strip()
    # Normalise to zero-padded 2-digit form.
    digits = "".join(c for c in raw if c.isdigit())
    if not digits:
        payload: dict[str, Any] = {
            "ok": False,
            "error": (
                "pattern_id must contain at least one digit; got "
                f"'{raw}'"
            ),
            "available_ids": sorted(_PATTERN_FILES.keys()),
        }
        return json.dumps(payload, indent=2)
    norm = digits.zfill(2)
    filename = _PATTERN_FILES.get(norm)
    if filename is None:
        payload = {
            "ok": False,
            "error": f"pattern_id '{norm}' not found",
            "available_ids": sorted(_PATTERN_FILES.keys()),
            "note": (
                "Canonical pattern catalog has 5 entries (01-05); "
                "see wrg-sigma://patterns/canonical-5 for INDEX."
            ),
        }
        return json.dumps(payload, indent=2)
    pattern_path = _PATTERNS_DIR / filename
    if not pattern_path.exists():
        payload = {
            "ok": False,
            "error": f"pattern file missing: {filename}",
            "expected_path": str(pattern_path),
        }
        return json.dumps(payload, indent=2)
    text = pattern_path.read_text(encoding="utf-8")
    return text.encode("ascii", errors="replace").decode("ascii")


def register_canonical_pattern_resources(mcp: Any) -> None:
    """Register the 5 canonical sigma pattern resources on an MCP server.

    Plugin-side registration helper. Accepts any object that exposes
    the ``@resource()`` decorator (FastMCP, or a future plugin-host
    MCP shim). Idempotent on import (decorator runs once per server
    construction).

    Sister to ``wrg_mcp_server.tools.resources.register_corpus_resources``
    (D R88-52d 1st canonical; this is the 2nd Pattern 33 Rule 6
    application).

    Note: the plugin's MCP server entry point (which B / F will wire
    up in R88-56b / R88-56f) is responsible for calling this function.
    The resource module itself is decoupled from the MCP runtime.
    """

    @mcp.resource(
        "wrg-sigma://patterns/canonical-5",
        name="wrg-sigma-canonical-patterns",
        description=(
            "5 canonical sigma detection pattern shape definitions "
            "distilled from 6+ months of WRG threat-intel corpus + "
            "50+ sigma rule operations. Use as a starting point for "
            "drafting new rules. Pattern selection heuristic + MITRE "
            "coverage matrix + per-pattern shape definitions inline. "
            "ASCII-only markdown body."
        ),
        mime_type="text/markdown",
    )
    def canonical_patterns() -> str:
        return canonical_patterns_body()

    @mcp.resource(
        "wrg-sigma://patterns/canonical-5/{pattern_id}",
        name="wrg-sigma-canonical-pattern-by-id",
        description=(
            "Individual canonical sigma pattern markdown by numeric "
            "ID (01 through 05). Returns full pattern definition: "
            "MITRE coverage + canonical detection shape (YAML) + "
            "why-it-works + false positives + reference rules from "
            "corpus + specialisations + severity guidance."
        ),
        mime_type="text/markdown",
    )
    def canonical_pattern_by_id(pattern_id: str) -> str:
        return canonical_pattern_by_id_body(pattern_id)
