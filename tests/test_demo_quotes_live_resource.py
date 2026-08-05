"""DEMO.md quotes the coverage resource verbatim, so it must still match it.

`DEMO.md` presents a fenced block as what reading
``wrg-sigma://coverage/mitre-attack-matrix`` returns. Its prose even says the
resource "cannot go stale against the rules" -- true of the resource, and not
true of a quotation of it. Four of the five numbers in that block were stale:
34 incident rules were quoted as 24, 66 pattern rules as 56, 78 techniques as
66, and 14 tactic groupings as 13. Each had been incremented by hand when the
corpus grew instead of being read back off the resource.

A quoted output is a claim about what a command prints. This module runs the
command and compares.

stdlib + pytest only; no network.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tools" / "resources"))

import coverage_resource as cr  # noqa: E402

DEMO = REPO_ROOT / "DEMO.md"
HEADING = "## Summary"


def summary_lines(text: str) -> list[str]:
    """The `## Summary` heading and the bullet block under it, blanks dropped."""
    lines = text.splitlines()
    try:
        start = next(i for i, line in enumerate(lines) if line.strip() == HEADING)
    except StopIteration:
        return []
    out = [lines[start].strip()]
    for line in lines[start + 1:]:
        stripped = line.strip()
        if not stripped:
            continue
        if not stripped.startswith("- "):
            break
        out.append(stripped)
    return out


# --- extractor behaviour --------------------------------------------------


def test_summary_lines_stops_at_the_first_non_bullet() -> None:
    text = "## Summary\n\n- a: 1\n- b: 2\n\nprose here\n- not part of it\n"
    assert summary_lines(text) == ["## Summary", "- a: 1", "- b: 2"]


def test_summary_lines_skips_blank_lines_inside_the_block() -> None:
    text = "## Summary\n- a: 1\n\n- b: 2\nprose\n"
    assert summary_lines(text) == ["## Summary", "- a: 1", "- b: 2"]


def test_summary_lines_is_empty_without_the_heading() -> None:
    assert summary_lines("# Other\n\n- a: 1\n") == []


# --- the gate -------------------------------------------------------------


def test_demo_summary_block_is_present() -> None:
    assert summary_lines(DEMO.read_text(encoding="utf-8")), (
        f"DEMO.md has no '{HEADING}' block to check"
    )


def test_demo_summary_matches_the_live_resource() -> None:
    """The gate: what DEMO shows must be what the resource actually returns."""
    quoted = summary_lines(DEMO.read_text(encoding="utf-8"))
    live = summary_lines(cr.coverage_matrix_body())
    assert live, "coverage_matrix_body() produced no Summary block"
    assert quoted == live, (
        "DEMO.md's quoted coverage summary has drifted from the resource.\n"
        f"  quoted: {quoted}\n"
        f"  live  : {live}\n"
        "Read the numbers back off the resource; do not increment them."
    )
