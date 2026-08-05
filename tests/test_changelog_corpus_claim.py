"""The newest CHANGELOG section's corpus claim must match the real corpus.

README's rule count is CI-gated by ``readme_stamp.py --check`` and has never
drifted. CHANGELOG carried no guard at all, and two sections shipped a wrong
number before anyone read them: ``[1.3.0]`` claimed "73 -> 76" while the tag it
names actually ships 80 rules, and the section written for the 100-rule corpus
claimed "76 -> 100" by continuing that stale 76. Both numbers were internally
consistent with the document and wrong against the repository.

Two invariants are checkable from the working tree, and neither is redundant:

1. The *newest* section's terminal count must equal the real corpus. A
   released count is a measurement, so it gets measured.
2. Each section's start count must equal the next-older section's end count.
   The chain has no gaps, so editing one end of a range and not the other is
   caught at the seam.

Scope, stated rather than implied: invariant 2 would NOT have caught the
original defect, because "73 -> 76" and "76 -> 100" agreed with each other --
both were wrong together. Catching *that* requires asking what the tag
actually shipped, which needs git history; CI checks out at ``fetch-depth: 1``
with no tags, so such a test would skip in CI and gate nothing. It is
deliberately not written here rather than written and inert.

Historical sections' terminal counts are likewise NOT re-checked against HEAD:
they describe past states, and doing so would demand rewriting released
history on every corpus change.

stdlib + pytest only; no network. Live-repo assertions read committed files.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import readme_stamp as rs  # noqa: E402

CHANGELOG = Path(rs.REPO_ROOT) / "CHANGELOG.md"

_HEADING = re.compile(r"^## \[(?P<ver>[^\]]+)\]", re.MULTILINE)
# The arrow is written as U+2192 in this file; accept ASCII "->" too so a
# future editor's autocorrect cannot silently disable the gate.
_CLAIM = re.compile(
    r"Corpus\s+(?P<frm>\d+)\s*(?:→|->)\s*(?P<to>\d+)\s+rules",
    re.IGNORECASE,
)


def newest_section(text: str) -> tuple[str, str] | None:
    """Return (version, body) of the topmost ``## [version]`` section."""
    first = _HEADING.search(text)
    if first is None:
        return None
    nxt = _HEADING.search(text, first.end())
    body = text[first.end(): nxt.start() if nxt else len(text)]
    return first.group("ver"), body


def corpus_claim(body: str) -> tuple[int, int] | None:
    """Return (from, to) of the section's ``Corpus A -> B rules`` claim."""
    m = _CLAIM.search(body)
    return (int(m.group("frm")), int(m.group("to"))) if m else None


# --- parser behaviour -----------------------------------------------------


def test_newest_section_is_the_topmost_one() -> None:
    text = "# Changelog\n\n## [2.0.0] - x\n\nCorpus 1 → 2 rules\n\n## [1.0.0] - y\n\nCorpus 0 → 1 rules\n"
    ver, body = newest_section(text)
    assert ver == "2.0.0"
    assert corpus_claim(body) == (1, 2)


def test_older_section_body_does_not_leak_into_the_newest() -> None:
    """A section with no claim must read as None, not borrow the next one's."""
    text = "## [2.0.0] - x\n\nNo corpus line here.\n\n## [1.0.0] - y\n\nCorpus 3 → 9 rules\n"
    _, body = newest_section(text)
    assert corpus_claim(body) is None


def test_ascii_arrow_is_accepted() -> None:
    assert corpus_claim("Corpus 80 -> 100 rules") == (80, 100)


def test_unicode_arrow_is_accepted() -> None:
    assert corpus_claim("Corpus 80 → 100 rules") == (80, 100)


def test_no_heading_reads_as_none() -> None:
    assert newest_section("# Changelog\n\nnothing here\n") is None


# --- the gate -------------------------------------------------------------


def test_changelog_has_a_parseable_newest_section() -> None:
    section = newest_section(CHANGELOG.read_text(encoding="utf-8"))
    assert section is not None, "CHANGELOG.md has no '## [version]' heading"


def test_newest_section_corpus_claim_matches_ground_truth() -> None:
    """The gate. A released count is a measurement, so it must be measured."""
    ver, body = newest_section(CHANGELOG.read_text(encoding="utf-8"))
    claim = corpus_claim(body)
    assert claim is not None, f"section [{ver}] states no 'Corpus A -> B rules' count"
    _, claimed = claim
    actual = rs.count_rules(rs.REPO_ROOT)
    assert claimed == actual, (
        f"CHANGELOG section [{ver}] claims {claimed} rules; the corpus has "
        f"{actual}. Re-measure the number, do not search-replace it."
    )


def test_section_chain_has_no_gap() -> None:
    """Each section starts where the next-older one ended.

    This is what catches a half-edit: bumping one section's end count and
    leaving the following section's start count behind shows up at the seam.
    """
    text = CHANGELOG.read_text(encoding="utf-8")
    sections = [
        (m.group("ver"), text[m.end(): n.start() if n else len(text)])
        for m, n in zip(
            list(_HEADING.finditer(text)),
            list(_HEADING.finditer(text))[1:] + [None],
        )
    ]
    claims = [(v, corpus_claim(b)) for v, b in sections]
    claims = [(v, c) for v, c in claims if c is not None]
    assert len(claims) >= 2, "need two counted sections to check the chain"

    for (newer_v, (newer_frm, _)), (older_v, (_, older_to)) in zip(claims, claims[1:]):
        assert newer_frm == older_to, (
            f"[{newer_v}] starts at {newer_frm} but [{older_v}] ended at "
            f"{older_to} -- one end of a range was edited without the other"
        )


def test_chain_check_flags_a_seam_mismatch() -> None:
    """The chain assertion above is only worth its line if a gap fails it."""
    text = (
        "## [2.0.0] - x\n\nCorpus 76 → 100 rules\n\n"
        "## [1.0.0] - y\n\nCorpus 73 → 80 rules\n"
    )
    sections = [
        (m.group("ver"), text[m.end(): n.start() if n else len(text)])
        for m, n in zip(
            list(_HEADING.finditer(text)),
            list(_HEADING.finditer(text))[1:] + [None],
        )
    ]
    claims = [(v, corpus_claim(b)) for v, b in sections]
    (_, (newer_frm, _)), (_, (_, older_to)) = claims
    assert newer_frm != older_to, "fixture must contain the gap it is testing"


def test_claim_start_is_not_above_its_end() -> None:
    """A backwards range means someone edited one end of it only."""
    ver, body = newest_section(CHANGELOG.read_text(encoding="utf-8"))
    claim = corpus_claim(body)
    if claim is None:  # covered by the test above
        pytest.skip("no corpus claim in the newest section")
    frm, to = claim
    assert frm <= to, f"section [{ver}] claims a shrinking corpus: {frm} -> {to}"
