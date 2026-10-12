"""The README's links must point at something.

The per-client install steps live in ``docs/install.md`` and the README links
to them. A link is the only thing holding the two together: rename the file or
reword a heading it points at and the README sends readers nowhere while every
other test stays green.

What this checks: every relative link in ``README.md`` and in the Markdown
files directly under ``docs/`` resolves to a file in the repository, and where
such a link carries a ``#fragment`` into a Markdown file (or into its own
page), that file has a heading with that anchor.

What it does not check: external URLs, and the notes under
``docs/detection-notes/`` and ``docs/source-reviews/``.

stdlib + pytest only; no network.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Every "](target)": a badge is a link around an image, so matching the bracketed
# text as well would skip the outer target and check only the image URL.
_LINK = re.compile(r"\]\(([^)\s]+)\)")
_FENCE = re.compile(r"^```.*?^```", re.S | re.M)
_SCHEME = re.compile(r"[a-z][a-z0-9+.-]*:")


def _prose(path: Path) -> str:
    """The file without its fenced code blocks: a link inside one is sample text."""
    return _FENCE.sub("", path.read_text(encoding="utf-8"))


def _slug(heading: str) -> str:
    """GitHub's heading anchor: lower-case, punctuation dropped, spaces to hyphens."""
    return re.sub(r"[^\w\- ]", "", heading.strip().lower()).replace(" ", "-")


def _anchors(path: Path) -> set[str]:
    return {_slug(h) for h in re.findall(r"^#{1,6} +(.+?) *$", _prose(path), re.M)}


def _sources() -> list[Path]:
    return [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md"))]


def broken_links(sources: list[Path]) -> tuple[int, list[str]]:
    """Return (relative links checked, problems found)."""
    checked, problems = 0, []
    for source in sources:
        for target in _LINK.findall(_prose(source)):
            if _SCHEME.match(target):
                continue
            checked += 1
            rel, _, fragment = target.partition("#")
            dest = (source.parent / rel) if rel else source
            name = source.relative_to(ROOT).as_posix()
            if not dest.exists():
                problems.append(f"{name}: {target} does not exist")
            elif fragment and dest.suffix == ".md" and fragment not in _anchors(dest):
                problems.append(f"{name}: {target} names no heading in {dest.name}")
    return checked, problems


def test_slug_matches_the_anchor_the_readme_already_uses() -> None:
    """The double hyphen in a heading survives as hyphens, as GitHub renders it."""
    assert _slug("Demo 5 -- correlation rules") == "demo-5----correlation-rules"


def test_a_missing_file_and_a_missing_heading_are_both_reported(tmp_path: Path, monkeypatch) -> None:
    """The checker must be able to fail: one link of each broken kind."""
    page = tmp_path / "page.md"
    other = tmp_path / "other.md"
    other.write_text("# Other\n\n## Real heading\n", encoding="utf-8")
    page.write_text(
        "[ok](other.md#real-heading) [gone](missing.md) [stale](other.md#old-heading)\n"
        "```\n[sample](not-checked.md)\n```\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(sys.modules[__name__], "ROOT", tmp_path)
    checked, problems = broken_links([page])
    assert checked == 3
    assert len(problems) == 2, problems


def test_readme_and_docs_links_resolve() -> None:
    sources = _sources()
    assert len(sources) > 1, "docs/ holds no Markdown, so nothing there was checked"
    checked, problems = broken_links(sources)
    assert checked >= 10, f"only {checked} relative links found; the pattern may have stopped matching"
    assert problems == []
