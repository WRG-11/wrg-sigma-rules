#!/usr/bin/env python3
"""detection_note_gap.py -- advisory report of observed_* rules with no
companion detection-note, ranked and grouped for whoever writes the next one.

CONTRIBUTING.md's sourcing bar requires a rule that claims to detect
something observed in the wild to be traceable to a source someone can
check. A detection-note (docs/detection-notes/) makes that traceability
readable by a human before they deploy the rule -- but nothing tracks which
observed_* rules still lack one, so the gap has been closed by whoever
happened to look (1 of 278 rules, before the 2026-09 batch).

This script does not write notes and does not judge whether a rule NEEDS
one -- it is advisory, same spirit as duplicate_rule_check.py. What it does:

1. Scans docs/detection-notes/*.md for `resources/examples/....yml` paths
   (matched by path shape, not by a specific comment-block format, so it
   survives the note-writer using a single "Accuracy source:" line or a
   multi-file "covering N sibling rules" list -- both forms exist in this
   corpus already).
2. Scans resources/examples/observed_*.yml for a CVSS score in the
   description (best-effort regex; a rule with no CVSS mention is NOT
   assumed low-priority -- it lands in its own "unscored" bucket instead of
   being silently sorted to the bottom, so this tool does not repeat the
   mistake it exists to avoid: a rule this regex cannot score is a rule
   this regex could not measure, not a rule with nothing worth scoring).
3. Classifies each reference URL by source type, so whoever picks up a gap
   knows which tool reaches it (`gh api .../security-advisories/<id>` for a
   GHSA URL, WebFetch for anything else) before they start.
4. Clusters uncovered rules sharing a filename vendor/product prefix (the
   same grouping this corpus's own descriptions already do by hand --
   "sibling rule" cross-references), since a coordinated disclosure series
   is more efficiently covered by one note than N near-duplicates.

Usage:
    python scripts/detection_note_gap.py                # human-readable report
    python scripts/detection_note_gap.py --json out.json # + machine-readable queue
    python scripts/detection_note_gap.py --min-cvss 7.0  # filter the report
"""
from __future__ import annotations

from urllib.parse import urlsplit

import argparse
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLES_DIR = REPO_ROOT / "resources" / "examples"
NOTES_DIR = REPO_ROOT / "docs" / "detection-notes"

_CVSS_RE = re.compile(r"CVSS\s*(?:v?3\.1|v?4\.0)?\s*(\d{1,2}\.\d)", re.IGNORECASE)
_RULE_PATH_RE = re.compile(r"resources/examples/[A-Za-z0-9_./-]+\.ya?ml")
_REFERENCES_BLOCK_RE = re.compile(
    r"^references:\n((?:^- .+\n)+)", re.MULTILINE
)
_VENDOR_PREFIX_RE = re.compile(r"^observed_([a-z0-9]+(?:_[a-z0-9]+)?)_")


def _source_kind(url: str) -> str:
    """Classify a reference URL by which tool reaches it fastest.

    Order matters: a GHSA path is checked before the bare-github fallback,
    since every GHSA URL is also a github.com URL.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return "other (WebFetch)"
    host = (parts.hostname or "").lower()
    path = parts.path or ""

    def _is_host(domain: str) -> bool:
        """Exact domain or a subdomain of it -- NOT a substring.

        `"github.com" in url` is not a host check: `evil.com/?x=github.com`
        passes it too. CodeQL flagged that shape seven times as
        `py/incomplete-url-substring-sanitization`, and it was right. No
        security decision is made here (this is a classifier), but a wrong
        classification is still wrong: that URL is not GitHub.
        """
        return host == domain or host.endswith("." + domain)

    if _is_host("github.com"):
        if "/security/advisories/GHSA-" in path:
            return "ghsa (gh api repos/<owner>/<repo>/security-advisories/<id>)"
        if "/issues/" in path:
            return "github_issue (gh api repos/<owner>/<repo>/issues/<n>)"
        if "/commit" in path:
            return "github_commit (gh api repos/<owner>/<repo>/commits/<sha>)"
        return "github_other (gh api or gh api contents)"
    if _is_host("vulncheck.com"):
        return "vulncheck (WebFetch; observed timeouts -- retry before giving up)"
    if _is_host("kb.cert.org"):
        return "cert_cc (WebFetch)"
    if _is_host("attack.mitre.org"):
        return "mitre_attack (background only, not a primary source)"
    return "other (WebFetch)"


@dataclass
class RuleGap:
    relpath: str
    title: str
    cvss: float | None
    references: list[str] = field(default_factory=list)

    @property
    def vendor_prefix(self) -> str | None:
        m = _VENDOR_PREFIX_RE.match(Path(self.relpath).name)
        return m.group(1) if m else None


def _covered_relpaths() -> set[str]:
    """Every resources/examples/....yml path mentioned in any existing note.

    Path-shape matching rather than parsing a specific frontmatter field:
    this corpus already has two note shapes (gogs: single "Accuracy source:"
    line; the sglang cluster note: a bulleted list of N sibling paths in the
    header comment) and a third writer will invent a third shape. The
    regex survives all of them because it does not care about the
    surrounding prose, only the path string itself.
    """
    covered: set[str] = set()
    if not NOTES_DIR.is_dir():
        return covered
    for note in NOTES_DIR.glob("*.md"):
        text = note.read_text(encoding="utf-8")
        covered.update(_RULE_PATH_RE.findall(text))
    return covered


def _parse_rule(path: Path) -> RuleGap:
    text = path.read_text(encoding="utf-8")
    relpath = "resources/examples/" + path.relative_to(EXAMPLES_DIR).as_posix()

    title_match = re.search(r"^title:\s*(.+)$", text, re.MULTILINE)
    title = title_match.group(1).strip() if title_match else path.stem

    cvss_match = _CVSS_RE.search(text)
    cvss = float(cvss_match.group(1)) if cvss_match else None

    refs: list[str] = []
    refs_match = _REFERENCES_BLOCK_RE.search(text)
    if refs_match:
        refs = [
            line[2:].strip()
            for line in refs_match.group(1).splitlines()
            if line.startswith("- ")
        ]

    return RuleGap(relpath=relpath, title=title, cvss=cvss, references=refs)


def find_gaps(min_cvss: float | None = None) -> tuple[list[RuleGap], list[RuleGap]]:
    """Return (scored_gaps_desc, unscored_gaps) -- both EXCLUDING covered rules.

    Never merges the two lists and never sorts unscored rules to the bottom
    of the scored list: doing so would silently claim "lowest priority" for
    rules this tool actually failed to measure, not rules that scored low.
    """
    covered = _covered_relpaths()
    scored: list[RuleGap] = []
    unscored: list[RuleGap] = []

    for path in sorted(EXAMPLES_DIR.rglob("observed_*.yml")):
        gap = _parse_rule(path)
        if gap.relpath in covered:
            continue
        if gap.cvss is not None:
            if min_cvss is not None and gap.cvss < min_cvss:
                continue
            scored.append(gap)
        else:
            if min_cvss is not None:
                continue  # a CVSS filter is explicitly not asking for unscored rules
            unscored.append(gap)

    scored.sort(key=lambda g: g.cvss or 0.0, reverse=True)
    return scored, unscored


def cluster_by_vendor(gaps: list[RuleGap]) -> dict[str, list[RuleGap]]:
    """Group gaps sharing a filename vendor/product prefix, 2+ members only.

    A cluster is a hint, not a verdict -- CONTRIBUTING.md's "more rules is
    not the goal" sibling for notes: a coordinated disclosure series (this
    corpus's own sglang_2026_08 batch) is usually one note away, not N.
    """
    groups: dict[str, list[RuleGap]] = defaultdict(list)
    for gap in gaps:
        prefix = gap.vendor_prefix
        if prefix:
            groups[prefix].append(gap)
    return {k: v for k, v in sorted(groups.items()) if len(v) >= 2}


def _print_report(
    scored: list[RuleGap], unscored: list[RuleGap], clusters: dict[str, list[RuleGap]]
) -> None:
    print(f"[detection-note-gap] {len(scored)} scored + {len(unscored)} unscored "
          f"observed_* rule(s) with no companion note")
    print()
    if scored:
        print("-- by CVSS, descending --")
        for g in scored:
            print(f"  CVSS {g.cvss:4.1f}  {g.relpath}")
            print(f"           {g.title}")
    if unscored:
        print()
        print(f"-- unscored ({len(unscored)}; NOT low-priority, just unmeasured "
              "by this regex -- likely actor/campaign-bound rules without a CVE) --")
        for g in unscored:
            print(f"  {g.relpath}")
    if clusters:
        print()
        print("-- vendor clusters (2+ uncovered rules, same prefix; consider "
              "one combined note) --")
        for prefix, members in clusters.items():
            print(f"  {prefix}: {len(members)} rule(s)")
            for g in members:
                print(f"    - {g.relpath}")


def _to_json(
    scored: list[RuleGap], unscored: list[RuleGap], clusters: dict[str, list[RuleGap]]
) -> dict[str, Any]:
    def _dump(g: RuleGap) -> dict[str, Any]:
        return {
            "relpath": g.relpath,
            "title": g.title,
            "cvss": g.cvss,
            "references": [
                {"url": u, "source_kind": _source_kind(u)} for u in g.references
            ],
        }

    return {
        "scored": [_dump(g) for g in scored],
        "unscored": [_dump(g) for g in unscored],
        "clusters": {
            prefix: [g.relpath for g in members]
            for prefix, members in clusters.items()
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--json", metavar="PATH", default=None,
                        help="write the full queue as JSON instead of only printing")
    parser.add_argument("--min-cvss", type=float, default=None,
                        help="only report scored rules at or above this CVSS "
                             "(excludes unscored rules from the report entirely)")
    args = parser.parse_args(argv)

    if not EXAMPLES_DIR.is_dir():
        print(f"[detection-note-gap] ERROR: {EXAMPLES_DIR} not found -- "
              "run from the repo root", file=sys.stderr)
        return 2

    scored, unscored = find_gaps(min_cvss=args.min_cvss)
    clusters = cluster_by_vendor(scored + unscored)

    _print_report(scored, unscored, clusters)

    if args.json:
        Path(args.json).write_text(
            json.dumps(_to_json(scored, unscored, clusters), indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"\n[detection-note-gap] wrote {args.json}")

    return 0  # advisory: never fails a build


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
