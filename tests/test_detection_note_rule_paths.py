"""Every rule path a detection note names must exist.

No check tied the notes to the corpus: a renamed or merged rule left its note
pointing at a file that was gone, and every other test stayed green. Measured
2026-09-30 while merging 43 actor clones: 12 notes named 43 member paths.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NOTES = ROOT / "docs" / "detection-notes"
PATH = re.compile(r"resources/examples/[\w./-]+?\.yml")


def test_notes_name_at_least_one_rule() -> None:
    """Canary: the pattern must find paths, or the next test proves nothing."""
    assert any(PATH.search(note.read_text(encoding="utf-8")) for note in NOTES.glob("*.md"))


def test_every_rule_path_in_a_note_exists() -> None:
    missing = sorted(
        (note.name, match)
        for note in NOTES.glob("*.md")
        for match in PATH.findall(note.read_text(encoding="utf-8"))
        if not (ROOT / match).is_file()
    )
    assert missing == [], missing[:10]
