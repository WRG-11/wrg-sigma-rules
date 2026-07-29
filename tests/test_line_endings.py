"""Guard: no tracked text file is stored with CRLF line endings.

Six rule files were stored with CRLF while the rest of the corpus used LF.
Nothing surfaced it until a bulk edit rewrote them, and those six then produced
whole-file diffs that buried the real change -- a reviewer reading the diff
would have seen 50 changed lines per file instead of the two that mattered.

`.gitattributes` now normalises on the way in. This test is the check that it
keeps working, because a misconfigured client can still commit CRLF and the
next person would only find out the same way: through a diff that hides its
own content.

Reads the committed blob (`git show HEAD:<path>`), not the working tree --
the working tree may legitimately hold CRLF on Windows while the repository
stores LF, and it is the stored form that matters.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

_PLUGIN_ROOT = Path(__file__).resolve().parent.parent

# Extensions git treats as text here (mirrors .gitattributes).
_TEXT_SUFFIXES = {
    ".yml", ".yaml", ".py", ".md", ".json", ".txt", ".cfg", ".toml", ".rc",
}


def _git(*args: str) -> str:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=_PLUGIN_ROOT,
            capture_output=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("git not available / not a work tree -- EOL sweep skipped")
    return result.stdout.decode("utf-8", errors="replace")


def _index_eol() -> list[tuple[str, str]]:
    """Return (index_eol, path) for every tracked text file.

    `git ls-files --eol` reports this for the whole tree in one call. The
    first draft of this test ran `git show HEAD:<path>` per file, which was
    correct but took 20 seconds and would have been a standing tax on every
    suite run.
    """
    rows: list[tuple[str, str]] = []
    for line in _git("ls-files", "--eol").splitlines():
        if not line.strip():
            continue
        # Format: "i/lf    w/crlf  attr/text=auto eol=lf\tpath"
        fields, _, path = line.partition("\t")
        if not path or Path(path).suffix.lower() not in _TEXT_SUFFIXES:
            continue
        index_eol = next(
            (f.split("/", 1)[1] for f in fields.split() if f.startswith("i/")),
            "",
        )
        rows.append((index_eol, path))
    return rows


def test_no_tracked_text_file_is_stored_with_crlf() -> None:
    # "i/crlf" is stored CRLF; "i/mixed" is worse. "i/none" means no line
    # endings at all (single-line or empty file), which is fine.
    offenders = [
        path for index_eol, path in _index_eol() if index_eol in {"crlf", "mixed"}
    ]

    assert not offenders, (
        f"{len(offenders)} tracked file(s) stored with CRLF. A bulk edit will "
        "rewrite these whole and bury the real change in the diff. Normalise "
        "them to LF:\n  " + "\n  ".join(offenders)
    )


def test_gitattributes_pins_lf() -> None:
    """The guard above only stays true because something enforces it."""
    attributes = (_PLUGIN_ROOT / ".gitattributes").read_text(encoding="utf-8")
    assert "text=auto eol=lf" in attributes
