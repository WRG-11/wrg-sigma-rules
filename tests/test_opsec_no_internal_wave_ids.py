"""OPSEC guard: no internal wave-dispatch identifiers in public tracked content.

WinstonRedGuard's internal multi-agent workflow tags each unit of work with a
wave-dispatch identifier of the form ``R<round>-<wave><agent-letter>`` (a capital
R, digits, a dash, digits, and an optional lowercase agent letter). These encode
internal fleet topology and must never ship in this public repo.

They have leaked three times as corpus-migration provenance comments/docstrings,
each caught *after* it was already public by a post-hoc opsec scan. This test
closes that gap: one ``git ls-files`` sweep fails the suite -- hence CI, hence the
merge -- the moment such an id reappears in tracked content, before it goes public.

To grant a legitimate exception, add the offending path to ``_ALLOWLIST`` with a
comment explaining why. Do not weaken the pattern.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

_PLUGIN_ROOT = Path(__file__).resolve().parent.parent

# Internal fleet wave-dispatch id: R<round>-<wave><agent?>. IGNORECASE catches a
# lowercased leak too; verified zero false-positives against the current corpus.
_WAVE_ID_RE = re.compile(r"R\d+-\d+[a-z]?", re.IGNORECASE)

# Paths permitted to contain the pattern (documented exceptions only).
#
# gitlab_mcp_server rule: the GHSA advisory id it cites (see that file's
# `references:` block -- an external, real GitHub Security Advisory id,
# not written out again here to avoid re-tripping this same regex inside
# this comment) contains a short digit-dash-digit-letter run that
# coincidentally matches R\d+-\d+[a-z]? -- not an internal wave-dispatch
# id. Confirmed: every match in that file resolves to a substring of that
# one external id, quoted verbatim from the advisory URL.
_ALLOWLIST: frozenset[str] = frozenset(
    {
        "resources/examples/initial_access/observed_gitlab_mcp_server_unauth_pat_abuse_t1190.yml",
    }
)


def _tracked_files() -> list[str]:
    try:
        result = subprocess.run(
            ["git", "ls-files"],
            cwd=_PLUGIN_ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("git not available / not a git work tree -- opsec sweep skipped")
    return [line for line in result.stdout.splitlines() if line]


def test_no_internal_wave_dispatch_ids_in_tracked_content() -> None:
    """Fail if any internal wave-dispatch id leaked into public tracked content."""
    offenders: list[str] = []
    for rel in _tracked_files():
        if rel in _ALLOWLIST:
            continue
        try:
            text = (_PLUGIN_ROOT / rel).read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue  # binary / unreadable -- not prose, nothing to leak
        for match in _WAVE_ID_RE.finditer(text):
            line_no = text.count("\n", 0, match.start()) + 1
            offenders.append(f"{rel}:{line_no}: {match.group(0)}")

    assert not offenders, (
        "Internal wave-dispatch id(s) leaked into public tracked content. "
        "Genericize them before publishing (drop the id, keep the meaning):\n  "
        + "\n  ".join(offenders)
    )
