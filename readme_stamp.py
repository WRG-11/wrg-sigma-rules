#!/usr/bin/env python3
"""Self-stamp README ground-truth metrics for this repo (Track-B, FREE GHA).

Counts the published sigma rule corpus and rewrites the in-place
``<!-- METRIC:sigma_rule_count -->N<!-- /METRIC:sigma_rule_count -->`` marker
block(s) in README.md from ground truth.

Marker convention is reused verbatim from a companion WinstonRedGuard
README-metrics helper (reuse > reinvent) — the value
*between* the markers is replaced; surrounding Markdown is untouched, and a
re-run with no corpus change is a no-op.

stdlib-only, zero-dependency, copy-portable: drop this file at the root of any
public WRG-11 repo, adjust ``METRICS`` below, and wire the companion workflow
``.github/workflows/readme-stamp.yml``.

Usage:
    python readme_stamp.py            # rewrite README markers in place
    python readme_stamp.py --check    # CI gate: exit 1 if drift, do NOT write

CRLF note: README.md is read/written with ``newline=""`` so the file's existing
end-of-line bytes (CRLF here) are preserved exactly — only the marker value
changes, never the line endings (no whole-file diff churn).
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
README = REPO_ROOT / "README.md"

# Rule corpus = sigma YAML under resources/examples/<tactic>/, one directory
# per ATT&CK tactic category. The category count used to live in this comment
# as a literal and drifted (it read 11 while the corpus had 14); it is counted
# from disk now — see count_tactic_categories. resources/canonical-patterns/
# holds *.md narrative pattern docs (not rules) and is excluded.
RULE_GLOBS = (
    "resources/examples/**/*.yml",
    "resources/examples/**/*.yaml",
)


def count_rules(root: Path) -> int:
    """Number of distinct sigma rule files in the published corpus."""
    files: set[Path] = set()
    for pattern in RULE_GLOBS:
        files.update(root.glob(pattern))
    return len(files)


def count_tactic_categories(root: Path) -> int:
    """Number of tactic directories under resources/examples/.

    Added after the README's "N ATT&CK tactic categories" line drifted the
    same way the test-module count once did: `discovery` was added to the
    corpus and the TL;DR bullet, the section heading, the plugin manifest
    and this file's own comment all kept saying 13. Nothing was measuring
    it, so nothing objected.
    """
    examples = root / "resources" / "examples"
    return len(
        [
            p
            for p in examples.iterdir()
            if p.is_dir() and not p.name.startswith((".", "_"))
        ]
    )


def count_test_modules(root: Path) -> int:
    """Number of pytest test modules under tests/ (test_*.py files).

    Added after README's "8 Python test modules" claim drifted to a stale
    number (actual: 10) with nothing catching it -- sigma_rule_count was the
    only self-stamped metric.
    """
    return len(list((root / "tests").glob("test_*.py")))


def _rule_files(root: Path) -> set[Path]:
    files: set[Path] = set()
    for pattern in RULE_GLOBS:
        files.update(root.glob(pattern))
    return files


def _count_status(root: Path, wanted: str) -> int:
    """Rules whose sigma ``status:`` is *wanted*.

    Reads the LAST document of each file: in a base-rule + correlation-rule
    pairing the correlation document is the rule being published, matching
    how validate_rule and convert_rule pick their subject.

    Deliberately hand-rolled rather than importing yaml -- this script is
    documented as stdlib-only and copy-portable, and the stamp workflow
    installs nothing. `status:` is a top-level scalar on its own line, so a
    line match is sufficient and cannot be tripped by nesting.
    """
    total = 0
    for path in _rule_files(root):
        statuses = [
            line.split(":", 1)[1].strip()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.startswith("status:")
        ]
        if statuses and statuses[-1] == wanted:
            total += 1
    return total


def count_status_test(root: Path) -> int:
    return _count_status(root, "test")


def count_status_experimental(root: Path) -> int:
    return _count_status(root, "experimental")


def count_status_stable(root: Path) -> int:
    """Intentionally expected to be 0 -- see README "Rule status".

    Stamped anyway rather than hardcoded: if a rule is ever promoted, the
    README table should say so without anyone remembering to edit it.
    """
    return _count_status(root, "stable")


# marker name -> resolver(root) -> scalar value. Mirrors a shared metric
# registry shape so the on-disk marker format stays byte-identical.
METRICS = {
    "sigma_rule_count": count_rules,
    "tactic_category_count": count_tactic_categories,
    "test_module_count": count_test_modules,
    "status_test_count": count_status_test,
    "status_experimental_count": count_status_experimental,
    "status_stable_count": count_status_stable,
}

# A shields badge cannot carry the HTML-comment markers above: a Markdown
# image URL has nowhere to put one. The value is located by its own regex
# instead, under the same contract — rewritten from ground truth, and
# `--check` fails on drift. Without this the badge is a hand-typed number
# sitting next to auto-stamped ones, which is how the sibling profile README
# ended up with a correct sentence and a stale badge in the same file.
BADGES = {
    "sigma_rule_count": re.compile(r"(img\.shields\.io/badge/sigma__rules-)(\d+)(-)"),
}


def _read(path: Path) -> str:
    # newline="" → no EOL translation on read (CRLF preserved verbatim).
    with open(path, "r", encoding="utf-8", newline="") as fh:
        return fh.read()


def _write(path: Path, text: str) -> None:
    # newline="" → write the string's bytes as-is (CRLF preserved verbatim).
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


def _marker_re(name: str) -> re.Pattern[str]:
    esc = re.escape(name)
    return re.compile(
        r"<!-- METRIC:" + esc + r" -->(.*?)<!-- /METRIC:" + esc + r" -->",
        re.DOTALL,
    )


def stamp_text(text: str, root: Path) -> tuple[str, list[tuple[str, str, str]]]:
    """Return (rewritten_text, drift) where drift is a list of
    (marker_name, old_value, new_value) for blocks whose value was stale.

    Replaces *every* occurrence of each known marker block so multiple
    mentions in one README stay in sync. Pure function (no I/O) for testing.
    """
    drift: list[tuple[str, str, str]] = []
    out = text
    for name, resolver in METRICS.items():
        value = str(resolver(root))
        regex = _marker_re(name)

        def _repl(match: re.Match[str], _name: str = name, _value: str = value) -> str:
            old = match.group(1)
            if old != _value:
                drift.append((_name, old, _value))
            return f"<!-- METRIC:{_name} -->{_value}<!-- /METRIC:{_name} -->"

        out = regex.sub(_repl, out)
        if not regex.search(text):
            print(f"warning: marker {name!r} not found in README", file=sys.stderr)

    for name, regex in BADGES.items():
        value = str(METRICS[name](root))

        def _badge_repl(
            match: re.Match[str], _name: str = name, _value: str = value
        ) -> str:
            old = match.group(2)
            if old != _value:
                drift.append((f"{_name} (badge)", old, _value))
            return match.group(1) + _value + match.group(3)

        out = regex.sub(_badge_repl, out)
        if not regex.search(text):
            print(f"warning: badge for {name!r} not found in README", file=sys.stderr)

    return out, drift


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit 1 if any marker is out of date; do not write",
    )
    args = parser.parse_args(argv)

    if not README.exists():
        print(f"error: {README} not found", file=sys.stderr)
        return 2

    original = _read(README)
    rewritten, drift = stamp_text(original, REPO_ROOT)
    summary = ", ".join(f"{name}={resolver(REPO_ROOT)}" for name, resolver in METRICS.items())

    if args.check:
        if drift:
            for name, old, new in drift:
                print(f"DRIFT {name}: README has {old!r}, ground truth is {new!r}")
            print(f"{len(drift)} marker(s) drifted — run `python readme_stamp.py`.")
            return 1
        print(f"README metrics in sync ({summary}).")
        return 0

    if rewritten != original:
        _write(README, rewritten)
        print(f"stamped README: {summary} ({len(drift)} block(s) updated)")
    else:
        print(f"README already in sync ({summary}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
