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
DEMO = REPO_ROOT / "DEMO.md"

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


def count_windows_product(root: Path) -> int:
    """Rules whose ``logsource.product`` is ``windows``.

    Added after DEMO.md's "66 of the 100 corpus rules are ``product:
    windows``" went stale in both numbers at once: the corpus grew 101 ->
    222 and the windows share grew 66 -> 72, while the sentence kept
    saying 66 of 100. Nothing objected because DEMO.md sat outside this
    script's reach entirely -- see STAMP_TARGETS.

    ``product`` is nested under ``logsource:``, so unlike ``status:`` it is
    matched on the stripped line rather than the line start. Cross-checked
    against ``yaml.safe_load_all`` over the live corpus: both said 72.
    """
    total = 0
    for path in _rule_files(root):
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if (
                stripped.startswith("product:")
                and stripped.split(":", 1)[1].strip() == "windows"
            ):
                total += 1
                break
    return total


def count_correlation_rules(root: Path) -> int:
    """Rules carrying a sigma ``correlation:`` document.

    This is the number the Lucene-family backends cannot convert --
    pySigma's elastic/kibana/wazuh/opensearch backends reject correlation
    rules outright. Marked because README states it as a literal ("fail on
    the 10 correlation rules"), which is exactly the shape of claim that
    drifted everywhere else in this file's history. Cross-checked against
    ``yaml.safe_load_all``: both said 10.
    """
    total = 0
    for path in _rule_files(root):
        if any(
            line.startswith("correlation:")
            for line in path.read_text(encoding="utf-8").splitlines()
        ):
            total += 1
    return total


def count_lucene_convertible(root: Path) -> int:
    """Rules the Lucene-family targets convert = corpus minus correlations.

    Derived rather than measured, because this script installs nothing and
    a real conversion needs pySigma plus three backend packages. The
    derivation is not left as an assumption:
    ``tests/test_lucene_convert_claim.py`` runs the actual ``convert_rule``
    across all four Lucene targets and asserts the count equals this
    metric -- so a rule that fails for some *other* reason turns that test
    red instead of silently skewing the published number.
    """
    return count_rules(root) - count_correlation_rules(root)


# marker name -> resolver(root) -> scalar value. Mirrors a shared metric
# registry shape so the on-disk marker format stays byte-identical.
METRICS = {
    "sigma_rule_count": count_rules,
    "tactic_category_count": count_tactic_categories,
    "test_module_count": count_test_modules,
    "status_test_count": count_status_test,
    "status_experimental_count": count_status_experimental,
    "status_stable_count": count_status_stable,
    "windows_product_count": count_windows_product,
    "correlation_rule_count": count_correlation_rules,
    "lucene_convert_count": count_lucene_convertible,
}

# A shields badge cannot carry the HTML-comment markers above: a Markdown
# image URL has nowhere to put one. The value is located by its own regex
# instead, under the same contract — rewritten from ground truth, and
# `--check` fails on drift. The reason is this README's own record: every
# number in it that sat outside a marker had gone stale by the time anyone
# re-measured (the tactic-category count in three places, the code_review
# rule count, two dated measurements), while every marked one was correct.
# A badge is the one value the marker mechanism cannot reach, so it gets a
# rewriter of its own rather than an exemption.
BADGES = {
    "sigma_rule_count": re.compile(r"(img\.shields\.io/badge/sigma__rules-)(\d+)(-)"),
}

# Markers each stamped file MUST contain; an absence here is a warning.
# Every file is still rewritten for *every* known metric -- a stray marker
# gets updated wherever it sits. These sets only say which absences are
# worth reporting.
#
# DEMO.md joined the stamp because the *reach*, not the mechanism, was the
# defect. README's marked numbers stayed correct through the corpus going
# 101 -> 222; DEMO.md's prose kept saying "100 corpus rules", "66 of the
# 100" and "convert 90 of 100" because this script never opened it.
# Hand-editing those three numbers would have drifted a fourth time on the
# next batch.
_README_MARKERS = frozenset(
    {
        "sigma_rule_count",
        "tactic_category_count",
        "test_module_count",
        "status_test_count",
        "status_experimental_count",
        "status_stable_count",
        "correlation_rule_count",
    }
)
_DEMO_MARKERS = frozenset(
    {"sigma_rule_count", "windows_product_count", "lucene_convert_count"}
)


def _stamp_targets() -> dict[Path, tuple[frozenset[str], bool]]:
    """file -> (required markers, whether BADGES apply), resolved NOW.

    Deliberately a function, not a module-level dict. A dict built at import
    time freezes whatever ``README`` pointed at then, so a caller that
    redirects ``README`` (every test here does, via monkeypatch) would still
    have its writes land on the real repo file. That is not hypothetical: it
    happened while this multi-file support was being added, and the tmp
    corpus's counts were written into the real DEMO.md.

    DEMO is located NEXT TO ``README`` rather than off ``REPO_ROOT`` for the
    same reason -- the two must move together -- and is skipped when absent,
    so a caller pointing ``README`` at a scratch directory stamps only that.
    """
    targets: dict[Path, tuple[frozenset[str], bool]] = {
        README: (_README_MARKERS, True)
    }
    demo = README.parent / DEMO.name
    if demo.exists():
        targets[demo] = (_DEMO_MARKERS, False)
    return targets


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


def stamp_text(
    text: str,
    root: Path,
    *,
    expected: frozenset[str] | None = None,
    apply_badges: bool = True,
    label: str = "README",
) -> tuple[str, list[tuple[str, str, str]]]:
    """Return (rewritten_text, drift) where drift is a list of
    (marker_name, old_value, new_value) for blocks whose value was stale.

    Replaces *every* occurrence of each known marker block so multiple
    mentions in one file stay in sync. Pure function (no I/O) for testing.

    ``expected`` names the markers whose *absence* is worth a warning; every
    known metric is rewritten regardless. Default ``None`` warns on all of
    them, which is what a single-file caller wants. ``apply_badges`` and
    ``label`` exist for the same reason: DEMO.md carries three markers and no
    badge, so warning about the other five would be noise, and saying
    "not found in README" while reading DEMO.md would be a lie.
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
        if not regex.search(text) and (expected is None or name in expected):
            print(f"warning: marker {name!r} not found in {label}", file=sys.stderr)

    if apply_badges:
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
                print(
                    f"warning: badge for {name!r} not found in {label}", file=sys.stderr
                )

    return out, drift


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit 1 if any marker is out of date; do not write",
    )
    args = parser.parse_args(argv)

    targets = _stamp_targets()
    if not README.exists():
        print(f"error: {README} not found", file=sys.stderr)
        return 2

    summary = ", ".join(
        f"{name}={resolver(REPO_ROOT)}" for name, resolver in METRICS.items()
    )
    total_drift = 0
    wrote: list[str] = []

    for path, (expected, badges) in targets.items():
        original = _read(path)
        rewritten, drift = stamp_text(
            original,
            REPO_ROOT,
            expected=expected,
            apply_badges=badges,
            label=path.name,
        )
        total_drift += len(drift)

        if args.check:
            for name, old, new in drift:
                print(f"DRIFT {name}: {path.name} has {old!r}, ground truth is {new!r}")
            continue

        if rewritten != original:
            _write(path, rewritten)
            wrote.append(f"{path.name} ({len(drift)} block(s))")

    if args.check:
        if total_drift:
            print(f"{total_drift} marker(s) drifted — run `python readme_stamp.py`.")
            return 1
        print(f"metrics in sync ({summary}).")
        return 0

    if wrote:
        print(f"stamped {', '.join(wrote)}: {summary}")
    else:
        print(f"already in sync ({summary}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
