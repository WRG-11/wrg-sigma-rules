"""Unit tests for readme_stamp.py (README self-stamp).

stdlib + pytest only; no network, no repo mutation (pure-function + tmp_path).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import readme_stamp as rs  # noqa: E402

MARKER = "<!-- METRIC:sigma_rule_count -->{}<!-- /METRIC:sigma_rule_count -->"


def _make_corpus(root: Path, n: int) -> None:
    """Create n synthetic rule .yml files under resources/examples/<tactic>/."""
    d = root / "resources" / "examples" / "execution"
    d.mkdir(parents=True, exist_ok=True)
    for i in range(n):
        (d / f"rule_{i}.yml").write_text("title: synthetic\n", encoding="utf-8")


# --- count_rules ----------------------------------------------------------

def test_count_rules_counts_yml(tmp_path: Path) -> None:
    _make_corpus(tmp_path, 5)
    assert rs.count_rules(tmp_path) == 5


def test_count_rules_ignores_md_and_canonical_patterns(tmp_path: Path) -> None:
    _make_corpus(tmp_path, 3)
    cp = tmp_path / "resources" / "canonical-patterns"
    cp.mkdir(parents=True)
    (cp / "01-pattern.md").write_text("# narrative doc, not a rule\n", encoding="utf-8")
    (tmp_path / "resources" / "examples" / "execution" / "NOTES.md").write_text("x", encoding="utf-8")
    assert rs.count_rules(tmp_path) == 3  # .md never counted


def test_count_rules_zero_when_empty(tmp_path: Path) -> None:
    assert rs.count_rules(tmp_path) == 0


# --- stamp_text (pure) ----------------------------------------------------

def test_stamp_text_updates_stale_marker(tmp_path: Path) -> None:
    _make_corpus(tmp_path, 7)
    text = f"corpus: {MARKER.format(3)} rules"
    out, drift = rs.stamp_text(text, tmp_path)
    assert MARKER.format(7) in out
    assert drift == [("sigma_rule_count", "3", "7")]


def test_stamp_text_idempotent_when_in_sync(tmp_path: Path) -> None:
    _make_corpus(tmp_path, 7)
    text = f"x {MARKER.format(7)} y"
    out, drift = rs.stamp_text(text, tmp_path)
    assert out == text
    assert drift == []


def test_stamp_text_updates_all_occurrences(tmp_path: Path) -> None:
    _make_corpus(tmp_path, 9)
    text = f"a {MARKER.format(1)} b {MARKER.format(1)} c {MARKER.format(1)}"
    out, drift = rs.stamp_text(text, tmp_path)
    assert out.count("-->9<!-- /METRIC:sigma_rule_count -->") == 3
    assert len(drift) == 3


def test_stamp_text_preserves_crlf(tmp_path: Path) -> None:
    _make_corpus(tmp_path, 4)
    text = f"line1\r\nrules {MARKER.format(2)} x\r\nline3\r\n"
    out, _ = rs.stamp_text(text, tmp_path)
    assert MARKER.format(4) in out
    assert out.count("\r\n") == text.count("\r\n")  # no EOL added/removed
    assert "\n" not in out.replace("\r\n", "")       # no lone LF introduced


# --- live repo integration ------------------------------------------------

def test_real_repo_corpus_countable(tmp_path: Path) -> None:
    # The live repo's published corpus must be a positive count (sanity);
    # deliberately NOT a hard-coded number — that would itself be drift-prone.
    assert rs.count_rules(rs.REPO_ROOT) > 0


def test_real_readme_markers_in_sync() -> None:
    # After wiring, the committed README's marker value must equal ground truth
    # (this is exactly what `readme_stamp.py --check` enforces in CI).
    text = rs._read(rs.README)
    _, drift = rs.stamp_text(text, rs.REPO_ROOT)
    assert drift == [], f"README markers out of sync with corpus: {drift}"


# --- count_test_modules -----------------------------------------------------

def test_count_test_modules_counts_test_prefixed_files(tmp_path: Path) -> None:
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    for name in ("test_a.py", "test_b.py", "conftest.py", "helpers.py"):
        (tests_dir / name).write_text("", encoding="utf-8")
    assert rs.count_test_modules(tmp_path) == 2


def test_count_test_modules_matches_real_repo_tests_dir() -> None:
    # Deliberately not hard-coded -- would itself be the exact drift this
    # metric exists to prevent.
    real_count = len(list((rs.REPO_ROOT / "tests").glob("test_*.py")))
    assert rs.count_test_modules(rs.REPO_ROOT) == real_count
    assert real_count > 0
