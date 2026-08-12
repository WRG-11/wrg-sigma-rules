"""Unit tests for readme_stamp.py (README self-stamp).

stdlib + pytest only; no network, no repo mutation (pure-function + tmp_path).
"""
from __future__ import annotations

import sys

import pytest
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


def _write_rule(path: Path, status: str, name: str = "r") -> None:
    path.write_text(
        f"title: {name}\nid: x\nstatus: {status}\n"
        "logsource:\n  category: process_creation\n"
        "detection:\n  selection: {a: 1}\n  condition: selection\n"
        "level: low\n",
        encoding="utf-8",
    )


def test_count_status_counts_each_status(tmp_path: Path) -> None:
    corpus = tmp_path / "resources" / "examples" / "execution"
    corpus.mkdir(parents=True)
    _write_rule(corpus / "a.yml", "test")
    _write_rule(corpus / "b.yml", "experimental")
    _write_rule(corpus / "c.yml", "experimental")
    assert rs.count_status_test(tmp_path) == 1
    assert rs.count_status_experimental(tmp_path) == 2
    assert rs.count_status_stable(tmp_path) == 0


def test_count_status_reads_the_last_document(tmp_path: Path) -> None:
    """In a base-rule + correlation-rule pair the published rule is the last
    document, matching how validate_rule and convert_rule pick their subject.
    Reading the first would report the base rule's status instead.
    """
    corpus = tmp_path / "resources" / "examples" / "credential_access"
    corpus.mkdir(parents=True)
    (corpus / "pair.yml").write_text(
        "title: base\nname: base_rule\nstatus: experimental\n"
        "logsource:\n  product: windows\n"
        "detection:\n  selection: {EventID: 4625}\n  condition: selection\n"
        "level: informational\n"
        "---\n"
        "title: correlation\nstatus: test\n"
        "correlation:\n  type: event_count\n  rules:\n    - base_rule\n"
        "  group-by:\n    - IpAddress\n  timespan: 10m\n  condition:\n    gt: 5\n"
        "level: high\n",
        encoding="utf-8",
    )
    assert rs.count_status_test(tmp_path) == 1
    assert rs.count_status_experimental(tmp_path) == 0


def test_status_counts_match_a_yaml_parse_of_the_real_corpus() -> None:
    """The stamper is deliberately stdlib-only and matches `status:` by line.
    Cross-check it against an actual YAML parse so that shortcut cannot drift
    from what the file really says.
    """
    import yaml

    root = Path(rs.REPO_ROOT)
    counts: dict[str, int] = {}
    for path in root.glob("resources/examples/**/*.yml"):
        docs = [
            d
            for d in yaml.safe_load_all(path.read_text(encoding="utf-8"))
            if isinstance(d, dict)
        ]
        status = docs[-1].get("status")
        counts[status] = counts.get(status, 0) + 1

    assert rs.count_status_test(root) == counts.get("test", 0)
    assert rs.count_status_experimental(root) == counts.get("experimental", 0)
    assert rs.count_status_stable(root) == counts.get("stable", 0)


def test_check_mode_reports_drift_without_writing(
    tmp_path: Path, monkeypatch: "pytest.MonkeyPatch", capsys: "pytest.CaptureFixture[str]"
) -> None:
    """--check is the CI gate; it must exit non-zero and leave the file alone."""
    corpus = tmp_path / "resources" / "examples" / "execution"
    corpus.mkdir(parents=True)
    _write_rule(corpus / "a.yml", "test")
    readme = tmp_path / "README.md"
    stale = "count: <!-- METRIC:sigma_rule_count -->999<!-- /METRIC:sigma_rule_count -->\n"
    readme.write_text(stale, encoding="utf-8")

    monkeypatch.setattr(rs, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(rs, "README", readme)

    assert rs.main(["--check"]) == 1
    assert readme.read_text(encoding="utf-8") == stale, "--check must not write"
    assert "DRIFT" in capsys.readouterr().out


def test_check_mode_passes_when_in_sync(
    tmp_path: Path, monkeypatch: "pytest.MonkeyPatch"
) -> None:
    corpus = tmp_path / "resources" / "examples" / "execution"
    corpus.mkdir(parents=True)
    _write_rule(corpus / "a.yml", "test")
    readme = tmp_path / "README.md"
    readme.write_text(
        "count: <!-- METRIC:sigma_rule_count -->1<!-- /METRIC:sigma_rule_count -->\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(rs, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(rs, "README", readme)
    assert rs.main(["--check"]) == 0


def test_main_writes_the_corrected_value(
    tmp_path: Path, monkeypatch: "pytest.MonkeyPatch"
) -> None:
    corpus = tmp_path / "resources" / "examples" / "execution"
    corpus.mkdir(parents=True)
    _write_rule(corpus / "a.yml", "test")
    _write_rule(corpus / "b.yml", "test")
    readme = tmp_path / "README.md"
    readme.write_text(
        "count: <!-- METRIC:sigma_rule_count -->0<!-- /METRIC:sigma_rule_count -->\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(rs, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(rs, "README", readme)

    assert rs.main([]) == 0
    assert ">2<" in readme.read_text(encoding="utf-8")


def test_main_reports_missing_readme(
    tmp_path: Path, monkeypatch: "pytest.MonkeyPatch"
) -> None:
    monkeypatch.setattr(rs, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(rs, "README", tmp_path / "nope.md")
    assert rs.main([]) == 2


def test_plugin_claim_is_rewritten_from_ground_truth(tmp_path: Path) -> None:
    """plugin.json states the count as prose; a JSON file cannot hold a marker.

    Third instance of the same reach problem: README's markers stayed correct
    through the corpus going 101 -> 222 while DEMO.md's prose AND this
    manifest's `description` both sat at "100". The manifest is the most
    public of the three -- it is what a marketplace listing renders.
    """
    corpus = tmp_path / "resources" / "examples" / "execution"
    corpus.mkdir(parents=True)
    for name in ("a.yml", "b.yml", "c.yml"):
        _write_rule(corpus / name, "test")

    text = "Ships a 100-rule published corpus spanning 9 MITRE ATT&CK tactics."
    out, drift = rs.stamp_text(
        text,
        tmp_path,
        expected=frozenset(),
        apply_badges=False,
        claims=rs.PLUGIN_CLAIMS,
        label="plugin.json",
    )

    assert "Ships a 3-rule published corpus" in out
    assert "spanning 1 MITRE ATT&CK tactics" in out
    assert ("sigma_rule_count (claim)", "100", "3") in drift


def test_main_leaves_the_real_demo_alone_when_readme_is_redirected(
    tmp_path: Path, monkeypatch: "pytest.MonkeyPatch"
) -> None:
    """A redirected README must not drag the repo's own DEMO.md into the write.

    Regression, and one that actually fired: the multi-file target map was
    first written as a module-level dict built from the real README/DEMO
    paths at import time. ``monkeypatch`` could redirect ``README``, but the
    dict still held the repo's published DEMO.md -- so this very test file's
    2-rule tmp corpus got stamped into it as "0 of 2". Resolving targets at
    call time, relative to wherever ``README`` currently points, is the fix.
    """
    real_demo = rs.REPO_ROOT / "DEMO.md"
    before = rs._read(real_demo)

    corpus = tmp_path / "resources" / "examples" / "execution"
    corpus.mkdir(parents=True)
    _write_rule(corpus / "a.yml", "test")
    _write_rule(corpus / "b.yml", "test")
    readme = tmp_path / "README.md"
    readme.write_text(
        "count: <!-- METRIC:sigma_rule_count -->0<!-- /METRIC:sigma_rule_count -->\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(rs, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(rs, "README", readme)

    assert rs.main([]) == 0
    assert ">2<" in readme.read_text(encoding="utf-8")  # tmp file WAS stamped
    assert rs._read(real_demo) == before, "main() wrote into the real DEMO.md"
