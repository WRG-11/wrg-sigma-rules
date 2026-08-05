"""write_rule_yaml() date-regression guard.

Found via a real near-miss: running migrate_sigma_corpus.py's main()
overwrote an already-deployed, fresher observed_ai_fingerprint_ai_prose.yml
(date 2026-06-22, 2 aggregated hits) with content re-rendered from a STALE
test fixture (date 2026-05-13, 1 hit) -- render_ai_fingerprint_rules() and
render_observed_breach_rules() read from fixtures/goldens that are not
reliably kept in sync with what has since been deployed via other means.

A net-line-loss guard (the pattern tools/sigma_public_resync.ps1 already
uses) would NOT have caught this: the diff was 8 insertions / 10 deletions,
net loss of only 2 lines -- well under any reasonable line-count threshold.
What actually regressed was the `date:` field itself. Every rule in this
corpus carries `date:`, so comparing old-file-date vs new-content-date is a
narrow, precise, low-false-positive signal for exactly this failure shape --
"this write would backdate an already-deployed rule" -- without having to
know which render function's source is trustworthy.

Template rules (TECHNIQUE_PATTERN_LIBRARY) always render with a FIXED date
constant, so re-running the template render is a no-op for this guard by
construction (new_date == old_date, never a regression).
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import migrate_sigma_corpus as msc  # noqa: E402


@pytest.fixture
def examples_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(msc, "EXAMPLES_DIR", tmp_path)
    return tmp_path


def _rule_doc(date: str, extra: str = "x") -> dict[str, object]:
    return {
        "title": "t",
        "id": "00000000-0000-0000-0000-000000000000",
        "status": "experimental",
        "description": extra,
        "references": [],
        "author": "a",
        "date": date,
        "logsource": {"category": "code_review", "product": "wrg_ai_fingerprint"},
        "detection": {"selection": {"detector": "x"}, "condition": "selection"},
        "falsepositives": [],
        "level": "low",
        "tags": [],
    }


def test_new_file_never_triggers_the_guard(examples_dir: Path) -> None:
    path = msc.write_rule_yaml("code_review", "new.yml", _rule_doc("2026-05-13"))
    assert path.exists()


def test_same_or_newer_date_is_allowed(examples_dir: Path) -> None:
    msc.write_rule_yaml("code_review", "r.yml", _rule_doc("2026-05-13"))
    # same date -- must not raise
    msc.write_rule_yaml("code_review", "r.yml", _rule_doc("2026-05-13", extra="y"))
    # newer date -- must not raise
    path = msc.write_rule_yaml("code_review", "r.yml", _rule_doc("2026-06-22", extra="z"))
    assert "2026-06-22" in path.read_text(encoding="utf-8")


def test_older_date_refuses_by_default(examples_dir: Path) -> None:
    msc.write_rule_yaml("code_review", "r.yml", _rule_doc("2026-06-22"))
    with pytest.raises(msc.DateRegressionError):
        msc.write_rule_yaml("code_review", "r.yml", _rule_doc("2026-05-13"))
    # the existing (fresher) file must be untouched
    on_disk = (examples_dir / "code_review" / "r.yml").read_text(encoding="utf-8")
    assert "2026-06-22" in on_disk
    assert "2026-05-13" not in on_disk


def test_older_date_allowed_with_explicit_override(examples_dir: Path) -> None:
    msc.write_rule_yaml("code_review", "r.yml", _rule_doc("2026-06-22"))
    path = msc.write_rule_yaml(
        "code_review", "r.yml", _rule_doc("2026-05-13"), allow_date_regression=True
    )
    assert "2026-05-13" in path.read_text(encoding="utf-8")


def test_missing_or_unparseable_existing_file_does_not_crash(
    examples_dir: Path,
) -> None:
    """A corrupt/non-YAML existing file at the target path must not crash
    the guard -- treat 'can't determine old date' as 'no signal', not a
    hard failure (the write proceeds)."""
    cat_dir = examples_dir / "code_review"
    cat_dir.mkdir(parents=True)
    (cat_dir / "r.yml").write_text("not: [valid yaml", encoding="utf-8")
    path = msc.write_rule_yaml("code_review", "r.yml", _rule_doc("2026-05-13"))
    assert path.exists()


def test_rule_doc_without_date_field_skips_the_check(examples_dir: Path) -> None:
    doc = _rule_doc("2026-06-22")
    msc.write_rule_yaml("code_review", "r.yml", doc)
    no_date_doc = {k: v for k, v in _rule_doc("2026-05-13").items() if k != "date"}
    # must not raise -- nothing to compare against without a date field
    path = msc.write_rule_yaml("code_review", "r.yml", no_date_doc)
    assert path.exists()
