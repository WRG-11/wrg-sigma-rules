"""INDEX.json <-> on-disk rule-corpus consistency (R89-568h drift-fix).

INDEX.json drifted from disk repeatedly (observed->template relabels, one-off
new-rule additions) because nothing asserted the two stay in sync: total_rules
said 68 while disk held 73, and the 'persistence' tactic (12th ATT&CK category)
was completely unindexed. This suite regenerates the index from disk and
diffs it against the committed INDEX.json -- any future addition/rename/
removal that skips `scripts/migrate_sigma_corpus.py --regenerate-index` fails
CI instead of silently drifting again.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

_PLUGIN_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PLUGIN_ROOT))

from scripts.migrate_sigma_corpus import regenerate_index_from_disk  # noqa: E402

_EXAMPLES_DIR = _PLUGIN_ROOT / "resources" / "examples"
_INDEX_PATH = _EXAMPLES_DIR / "INDEX.json"

_REGEN_HINT = "run `py -3 scripts/migrate_sigma_corpus.py --regenerate-index`"


def _load_index() -> dict:
    return json.loads(_INDEX_PATH.read_text(encoding="utf-8"))


def _disk_rule_relpaths() -> set[str]:
    return {
        p.relative_to(_EXAMPLES_DIR).as_posix() for p in _EXAMPLES_DIR.rglob("*.yml")
    }


def test_total_rules_matches_disk_count() -> None:
    """INDEX.total_rules must equal the actual on-disk *.yml count."""
    index = _load_index()
    disk_count = len(_disk_rule_relpaths())
    assert index["total_rules"] == disk_count, (
        f"INDEX.json total_rules={index['total_rules']} but disk has "
        f"{disk_count} *.yml rules -- {_REGEN_HINT}"
    )


def test_every_disk_rule_is_indexed() -> None:
    """Every on-disk rule file must appear in INDEX.categories."""
    index = _load_index()
    indexed = {f for files in index["categories"].values() for f in files}
    missing = sorted(_disk_rule_relpaths() - indexed)
    assert not missing, (
        f"{len(missing)} on-disk rule(s) missing from INDEX.categories: "
        f"{missing} -- {_REGEN_HINT}"
    )


def test_no_stale_index_entries() -> None:
    """INDEX.categories must not reference files that no longer exist on disk."""
    index = _load_index()
    indexed = {f for files in index["categories"].values() for f in files}
    stale = sorted(indexed - _disk_rule_relpaths())
    assert not stale, (
        f"{len(stale)} INDEX.categories entry(ies) reference missing files "
        f"(stale rename?): {stale} -- {_REGEN_HINT}"
    )


def test_persistence_tactic_indexed() -> None:
    """Regression guard: 'persistence' (12th ATT&CK tactic) must be indexed.

    R89-568h found this tactic dir present on disk but completely absent
    from INDEX.categories -- the total_rules drift masked it.
    """
    index = _load_index()
    assert "persistence" in index["categories"], (
        "'persistence' tactic missing from INDEX.categories"
    )
    assert index["categories"]["persistence"], "persistence category is empty"


def test_by_detection_type_and_by_target_platform_cover_all_rules() -> None:
    """Auxiliary index dimensions must cover every indexed rule exactly once."""
    index = _load_index()
    total = index["total_rules"]
    for dim in ("by_detection_type", "by_target_platform"):
        flat = [f for files in index[dim].values() for f in files]
        assert len(flat) == total, (
            f"INDEX.{dim} covers {len(flat)} rules, expected {total} -- "
            f"{_REGEN_HINT}"
        )
        assert len(set(flat)) == len(flat), f"INDEX.{dim} has duplicate entries"


def test_regenerated_index_matches_committed_index() -> None:
    """Full snapshot test: regenerating from disk must reproduce INDEX.json.

    Catches any drift dimension (rename, addition, removal, re-categorization)
    in one assertion, independent of which specific field the other tests
    happen to check.
    """
    committed = _load_index()
    regenerated = regenerate_index_from_disk(
        _EXAMPLES_DIR, generated_at=committed["_generated_at"]
    )
    for key in ("total_rules", "categories", "by_detection_type", "by_target_platform"):
        assert regenerated[key] == committed[key], (
            f"INDEX.json '{key}' is out of sync with on-disk rules -- "
            f"{_REGEN_HINT}"
        )
