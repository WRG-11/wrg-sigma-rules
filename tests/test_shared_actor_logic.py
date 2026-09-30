"""One detection logic, one rule: an actor observed doing the same thing is a tag.

Measured 2026-09-30: 47 `observed_*` rules repeated one of 11 detection
logics under a different actor tag -- identical `detection:` and
`correlation:`, differing only in title, id, references and level. 43 were
byte-identical; 4 differed only in writing the threshold as `gt: N` instead of
`gte: N+1`, which selects the same integer counts. The biggest group was 14
files for one "same file-sharing host 4+ times in 10 minutes" signature. They
were merged into 11 `observed_shared_*` rules that carry every member's actor
tag and list the merged ids under `related`.

A new actor seen matching an existing rule's logic is added to that rule
(tag + references); a second file with the same logic fails here, including
one that only rewrites the threshold.
"""
from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from duplicate_rule_check import (  # noqa: E402
    _actor_tags,
    _logic_digest,
    find_exact_actor_logic_groups,
)

EXAMPLES = ROOT / "resources" / "examples"
ACTOR = "wrg.observed.actor."


def _gte_form(docs: list[dict]) -> list[dict]:
    """`gt: N` -> `gte: N+1`; the duplicate checker deliberately keeps them apart."""
    out = []
    for doc in docs:
        corr = doc.get("correlation")
        if isinstance(corr, dict) and isinstance(corr.get("condition"), dict):
            cond = corr["condition"]
            if set(cond) == {"gt"} and isinstance(cond["gt"], int):
                doc = {**doc, "correlation": {**corr, "condition": {"gte": cond["gt"] + 1}}}
        out.append(doc)
    return out


def _shared_rules() -> list[Path]:
    return sorted(EXAMPLES.rglob("observed_shared_*.yml"))


def _docs(path: Path) -> list[dict]:
    return [d for d in yaml.safe_load_all(path.read_text(encoding="utf-8")) if isinstance(d, dict)]


def test_no_two_observed_rules_share_exact_logic() -> None:
    skipped: list[str] = []
    groups = find_exact_actor_logic_groups(EXAMPLES, skipped_files=skipped)
    assert skipped == []
    assert groups == [], [[r["path"] for r in g["rules"]] for g in groups]


def test_no_two_observed_rules_share_logic_up_to_the_threshold_spelling() -> None:
    groups: dict[str, list[str]] = defaultdict(list)
    for path in sorted(EXAMPLES.rglob("observed_*.yml")):
        docs = _docs(path)
        if _actor_tags(docs):
            groups[_logic_digest(_gte_form(docs))].append(path.name)
    assert [names for names in groups.values() if len(names) > 1] == []


def test_gte_form_equates_gt_n_with_gte_n_plus_one() -> None:
    """Two-directional canary for the normalisation the test above relies on."""
    gt = [{"correlation": {"type": "event_count", "condition": {"gt": 3}}}]
    gte = [{"correlation": {"type": "event_count", "condition": {"gte": 4}}}]
    other = [{"correlation": {"type": "event_count", "condition": {"gte": 3}}}]
    assert _logic_digest(_gte_form(gt)) == _logic_digest(_gte_form(gte))
    assert _logic_digest(_gte_form(gt)) != _logic_digest(_gte_form(other))


def test_shared_rules_exist() -> None:
    """Canary: the checks below must have something to check."""
    assert len(_shared_rules()) >= 11


def test_shared_rules_name_every_actor_they_tag() -> None:
    for path in _shared_rules():
        docs = _docs(path)
        alert = docs[-1]
        actors = [t.removeprefix(ACTOR) for t in alert["tags"] if t.startswith(ACTOR)]
        assert len(actors) >= 2, path.name
        for actor in actors:
            assert actor in alert["description"], (path.name, actor)


def test_shared_rules_relate_to_the_ids_they_replaced() -> None:
    for path in _shared_rules():
        for doc in _docs(path):
            related = doc.get("related") or []
            assert related, (path.name, doc["title"])
            assert {entry["type"] for entry in related} == {"merged"}, path.name
