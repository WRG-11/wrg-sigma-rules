"""Correlation conversions report where the query changes the rule's meaning.

A converted correlation query can be valid syntax and still ask a different
question than the Sigma rule. Measured 2026-09-30 over the 52 corpus
correlation rules with the pinned backends (pySigma 1.5.1,
pysigma-backend-elasticsearch 2.1.1, pysigma-backend-opensearch 2.0.3,
pysigma-backend-splunk 2.1.0):

* ``opensearch-ppl`` drops the ``timespan`` of every ``event_count`` and
  ``value_count`` rule (48 rules): the threshold then applies to the whole
  search range. For ``temporal`` / ``temporal_ordered`` it tells sub-rules
  apart by ``dc(EventID)`` and enforces no order; in all 3
  ``temporal_ordered`` rules both sub-rules read ``process_creation``, so the
  query cannot reach its own threshold.
* ``eql`` renders ``value_count`` as a join on the counted field (the same
  value repeated, the opposite of distinct values), renders ``gt N`` as
  ``runs=N``, and drops the window of ``temporal`` (``sample``).
* ``splunk`` and ``esql`` keep the window as fixed buckets; ``eql`` keeps it
  as a sliding ``maxspan`` and enforces order with ``sequence``.

Every check here is two-directional: it fires on the measured deviation and
stays silent on a target that keeps the property. If a backend upgrade fixes
a deviation, the "fires" test turns red -- the prompt is to drop that check,
not to weaken the test.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from tools.convert_rule import convert_rule_body  # noqa: E402

pytest.importorskip("sigma.backends.elasticsearch")
pytest.importorskip("sigma.backends.opensearch")
pytest.importorskip("sigma.backends.splunk")

_EXAMPLES = _ROOT / "resources" / "examples"


def _rule(name: str) -> str:
    matches = sorted(_EXAMPLES.rglob(name))
    assert len(matches) == 1, name
    return matches[0].read_text(encoding="utf-8")


EVENT_COUNT = "observed_medusa_t1005.yml"  # gt 5 in 10m by Image
VALUE_COUNT = "template_t1110_003_password_spraying_distinct_account_count.yml"  # >15 users/30m
TEMPORAL = "template_t1486_t1490_ransomware_chain_temporal.yml"  # 30m, two log types
TEMPORAL_ORDERED = "observed_clawhavoc_claude_skills_t1195_002.yml"  # 5m, both process_creation


def _convert(name: str, target: str) -> dict:
    result = convert_rule_body(_rule(name), target=target)
    assert result["ok"] is True, (target, result.get("error"))
    return result


def _codes(result: dict) -> set[str]:
    return {item["code"] for item in result["correlation_semantics"]}


# --------------------------------------------------------------- window
@pytest.mark.parametrize("name", [EVENT_COUNT, VALUE_COUNT])
def test_ppl_count_correlations_drop_the_window(name: str) -> None:
    result = _convert(name, "opensearch-ppl")
    assert "window_dropped" in _codes(result)
    assert any("whole search" in warning for warning in result["warnings"])


@pytest.mark.parametrize("target", ["splunk", "esql"])
@pytest.mark.parametrize("name", [EVENT_COUNT, VALUE_COUNT, TEMPORAL])
def test_splunk_and_esql_keep_the_window_as_fixed_buckets(name: str, target: str) -> None:
    codes = _codes(_convert(name, target))
    assert "window_dropped" not in codes
    assert "fixed_window" in codes


def test_esql_renders_the_window_as_date_trunc() -> None:
    result = _convert(EVENT_COUNT, "esql")
    assert "date_trunc(10minutes, @timestamp)" in result["query"]


def test_eql_keeps_a_sliding_window_for_counts() -> None:
    codes = _codes(_convert(EVENT_COUNT, "eql"))
    assert "window_dropped" not in codes
    assert "fixed_window" not in codes


def test_eql_temporal_drops_the_window() -> None:
    """``sample`` matches the sub-rules with no time bound at all."""
    result = _convert(TEMPORAL, "eql")
    assert result["query"].lstrip().startswith("sample")
    assert "window_dropped" in _codes(result)


# ---------------------------------------------------------------- order
def test_eql_enforces_temporal_order_with_a_sequence() -> None:
    result = _convert(TEMPORAL_ORDERED, "eql")
    assert result["query"].lstrip().startswith("sequence")
    assert "maxspan=5m" in result["query"]
    assert _codes(result) == set()


def test_ppl_temporal_ordered_enforces_no_order() -> None:
    assert "order_not_enforced" in _codes(_convert(TEMPORAL_ORDERED, "opensearch-ppl"))


# ------------------------------------------------------ sub-rule identity
def test_ppl_same_logsource_subrules_cannot_reach_the_threshold() -> None:
    """Both sub-rules read process_creation, so dc(EventID) stays at 1."""
    result = _convert(TEMPORAL_ORDERED, "opensearch-ppl")
    assert "dc(EventID)" in result["query"]
    codes = _codes(result)
    assert {"subrule_identity_by_eventid", "cannot_fire_same_logsource"} <= codes


def test_ppl_different_logsource_subrules_are_only_flagged_not_declared_dead() -> None:
    """process_creation + file_event carry different EventIDs; the proxy can work."""
    codes = _codes(_convert(TEMPORAL, "opensearch-ppl"))
    assert "subrule_identity_by_eventid" in codes
    assert "cannot_fire_same_logsource" not in codes


# ------------------------------------------------------------ value_count
def test_eql_value_count_joins_on_the_counted_field() -> None:
    result = _convert(VALUE_COUNT, "eql")
    assert "] by TargetUserName" in result["query"]
    assert "value_count_joins_on_field" in _codes(result)


def test_esql_value_count_counts_distinct_values() -> None:
    result = _convert(VALUE_COUNT, "esql")
    assert "count_distinct(TargetUserName)" in result["query"]
    assert "value_count_joins_on_field" not in _codes(result)


# -------------------------------------------------------------- threshold
def test_eql_gt_threshold_is_one_run_short() -> None:
    result = _convert(EVENT_COUNT, "eql")
    assert "runs=5" in result["query"]
    assert "threshold_off_by_one" in _codes(result)


def test_splunk_gt_threshold_is_kept() -> None:
    result = _convert(EVENT_COUNT, "splunk")
    assert "event_count > 5" in result["query"]
    assert "threshold_off_by_one" not in _codes(result)


# ----------------------------------------------------------------- scope
def test_plain_rules_carry_no_correlation_semantics_field() -> None:
    result = _convert("observed_play_t1190.yml", "splunk")
    assert "correlation_semantics" not in result


def test_every_corpus_correlation_gets_a_checked_semantics_list() -> None:
    """An empty list means the checks ran and found nothing -- not equivalence."""
    rules = [
        path
        for path in sorted(_EXAMPLES.rglob("*.yml"))
        if any(line.startswith("correlation:") for line in path.read_text(encoding="utf-8").splitlines())
    ]
    assert len(rules) >= 50
    for path in rules:
        result = convert_rule_body(path.read_text(encoding="utf-8"), target="esql")
        if not result["ok"]:
            assert result["capability"] == "correlation_type:temporal_ordered", path.name
            continue
        assert isinstance(result["correlation_semantics"], list), path.name
