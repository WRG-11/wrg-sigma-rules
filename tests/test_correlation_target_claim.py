"""Locks DEMO.md's per-target conversion counts to a real measurement.

DEMO.md used to say that ``splunk`` and ``opensearch-ppl`` "convert all" corpus
rules. Measured 2026-09-30, splunk rejected 3: every ``temporal_ordered``
correlation, which pySigma's Splunk backend cannot express. The published
number had never been checked, because only the Lucene count had a test.

``readme_stamp.count_splunk_esql_convertible`` is derived (corpus minus
``temporal_ordered`` rules) so the stamp script stays stdlib-only. This test
runs the real ``convert_rule`` over the live corpus and fails the moment the
derivation and the backends disagree -- for splunk and esql (which must fail
on exactly the temporal_ordered set) and for eql and opensearch-ppl (which
must convert every rule; whether the result keeps the rule's meaning is
``correlation_semantics``' job, not this count's).
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import readme_stamp as rs  # noqa: E402
from tools.convert_rule.convert_rule import _BACKEND_SPECS  # noqa: E402
from tools.convert_rule.convert_rule import convert_rule_body  # noqa: E402
from tools.resources.coverage_resource import _EXAMPLES_DIR  # noqa: E402

TARGETS = ("splunk", "esql", "eql", "opensearch-ppl")

requires_backends = pytest.mark.skipif(
    any(importlib.util.find_spec(_BACKEND_SPECS[t][0]) is None for t in TARGETS),
    reason="pySigma splunk/elasticsearch/opensearch backend package(s) not installed",
)


@pytest.fixture(scope="module")
def failures() -> dict[str, set[str]]:
    rules = sorted(_EXAMPLES_DIR.rglob("*.yml"))
    assert rules, "corpus enumerator returned nothing -- wrong root?"
    failed: dict[str, set[str]] = {}
    for target in TARGETS:
        failed[target] = {
            path.name
            for path in rules
            if not convert_rule_body(path.read_text(encoding="utf-8"), target=target).get("ok")
        }
    return failed


def _temporal_ordered_files() -> set[str]:
    return {
        path.name
        for path in _EXAMPLES_DIR.rglob("*.yml")
        if "type: temporal_ordered" in path.read_text(encoding="utf-8")
    }


def test_temporal_ordered_count_is_not_zero() -> None:
    """Canary: a derivation that finds nothing would make every claim trivially true."""
    assert rs.count_temporal_ordered_rules(rs.REPO_ROOT) >= 1


@requires_backends
@pytest.mark.parametrize("target", ["splunk", "esql"])
def test_splunk_and_esql_fail_on_exactly_the_temporal_ordered_rules(
    failures: dict[str, set[str]], target: str
) -> None:
    assert failures[target] == _temporal_ordered_files()
    total = rs.count_rules(rs.REPO_ROOT)
    assert total - len(failures[target]) == rs.count_splunk_esql_convertible(rs.REPO_ROOT)


@requires_backends
@pytest.mark.parametrize("target", ["eql", "opensearch-ppl"])
def test_eql_and_ppl_convert_every_rule(failures: dict[str, set[str]], target: str) -> None:
    assert failures[target] == set()
