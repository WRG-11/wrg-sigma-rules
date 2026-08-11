"""Locks DEMO.md's Lucene-conversion claim to a real measurement.

``readme_stamp.count_lucene_convertible`` is DERIVED -- corpus size minus the
number of correlation rules -- so the stamp script can stay stdlib-only and
install nothing. The derivation carries one assumption: a correlation
document is the *only* reason a Lucene-family backend rejects a corpus rule.

That assumption is true today and was measured, not guessed. It is also
exactly the kind of thing that stops being true quietly: a rule using a
field modifier one backend cannot express would drop the real count below
the derived one, and DEMO.md would keep publishing the derived number.

So this test runs the actual ``convert_rule`` across the whole live corpus
on every Lucene target and fails the moment the two diverge.

stdlib + pytest + the repo's own conversion path; no network.
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

# The four targets DEMO.md groups as "the Lucene-family targets".
LUCENE_TARGETS = ("elastic", "kibana", "wazuh", "opensearch")


def _backend_module(target: str) -> str:
    """Ask the tool which module backs a target instead of hardcoding it."""
    return _BACKEND_SPECS[target][0]


requires_lucene_backends = pytest.mark.skipif(
    any(
        importlib.util.find_spec(_backend_module(t)) is None for t in LUCENE_TARGETS
    ),
    reason="pySigma Lucene-family backend package(s) not installed",
)


@pytest.fixture(scope="module")
def conversion_outcome() -> dict[str, set[str]]:
    """target -> set of rule filenames that failed to convert.

    Module-scoped: the corpus is converted once for every target here, and
    both tests below read the same result.
    """
    rules = sorted(_EXAMPLES_DIR.rglob("*.yml"))
    assert rules, "corpus enumerator returned nothing -- wrong root?"
    failures: dict[str, set[str]] = {}
    for target in LUCENE_TARGETS:
        failed: set[str] = set()
        for path in rules:
            result = convert_rule_body(path.read_text(encoding="utf-8"), target=target)
            if not result.get("ok"):
                failed.add(path.name)
        failures[target] = failed
    return failures


@requires_lucene_backends
def test_lucene_convert_count_matches_real_conversion(
    conversion_outcome: dict[str, set[str]],
) -> None:
    """The stamped number equals what the backends actually convert."""
    total = rs.count_rules(rs.REPO_ROOT)
    derived = rs.count_lucene_convertible(rs.REPO_ROOT)

    for target, failed in conversion_outcome.items():
        actual = total - len(failed)
        assert actual == derived, (
            f"{target} converts {actual} of {total} rules, but "
            f"lucene_convert_count is stamped as {derived}. "
            f"{len(failed)} rule(s) failed; correlation rules number "
            f"{rs.count_correlation_rules(rs.REPO_ROOT)}. Extra failures: "
            f"{sorted(failed)[:5]}"
        )


@requires_lucene_backends
def test_all_lucene_targets_fail_on_the_same_set(
    conversion_outcome: dict[str, set[str]],
) -> None:
    """DEMO.md says all four "share it" -- assert the sets are identical.

    A per-target difference would make the single stamped number wrong for
    at least one of the four, which prose grouping them together cannot
    express.
    """
    sets = {t: frozenset(f) for t, f in conversion_outcome.items()}
    distinct = set(sets.values())
    assert len(distinct) == 1, (
        "Lucene targets no longer fail on an identical set: "
        + "; ".join(f"{t}={len(f)}" for t, f in sorted(sets.items()))
    )
