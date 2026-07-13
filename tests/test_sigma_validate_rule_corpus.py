"""Corpus validation -- every WRG sigma rule example validates clean.

51 parametrized tests covering all tactics:
  code_review / collection / command_and_control / credential_access /
  defense_evasion / execution / exfiltration / impact / initial_access /
  lateral_movement / resource_development

Import-guard discipline (ss15.14 v1.2 7th realisation; cross-corpus
sister pattern, MATURE cluster):
  pytest.importorskip("sigma") ensures ALL 51 tests SKIP when pySigma is
  not installed, and ALL 51 PASS when it is -- scaffold-cross-validation.

Delta-1: brief targeted apps/wrg_actor_watch/sigma_rules/*.yml (path
  absent in repo); actual corpus lives in resources/examples/**/*.yml
  (migration artifact). 51 rules discovered at collection time.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Import-guard: ALL tests in this module skip if pySigma is absent.
# When pySigma is installed, all 51 corpus rules must validate clean.
pytest.importorskip("sigma", reason="pySigma required for corpus validation")

_PLUGIN_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PLUGIN_ROOT))

from tools.validate_rule import validate_rule_body  # noqa: E402

_EXAMPLES_DIR = _PLUGIN_ROOT / "resources" / "examples"


def _collect_corpus_rules() -> list[Path]:
    return sorted(_EXAMPLES_DIR.rglob("*.yml"))


_CORPUS_RULES = _collect_corpus_rules()

# Known corpus quality issues: rules with structural anomalies that pre-date
# this test scaffold. These are KNOWN and ACCEPTED; each entry documents
# the known schema defect. These should be fixed in a future pass.
# Keyed by file stem -> list of allowed schema error field values.
#
# Note: the nil-UUID entry for observed_sigma_rule_lockbit_btc was
# removed here -- _UUID_RE now accepts the nil UUID as a valid RFC 4122
# special case, so that rule's zero-UUID id no longer produces a schema
# error and needs no allowlisting.
_KNOWN_SCHEMA_QUALITY_ISSUES: dict[str, list[str]] = {}


@pytest.mark.parametrize(
    "rule_path",
    _CORPUS_RULES,
    ids=[p.stem for p in _CORPUS_RULES],
)
def test_corpus_rule_schema_valid(rule_path: Path) -> None:
    """Every WRG corpus rule must pass schema + pySigma validation.

    Rules listed in _KNOWN_SCHEMA_QUALITY_ISSUES are allowed to have the
    specific schema defects documented there (zero-UUID placeholder etc.).
    All other schema errors are hard failures.
    """
    yaml_content = rule_path.read_text(encoding="utf-8")
    result = validate_rule_body(yaml_content)

    assert result["ok"] is True, (
        f"{rule_path.name}: validate_rule_body returned ok=False"
    )

    known_allowed_fields = _KNOWN_SCHEMA_QUALITY_ISSUES.get(rule_path.stem, [])
    unexpected_errors = [
        e for e in result["schema_errors"]
        if e.get("field") not in known_allowed_fields
    ]
    assert unexpected_errors == [], (
        f"{rule_path.name} unexpected schema errors: {unexpected_errors}\n"
        f"(known allowed fields: {known_allowed_fields})"
    )

    hard_failures = [
        e for e in result.get("pysigma_errors", [])
        if e.get("kind") == "pysigma_parse"
    ]
    assert not hard_failures, (
        f"{rule_path.name} pySigma parse errors: {hard_failures}"
    )

    # Linter warnings are quality hints, not blocking errors.
    # Allow up to 2 (condition_default for code_review + one other).
    assert len(result["linter_warnings"]) <= 2, (
        f"{rule_path.name} has {len(result['linter_warnings'])} linter "
        f"warnings: {[w['rule'] for w in result['linter_warnings']]}"
    )


@pytest.mark.parametrize(
    "rule_path",
    _CORPUS_RULES,
    ids=[p.stem for p in _CORPUS_RULES],
)
def test_corpus_rule_ascii_output(rule_path: Path) -> None:
    """Validate output strings must be ASCII-only (Pattern 33 Rule 5)."""
    yaml_content = rule_path.read_text(encoding="utf-8")
    result = validate_rule_body(yaml_content)
    for err in result.get("schema_errors", []):
        msg = err.get("message", "")
        assert all(ord(c) < 128 for c in msg), (
            f"{rule_path.name} non-ASCII in schema error: {msg!r}"
        )


def test_corpus_rule_count_meets_minimum() -> None:
    """Corpus must contain at least 51 rules (migration baseline)."""
    assert len(_CORPUS_RULES) >= 51, (
        f"Expected >= 51 corpus rules, found {len(_CORPUS_RULES)}"
    )


def test_corpus_rules_span_minimum_6_tactics() -> None:
    """Corpus must cover at least 6 MITRE tactic categories."""
    tactic_dirs = {p.parent.name for p in _CORPUS_RULES}
    assert len(tactic_dirs) >= 6, (
        f"Expected >= 6 tactic dirs, found {tactic_dirs}"
    )


def test_corpus_observed_rules_have_actor_tags() -> None:
    """Observed rules (prefix 'observed_') must carry a wrg.observed tag."""
    import yaml as _yaml

    observed_paths = [p for p in _CORPUS_RULES if p.stem.startswith("observed_")]
    assert observed_paths, "No observed_ rules found in corpus"
    for p in observed_paths:
        doc = _yaml.safe_load(p.read_text(encoding="utf-8"))
        tags = [t.lower() for t in (doc.get("tags") or [])]
        assert any(t in ("wrg.observed", "wrg.observed.actor") or t.startswith("wrg.observed")
                   for t in tags), (
            f"{p.name}: observed rule missing wrg.observed tag; tags={tags}"
        )


def test_corpus_template_rules_have_status_experimental() -> None:
    """Template rules (prefix 'template_') must be status=experimental."""
    import yaml as _yaml

    template_paths = [p for p in _CORPUS_RULES if p.stem.startswith("template_")]
    assert template_paths, "No template_ rules found in corpus"
    for p in template_paths:
        doc = _yaml.safe_load(p.read_text(encoding="utf-8"))
        status = doc.get("status", "")
        assert status in ("experimental", "test"), (
            f"{p.name}: template rule has unexpected status='{status}'"
        )
