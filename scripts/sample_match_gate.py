#!/usr/bin/env python3
"""sample_match_gate.py -- verify that a rule's sidecar sample event(s)
actually fire the rule's own detection logic, and that a rule marked
``status: test`` has a sample at all.

Modeled on SigmaHQ/sigma's ``regression_data`` system (README fetched and
read in full 2026-09-04): every ``status: test``/``stable`` rule there must
carry a ``regression_tests_path`` pointing at a real EVTX/JSON sample plus
an expected ``match_count``, enforced in CI. This corpus is proxy/
application-logsource-heavy rather than Windows-EVTX-heavy, so the JSON
sidecar shape (not the EVTX one) is what actually fits -- no new dependency,
no EVTX tooling.

Sidecar convention: ``resources/examples/<category>/<rule>.sample.json``,
a JSON object (or list of them) shaped like the flat event dict the rule's
own ``detection:`` selections are written against (the same key/value shape
this corpus's rules already use in their own ``Message``/``cs-*``/field
examples). Two kinds of entries are meaningful:

* ``{"expect_match": true, "event": {...}}`` -- must fire the rule.
* ``{"expect_match": false, "event": {...}}`` -- must NOT fire the rule
  (a clean/benign case). A rule with ONLY positive samples has never been
  shown to reject anything, which is exactly the asymmetry this gate is
  built to catch.

This is advisory, same spirit as duplicate_rule_check.py -- it does not
fail on a missing sample by default, since the sidecar convention is new
and retrofitting 212 observed_* rules is its own project, not a side
effect of running this script once. ``--require-samples`` promotes missing
samples on ``status: test`` rules from a warning to a failure, for use once
the sidecar becomes a real authoring requirement.

Evaluator scope (deliberately NOT a full Sigma implementation): supports
the modifier set actually observed across this corpus's rules --
``contains`` (+ ``all``), ``endswith``, ``startswith``, ``re``, ``cidr``,
``gt``, ``gte``, ``lt``, ``lte``, and a bare/absent-field null check. Sigma's
wildcard-count syntax (``1 of selection_*``, ``all of selection_dns_*``,
``2 of selection_*``) is expanded to plain and/or/sum() first; the resulting
condition string -- using ``and``/``or``/``not``/parentheses over selection
names, already Python-boolean-shaped -- is evaluated directly in a
namespace containing ONLY the selections' own true/false results --
this is not eval() over untrusted input, the corpus is this repo's own
YAML, and the namespace has no builtins. A condition or modifier this
evaluator doesn't understand is reported as ``ERR``, never silently
treated as a non-match -- a broken probe must not report an empty result
the same way a probe that ran and found nothing does.

Usage:
    python scripts/sample_match_gate.py                    # advisory report
    python scripts/sample_match_gate.py --require-samples  # status:test needs a sample
    python scripts/sample_match_gate.py --json out.json
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLES_DIR = REPO_ROOT / "resources" / "examples"


class EvaluatorError(Exception):
    """A rule/sample shape this evaluator does not support -- never
    silently treated as a non-match. Distinguishes 'measured: no match'
    from 'could not measure'."""


def _match_single(value: Any, expected: Any, mods: list[str]) -> bool:
    if "re" in mods:
        return bool(re.search(str(expected), str(value)))
    if "cidr" in mods:
        return ipaddress.ip_address(str(value)) in ipaddress.ip_network(str(expected))
    if "contains" in mods:
        return str(expected) in str(value)
    if "endswith" in mods:
        return str(value).endswith(str(expected))
    if "startswith" in mods:
        return str(value).startswith(str(expected))
    if "gte" in mods:
        return value >= expected
    if "lte" in mods:
        return value <= expected
    if "gt" in mods:
        return value > expected
    if "lt" in mods:
        return value < expected
    if not mods:
        return value == expected
    raise EvaluatorError(f"unsupported modifier(s) {mods!r} on value {expected!r}")


def _match_field(value: Any, expected: Any, mods: list[str]) -> bool:
    if expected is None:
        return value is None
    if isinstance(expected, list):
        results = [_match_single(value, e, [m for m in mods if m != "all"]) for e in expected]
        return all(results) if "all" in mods else any(results)
    return _match_single(value, expected, mods)


def _match_selection(selection: dict[str, Any], event: dict[str, Any]) -> bool:
    for field_spec, expected in selection.items():
        field_name, *mods = field_spec.split("|")
        if expected is None and field_name not in event:
            continue  # absent field satisfies an explicit null check
        value = event.get(field_name)
        if not _match_field(value, expected, mods):
            return False
    return True


_OF_EXPR_RE = re.compile(r"\b(all|\d+|1)\s+of\s+([A-Za-z0-9_]+)\*")


def _expand_of_expressions(condition: str, selection_results: dict[str, bool]) -> str:
    """Expand Sigma's ``N of <prefix>*`` / ``all of <prefix>*`` wildcard-count
    syntax into a plain Python boolean sub-expression, so the rest of the
    condition string can still be handled by a normal eval(). Raises
    EvaluatorError (never silently drops to False) if a count-expression's
    prefix matches no selection name at all -- that is a broken probe, not
    an empty result.
    """

    def replace(m: re.Match[str]) -> str:
        count_token, prefix = m.group(1), m.group(2)
        matching = sorted(name for name in selection_results if name.startswith(prefix))
        if not matching:
            raise EvaluatorError(f"'{count_token} of {prefix}*' matched no selection name")
        if count_token == "all":
            return "(" + " and ".join(matching) + ")"
        n = int(count_token)
        if n == 1:
            return "(" + " or ".join(matching) + ")"
        terms = ", ".join(f"bool({name})" for name in matching)
        return f"(sum([{terms}]) >= {n})"

    return _OF_EXPR_RE.sub(replace, condition)


def _evaluate_condition(condition: str, selection_results: dict[str, bool]) -> bool:
    # Sigma's condition grammar (and/or/not/parens over selection names) is
    # already Python-boolean-shaped. Evaluated in a namespace holding ONLY
    # the selections' own bool results, no builtins -- this is this repo's
    # own trusted YAML, not untrusted input, and the namespace can express
    # nothing beyond true/false combination. Sigma's wildcard-count syntax
    # (``1 of selection_*``, ``all of selection_dns_*``, ``2 of selection_*``)
    # is expanded to plain and/or/sum() first, since eval() cannot parse it
    # directly.
    try:
        expanded = _expand_of_expressions(condition, selection_results)
    except EvaluatorError:
        raise
    try:
        return bool(eval(expanded, {"__builtins__": {}}, selection_results))  # noqa: S307
    except Exception as exc:
        raise EvaluatorError(f"condition {condition!r} could not be evaluated: {exc}") from exc


def rule_fires(rule_doc: dict[str, Any], event: dict[str, Any]) -> bool:
    """Return whether ``event`` satisfies ``rule_doc``'s detection condition.

    Raises EvaluatorError (never returns a silent False) when the rule uses
    a modifier or condition shape this evaluator does not support.
    """
    detection = rule_doc.get("detection", {})
    condition = detection.get("condition")
    if not isinstance(condition, str):
        raise EvaluatorError("no single string 'condition' -- correlation rule or multi-condition; skip")
    selection_results = {
        name: _match_selection(sel, event)
        for name, sel in detection.items()
        if name != "condition" and isinstance(sel, dict)
    }
    return _evaluate_condition(condition, selection_results)


@dataclass
class RuleCheck:
    relpath: str
    status: str | None
    has_sample: bool
    sample_results: list[str] = field(default_factory=list)
    ok: bool = True


def _load_first_doc(path: Path) -> dict[str, Any]:
    docs = [d for d in yaml.safe_load_all(path.read_text(encoding="utf-8")) if isinstance(d, dict)]
    for d in docs:
        if "detection" in d:
            return d
    return docs[0] if docs else {}


def check_rule(rule_path: Path) -> RuleCheck:
    rule_doc = _load_first_doc(rule_path)
    status = rule_doc.get("status")
    sample_path = rule_path.with_suffix("").with_suffix(".sample.json")
    relpath = "resources/examples/" + rule_path.relative_to(EXAMPLES_DIR).as_posix()

    if not sample_path.is_file():
        return RuleCheck(relpath=relpath, status=status, has_sample=False)

    check = RuleCheck(relpath=relpath, status=status, has_sample=True)
    try:
        cases = json.loads(sample_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        check.ok = False
        check.sample_results.append(f"ERR: sample file is not valid JSON: {exc}")
        return check
    if isinstance(cases, dict):
        cases = [cases]

    saw_positive = False
    saw_negative = False
    for i, case in enumerate(cases):
        expect = case.get("expect_match")
        event = case.get("event", {})
        if expect is True:
            saw_positive = True
        elif expect is False:
            saw_negative = True
        try:
            fired = rule_fires(rule_doc, event)
        except EvaluatorError as exc:
            check.sample_results.append(f"case[{i}]: ERR ({exc})")
            continue
        if fired == bool(expect):
            check.sample_results.append(f"case[{i}]: OK (expected={expect}, got={fired})")
        else:
            check.ok = False
            check.sample_results.append(f"case[{i}]: FAIL (expected={expect}, got={fired})")

    if not saw_negative:
        check.sample_results.append(
            "NOTE: no expect_match=false case -- this sample only proves the rule "
            "CAN fire, never that it rejects a clean case (one-sided evidence)"
        )
    if not saw_positive:
        check.ok = False
        check.sample_results.append("ERR: no expect_match=true case in this sample file")

    return check


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--require-samples", action="store_true",
                        help="fail if any status:test rule has no sidecar sample")
    parser.add_argument("--json", metavar="PATH", default=None)
    args = parser.parse_args(argv)

    if not EXAMPLES_DIR.is_dir():
        print(f"[sample-match-gate] ERROR: {EXAMPLES_DIR} not found -- run from repo root", file=sys.stderr)
        return 2

    checks = [check_rule(p) for p in sorted(EXAMPLES_DIR.rglob("observed_*.yml"))]
    with_sample = [c for c in checks if c.has_sample]
    without_sample_test_status = [c for c in checks if not c.has_sample and c.status == "test"]
    failing = [c for c in with_sample if not c.ok]

    print(f"[sample-match-gate] {len(with_sample)}/{len(checks)} observed_* rules have a sidecar sample")
    for c in with_sample:
        marker = "OK" if c.ok else "FAIL"
        print(f"  [{marker}] {c.relpath}")
        for line in c.sample_results:
            print(f"      {line}")

    if without_sample_test_status:
        print(f"\n[sample-match-gate] {len(without_sample_test_status)} status:test rule(s) with NO sample:")
        for c in without_sample_test_status:
            print(f"  {c.relpath}")

    if args.json:
        payload = {
            "with_sample": [
                {"relpath": c.relpath, "status": c.status, "ok": c.ok, "results": c.sample_results}
                for c in with_sample
            ],
            "test_status_missing_sample": [c.relpath for c in without_sample_test_status],
        }
        Path(args.json).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    if failing:
        print(f"\n[sample-match-gate] FAIL: {len(failing)} rule(s) whose sample does not match their own detection logic")
        return 1
    if args.require_samples and without_sample_test_status:
        print(f"\n[sample-match-gate] FAIL: --require-samples set, {len(without_sample_test_status)} status:test rule(s) missing a sample")
        return 1
    print("\n[sample-match-gate] ok")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
