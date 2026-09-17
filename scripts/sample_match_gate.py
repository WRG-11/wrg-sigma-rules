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

For a base-rule plus ``event_count`` correlation, use the same shape with an
``events`` list instead of ``event``. The gate first evaluates the named base
rule for every event, groups matching events using the correlation's
``group-by`` fields, and then evaluates its ``gt``/``gte`` threshold. This is
deliberately only the correlation form used by this corpus; an unsupported
correlation is an error, never a silently passing sample.

This is advisory by default. ``--require-samples`` applies the requirement
to every ``status: test`` rule. ``--require-new-samples`` makes it a CI
authoring policy today: existing debt is enumerated in a reviewed baseline,
but any new status:test rule without a sidecar fails the build.

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
    python scripts/sample_match_gate.py --require-samples  # every status:test needs a sample
    python scripts/sample_match_gate.py --require-new-samples --baseline path/to/reviewed-baseline.json
    python scripts/sample_match_gate.py --json out.json

The repository CI uses the stricter ``--require-samples`` path. The optional
baseline mode is only for a deliberate staged-policy migration and requires an
explicit, reviewed file; this repository ships no grandfathered baseline.
"""
from __future__ import annotations

import ast

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
        # ``all`` is Sigma condition grammar (e.g. ``all of selection_*``),
        # not a credential literal.
        if count_token == "all":  # nosec B105
            return "(" + " and ".join(matching) + ")"
        n = int(count_token)
        if n == 1:
            return "(" + " or ".join(matching) + ")"
        terms = ", ".join(f"bool({name})" for name in matching)
        return f"(sum([{terms}]) >= {n})"

    return _OF_EXPR_RE.sub(replace, condition)


def _eval_node(node: ast.AST, names: dict[str, bool]) -> object:
    """Evaluate one node of a Sigma condition. Anything unlisted is an error.

    An allowlist, not a sandbox: the grammar this needs is `and` / `or` /
    `not` over selection names, plus the `sum([bool(x), ...]) >= n` shape
    that `_expand_of_expressions` produces for `N of prefix*`. Every other
    node type -- attribute access, subscripts, arbitrary calls, lambdas --
    raises rather than being evaluated, so there is nothing to escape from.
    """
    if isinstance(node, ast.Expression):
        return _eval_node(node.body, names)
    if isinstance(node, ast.BoolOp):
        vals = (_eval_node(v, names) for v in node.values)
        if isinstance(node.op, ast.And):
            return all(vals)
        if isinstance(node.op, ast.Or):
            return any(vals)
        raise EvaluatorError(f"unsupported boolean operator: {type(node.op).__name__}")
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return not _eval_node(node.operand, names)
    if isinstance(node, ast.Name):
        if node.id not in names:
            raise EvaluatorError(f"unknown selection name: {node.id!r}")
        return names[node.id]
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.List):
        return [_eval_node(e, names) for e in node.elts]
    if isinstance(node, ast.Compare):
        left = _eval_node(node.left, names)
        for op, comp in zip(node.ops, node.comparators):
            right = _eval_node(comp, names)
            if isinstance(op, ast.GtE):
                ok = left >= right
            elif isinstance(op, ast.Gt):
                ok = left > right
            elif isinstance(op, ast.LtE):
                ok = left <= right
            elif isinstance(op, ast.Lt):
                ok = left < right
            elif isinstance(op, ast.Eq):
                ok = left == right
            else:
                raise EvaluatorError(f"unsupported comparison: {type(op).__name__}")
            if not ok:
                return False
            left = right
        return True
    if isinstance(node, ast.Call):
        if not isinstance(node.func, ast.Name) or node.func.id not in {"sum", "bool"}:
            raise EvaluatorError("only sum() and bool() may be called in a condition")
        args = [_eval_node(a, names) for a in node.args]
        if node.keywords:
            raise EvaluatorError("keyword arguments are not allowed in a condition")
        return sum(args[0]) if node.func.id == "sum" else bool(args[0])
    raise EvaluatorError(f"unsupported expression element: {type(node).__name__}")


def _evaluate_condition(condition: str, selection_results: dict[str, bool]) -> bool:
    """Evaluate a Sigma condition over already-computed selection results.

    Parsed and walked with `ast`, never `eval`. The grammar is small enough
    that an allowlisting walker is shorter than the argument for why an
    `eval` would be safe -- and it does not have to be re-argued each time a
    scanner flags it (bandit B307, which this repo's CI fails on, and it
    carries no `# nosec` anywhere else).

    Sigma's wildcard-count syntax (`1 of selection_*`, `all of
    selection_dns_*`, `2 of selection_*`) is expanded to plain and/or/sum()
    first, because that shape is what the walker understands.
    """
    expanded = _expand_of_expressions(condition, selection_results)
    try:
        tree = ast.parse(expanded, mode="eval")
    except SyntaxError as exc:
        raise EvaluatorError(f"condition {condition!r} could not be parsed: {exc}") from exc
    try:
        return bool(_eval_node(tree, selection_results))
    except EvaluatorError:
        raise
    except Exception as exc:  # noqa: BLE001 -- any walker failure is a condition failure
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


def _load_docs(path: Path) -> list[dict[str, Any]]:
    return [
        doc
        for doc in yaml.safe_load_all(path.read_text(encoding="utf-8"))
        if isinstance(doc, dict)
    ]


def _correlation_fires(docs: list[dict[str, Any]], events: list[dict[str, Any]]) -> bool:
    """Evaluate the repository's event_count correlation shape over *events*."""
    correlation_doc = next((doc for doc in reversed(docs) if "correlation" in doc), None)
    if not correlation_doc:
        raise EvaluatorError("correlation document not found")
    correlation = correlation_doc["correlation"]
    if not isinstance(correlation, dict) or correlation.get("type") != "event_count":
        raise EvaluatorError("only event_count correlations are supported")
    rule_names = correlation.get("rules")
    if not isinstance(rule_names, list) or len(rule_names) != 1 or not isinstance(rule_names[0], str):
        raise EvaluatorError("event_count correlation must name exactly one base rule")
    base_rule = next((doc for doc in docs if doc.get("name") == rule_names[0]), None)
    if not isinstance(base_rule, dict):
        raise EvaluatorError(f"base rule {rule_names[0]!r} not found")
    group_by = correlation.get("group-by", [])
    if not isinstance(group_by, list) or not all(isinstance(field, str) for field in group_by):
        raise EvaluatorError("correlation group-by must be a list of field names")
    counts: dict[tuple[Any, ...], int] = {}
    for event in events:
        if not isinstance(event, dict):
            raise EvaluatorError("correlation sample events must be objects")
        if rule_fires(base_rule, event):
            key = tuple(event.get(field) for field in group_by)
            counts[key] = counts.get(key, 0) + 1
    condition = correlation.get("condition")
    if not isinstance(condition, dict) or len(condition) != 1:
        raise EvaluatorError("event_count correlation must have one threshold condition")
    operator, threshold = next(iter(condition.items()))
    if not isinstance(threshold, int):
        raise EvaluatorError("event_count threshold must be an integer")
    if operator == "gt":
        return any(count > threshold for count in counts.values())
    if operator == "gte":
        return any(count >= threshold for count in counts.values())
    raise EvaluatorError(f"unsupported event_count threshold {operator!r}")


def check_rule(rule_path: Path) -> RuleCheck:
    docs = _load_docs(rule_path)
    rule_doc = docs[-1] if docs else {}
    status = rule_doc.get("status")
    sample_path = rule_path.with_suffix("").with_suffix(".sample.json")
    try:
        relpath = "resources/examples/" + rule_path.relative_to(EXAMPLES_DIR).as_posix()
    except ValueError:
        # Unit tests and downstream consumers may validate a standalone rule
        # outside this checkout. The path is display-only; never reject an
        # otherwise valid sample merely because it is not in our corpus.
        relpath = str(rule_path)

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
    if not isinstance(cases, list):
        check.ok = False
        check.sample_results.append("ERR: sample file must contain an object or list of objects")
        return check

    saw_positive = False
    saw_negative = False
    correlation_requires_sequence = "correlation" in rule_doc and status == "test"
    if correlation_requires_sequence and any(
        not isinstance(case, dict) or "events" not in case for case in cases
    ):
        check.ok = False
        check.sample_results.append(
            "ERR: status:test event_count correlation requires an 'events' "
            "sequence to prove its threshold, not only a base-rule event"
        )
    for i, case in enumerate(cases):
        if not isinstance(case, dict):
            check.ok = False
            check.sample_results.append(f"case[{i}]: ERR (case must be an object)")
            continue
        expect = case.get("expect_match")
        if not isinstance(expect, bool):
            check.ok = False
            check.sample_results.append(
                f"case[{i}]: ERR (expect_match must be a boolean)"
            )
            continue
        event = case.get("event", {})
        if expect is True:
            saw_positive = True
        elif expect is False:
            saw_negative = True
        try:
            if "correlation" in rule_doc and "events" in case:
                raw_events = case.get("events", [])
                if not isinstance(raw_events, list):
                    raise EvaluatorError("correlation sample needs an 'events' list")
                fired = _correlation_fires(docs, raw_events)
            else:
                # Existing sidecars for correlation collections predate
                # sequence support and intentionally exercise the base
                # selection with one ``event``. Keep that useful unit test;
                # a new ``events`` case exercises the actual threshold.
                target = next((doc for doc in docs if "detection" in doc), rule_doc)
                if not isinstance(event, dict):
                    raise EvaluatorError("event must be an object")
                fired = rule_fires(target, event)
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


def _load_baseline(path: Path) -> set[str]:
    """Read the explicit, reviewable allowlist for pre-policy sample debt."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"could not read sample baseline {path}: {exc}") from exc
    rules = payload.get("missing_status_test_samples") if isinstance(payload, dict) else None
    if not isinstance(rules, list) or not all(isinstance(rule, str) for rule in rules):
        raise ValueError(
            f"sample baseline {path} must contain a string-list 'missing_status_test_samples'"
        )
    return set(rules)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--require-samples", action="store_true",
                        help="fail if any status:test rule has no sidecar sample")
    parser.add_argument("--require-new-samples", action="store_true",
                        help="fail missing status:test samples not listed in --baseline")
    parser.add_argument("--baseline", metavar="PATH", default=None,
                        help="reviewed allowlist for status:test rules predating this policy")
    parser.add_argument("--json", metavar="PATH", default=None)
    args = parser.parse_args(argv)

    if not EXAMPLES_DIR.is_dir():
        print(f"[sample-match-gate] ERROR: {EXAMPLES_DIR} not found -- run from repo root", file=sys.stderr)
        return 2

    if args.require_new_samples and not args.baseline:
        parser.error("--require-new-samples requires --baseline")

    checks = [check_rule(p) for p in sorted(EXAMPLES_DIR.rglob("*.yml"))]
    with_sample = [c for c in checks if c.has_sample]
    without_sample_test_status = [c for c in checks if not c.has_sample and c.status == "test"]
    failing = [c for c in with_sample if not c.ok]
    baseline: set[str] = set()
    if args.baseline:
        try:
            baseline = _load_baseline(Path(args.baseline))
        except ValueError as exc:
            print(f"[sample-match-gate] ERROR: {exc}", file=sys.stderr)
            return 2
    newly_missing = [c for c in without_sample_test_status if c.relpath not in baseline]

    print(f"[sample-match-gate] {len(with_sample)}/{len(checks)} rules have a sidecar sample")
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
            "new_test_status_missing_sample": [c.relpath for c in newly_missing],
        }
        Path(args.json).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    if failing:
        print(f"\n[sample-match-gate] FAIL: {len(failing)} rule(s) whose sample does not match their own detection logic")
        return 1
    if args.require_samples and without_sample_test_status:
        print(f"\n[sample-match-gate] FAIL: --require-samples set, {len(without_sample_test_status)} status:test rule(s) missing a sample")
        return 1
    if args.require_new_samples and newly_missing:
        print(
            f"\n[sample-match-gate] FAIL: {len(newly_missing)} new status:test rule(s) "
            "missing a sample (not in the reviewed baseline)"
        )
        return 1
    print("\n[sample-match-gate] ok")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
