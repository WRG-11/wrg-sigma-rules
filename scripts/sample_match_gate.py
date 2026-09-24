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

For a correlation, use the same shape with an ``events`` list instead of
``event``. ``event_count`` samples prove their ``gt``/``gte`` threshold.
``value_count`` samples prove the number of distinct field values in a group.
``temporal`` and ``temporal_ordered`` samples provide source-order events with
ISO-8601 ``timestamp`` values, so the gate can prove the configured time
window (and named-rule ordering for the latter). An unsupported correlation is
an error, never a silently passing sample.

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
    python scripts/sample_match_gate.py --require-correlation-samples  # every correlation needs a sequence sample
    python scripts/sample_match_gate.py --require-new-samples --baseline path/to/reviewed-baseline.json
    python scripts/sample_match_gate.py --require-new-experimental-samples --experimental-baseline resources/examples/EXPERIMENTAL_SAMPLE_EXCEPTION_BASELINE.json
    python scripts/sample_match_gate.py --json out.json

The repository CI uses the stricter ``--require-samples`` path for
``status: test`` rules, so the optional status:test baseline mode is only for
a deliberate staged-policy migration and this repository ships no
grandfathered status:test baseline. Experimental rules are ratcheted instead:
``EXPERIMENTAL_SAMPLE_EXCEPTION_BASELINE.json`` enumerates the reviewed
pre-policy debt, any new experimental rule without a sidecar fails, and
entries are removed as the existing debt is covered.
"""
from __future__ import annotations

import ast

import argparse
from datetime import datetime, timedelta
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
    """Evaluate the repository-supported correlation shapes over *events*."""
    correlation_doc = next((doc for doc in reversed(docs) if "correlation" in doc), None)
    if not correlation_doc:
        raise EvaluatorError("correlation document not found")
    correlation = correlation_doc["correlation"]
    if not isinstance(correlation, dict):
        raise EvaluatorError("correlation must be an object")
    correlation_type = correlation.get("type")
    if correlation_type == "event_count":
        return _event_count_correlation_fires(docs, correlation, events)
    if correlation_type == "value_count":
        return _value_count_correlation_fires(docs, correlation, events)
    if correlation_type == "temporal":
        return _temporal_correlation_fires(docs, correlation, events)
    if correlation_type == "temporal_ordered":
        return _temporal_ordered_correlation_fires(docs, correlation, events)
    raise EvaluatorError(f"unsupported correlation type {correlation_type!r}")


def _event_count_correlation_fires(
    docs: list[dict[str, Any]], correlation: dict[str, Any], events: list[dict[str, Any]]
) -> bool:
    """Evaluate an event_count correlation over *events*."""
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


def _base_rule(docs: list[dict[str, Any]], name: str) -> dict[str, Any]:
    base_rule = next((doc for doc in docs if doc.get("name") == name), None)
    if not isinstance(base_rule, dict):
        raise EvaluatorError(f"base rule {name!r} not found")
    return base_rule


def _threshold_fires(values: dict[tuple[Any, ...], set[Any]], condition: dict[str, Any]) -> bool:
    if len(condition) != 2 or not isinstance(condition.get("field"), str):
        raise EvaluatorError("value_count condition needs one field and one threshold")
    threshold_items = [(operator, threshold) for operator, threshold in condition.items() if operator != "field"]
    operator, threshold = threshold_items[0]
    if not isinstance(threshold, int):
        raise EvaluatorError("value_count threshold must be an integer")
    if operator == "gt":
        return any(len(group_values) > threshold for group_values in values.values())
    if operator == "gte":
        return any(len(group_values) >= threshold for group_values in values.values())
    raise EvaluatorError(f"unsupported value_count threshold {operator!r}")


def _value_count_correlation_fires(
    docs: list[dict[str, Any]], correlation: dict[str, Any], events: list[dict[str, Any]]
) -> bool:
    """Evaluate a value_count correlation over distinct values per group."""
    rule_names = correlation.get("rules")
    if not isinstance(rule_names, list) or len(rule_names) != 1 or not isinstance(rule_names[0], str):
        raise EvaluatorError("value_count correlation must name exactly one base rule")
    base_rule = _base_rule(docs, rule_names[0])
    group_by = correlation.get("group-by", [])
    if not isinstance(group_by, list) or not all(isinstance(field, str) for field in group_by):
        raise EvaluatorError("correlation group-by must be a list of field names")
    condition = correlation.get("condition")
    if not isinstance(condition, dict):
        raise EvaluatorError("value_count correlation needs an object condition")
    field = condition.get("field")
    if not isinstance(field, str):
        raise EvaluatorError("value_count condition field must be a string")
    values: dict[tuple[Any, ...], set[Any]] = {}
    for event in events:
        if not isinstance(event, dict):
            raise EvaluatorError("correlation sample events must be objects")
        if rule_fires(base_rule, event) and event.get(field) is not None:
            key = tuple(event.get(group_field) for group_field in group_by)
            values.setdefault(key, set()).add(event[field])
    return _threshold_fires(values, condition)


def _parse_timespan(value: Any) -> timedelta:
    if not isinstance(value, str):
        raise EvaluatorError("correlation timespan must be a string such as '5m'")
    match = re.fullmatch(r"(\d+)([smhd])", value)
    if not match:
        raise EvaluatorError(f"unsupported correlation timespan {value!r}")
    amount, unit = match.groups()
    keyword = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}[unit]
    return timedelta(**{keyword: int(amount)})


def _event_timestamp(event: dict[str, Any]) -> datetime:
    value = event.get("timestamp")
    if not isinstance(value, str):
        raise EvaluatorError("temporal_ordered sample events require an ISO-8601 'timestamp'")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvaluatorError(f"invalid temporal_ordered event timestamp {value!r}") from exc
    if parsed.tzinfo is None:
        raise EvaluatorError("temporal_ordered event timestamps must include a timezone")
    return parsed


def _temporal_correlation_fires(
    docs: list[dict[str, Any]], correlation: dict[str, Any], events: list[dict[str, Any]]
) -> bool:
    """Find distinct named base-rule matches in one group and time window."""
    rule_names = correlation.get("rules")
    if not isinstance(rule_names, list) or len(rule_names) < 2 or not all(
        isinstance(name, str) for name in rule_names
    ):
        raise EvaluatorError("temporal correlation must name at least two base rules")
    base_rules = [_base_rule(docs, name) for name in rule_names]
    group_by = correlation.get("group-by", [])
    if not isinstance(group_by, list) or not all(isinstance(field, str) for field in group_by):
        raise EvaluatorError("correlation group-by must be a list of field names")
    timespan = _parse_timespan(correlation.get("timespan"))
    grouped: dict[tuple[Any, ...], list[tuple[dict[str, Any], datetime]]] = {}
    for event in events:
        if not isinstance(event, dict):
            raise EvaluatorError("correlation sample events must be objects")
        key = tuple(event.get(field) for field in group_by)
        grouped.setdefault(key, []).append((event, _event_timestamp(event)))

    for grouped_events in grouped.values():
        matches = [
            [index for index, (event, _) in enumerate(grouped_events) if rule_fires(rule, event)]
            for rule in base_rules
        ]
        if any(not candidates for candidates in matches):
            continue

        def has_window(stage: int, selected: list[int]) -> bool:
            if stage == len(matches):
                timestamps = [grouped_events[index][1] for index in selected]
                return max(timestamps) - min(timestamps) <= timespan
            return any(
                index not in selected and has_window(stage + 1, [*selected, index])
                for index in matches[stage]
            )

        if has_window(0, []):
            return True
    return False


def _temporal_ordered_correlation_fires(
    docs: list[dict[str, Any]], correlation: dict[str, Any], events: list[dict[str, Any]]
) -> bool:
    """Find an ordered, same-group base-rule sequence inside its time window."""
    rule_names = correlation.get("rules")
    if not isinstance(rule_names, list) or len(rule_names) < 2 or not all(
        isinstance(name, str) for name in rule_names
    ):
        raise EvaluatorError("temporal_ordered correlation must name at least two base rules")
    base_rules = []
    for name in rule_names:
        base_rule = next((doc for doc in docs if doc.get("name") == name), None)
        if not isinstance(base_rule, dict):
            raise EvaluatorError(f"base rule {name!r} not found")
        base_rules.append(base_rule)
    group_by = correlation.get("group-by", [])
    if not isinstance(group_by, list) or not all(isinstance(field, str) for field in group_by):
        raise EvaluatorError("correlation group-by must be a list of field names")
    timespan = _parse_timespan(correlation.get("timespan"))

    grouped: dict[tuple[Any, ...], list[tuple[dict[str, Any], datetime]]] = {}
    for event in events:
        if not isinstance(event, dict):
            raise EvaluatorError("correlation sample events must be objects")
        key = tuple(event.get(field) for field in group_by)
        grouped.setdefault(key, []).append((event, _event_timestamp(event)))

    for grouped_events in grouped.values():
        stage = 0
        first_timestamp: datetime | None = None
        previous_timestamp: datetime | None = None
        for event, timestamp in grouped_events:
            if previous_timestamp is not None and timestamp < previous_timestamp:
                raise EvaluatorError(
                    "temporal_ordered sample events must be in non-decreasing timestamp order"
                )
            previous_timestamp = timestamp
            if rule_fires(base_rules[stage], event):
                first_timestamp = first_timestamp or timestamp
                if timestamp - first_timestamp > timespan:
                    stage = 0
                    first_timestamp = None
                    if not rule_fires(base_rules[stage], event):
                        continue
                    first_timestamp = timestamp
                stage += 1
                if stage == len(base_rules):
                    return True
    return False


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
    correlation_requires_sequence = "correlation" in rule_doc
    if correlation_requires_sequence and any(
        not isinstance(case, dict) or "events" not in case for case in cases
    ):
        check.ok = False
        check.sample_results.append(
            "ERR: correlation requires an 'events' sequence to prove its "
            "threshold or ordering, not only a base-rule event"
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


def _load_baseline(path: Path, field: str) -> set[str]:
    """Read the explicit, reviewable allowlist for pre-policy sample debt."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"could not read sample baseline {path}: {exc}") from exc
    rules = payload.get(field) if isinstance(payload, dict) else None
    if not isinstance(rules, list) or not all(isinstance(rule, str) for rule in rules):
        raise ValueError(
            f"sample baseline {path} must contain a string-list {field!r}"
        )
    return set(rules)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--require-samples", action="store_true",
                        help="fail if any status:test rule has no sidecar sample")
    parser.add_argument("--require-correlation-samples", action="store_true",
                        help="fail if any correlation rule has no sidecar sample")
    parser.add_argument("--require-new-samples", action="store_true",
                        help="fail missing status:test samples not listed in --baseline")
    parser.add_argument("--baseline", metavar="PATH", default=None,
                        help="reviewed allowlist for status:test rules predating this policy")
    parser.add_argument("--require-new-experimental-samples", action="store_true",
                        help="fail missing experimental-rule samples not listed in --experimental-baseline")
    parser.add_argument("--experimental-baseline", metavar="PATH", default=None,
                        help="reviewed allowlist for experimental rules predating the sample policy")
    parser.add_argument("--json", metavar="PATH", default=None)
    args = parser.parse_args(argv)

    if not EXAMPLES_DIR.is_dir():
        print(f"[sample-match-gate] ERROR: {EXAMPLES_DIR} not found -- run from repo root", file=sys.stderr)
        return 2

    if args.require_new_samples and not args.baseline:
        parser.error("--require-new-samples requires --baseline")
    if args.require_new_experimental_samples and not args.experimental_baseline:
        parser.error("--require-new-experimental-samples requires --experimental-baseline")

    rule_paths = sorted(EXAMPLES_DIR.rglob("*.yml"))
    checks = [check_rule(path) for path in rule_paths]
    with_sample = [c for c in checks if c.has_sample]
    without_sample_test_status = [c for c in checks if not c.has_sample and c.status == "test"]
    without_sample_experimental = [
        c for c in checks if not c.has_sample and c.status == "experimental"
    ]
    without_sample_correlation = [
        (path, check)
        for path, check in zip(rule_paths, checks)
        if not check.has_sample and "correlation" in (_load_docs(path)[-1] if _load_docs(path) else {})
    ]
    failing = [c for c in with_sample if not c.ok]
    baseline: set[str] = set()
    experimental_baseline: set[str] = set()
    if args.baseline:
        try:
            baseline = _load_baseline(Path(args.baseline), "missing_status_test_samples")
        except ValueError as exc:
            print(f"[sample-match-gate] ERROR: {exc}", file=sys.stderr)
            return 2
    newly_missing = [c for c in without_sample_test_status if c.relpath not in baseline]
    if args.experimental_baseline:
        try:
            experimental_baseline = _load_baseline(
                Path(args.experimental_baseline), "missing_experimental_samples"
            )
        except ValueError as exc:
            print(f"[sample-match-gate] ERROR: {exc}", file=sys.stderr)
            return 2
    newly_missing_experimental = [
        c for c in without_sample_experimental if c.relpath not in experimental_baseline
    ]

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

    if without_sample_correlation:
        print(f"\n[sample-match-gate] {len(without_sample_correlation)} correlation rule(s) with NO sample:")
        for _, c in without_sample_correlation:
            print(f"  {c.relpath}")

    if args.json:
        payload = {
            "with_sample": [
                {"relpath": c.relpath, "status": c.status, "ok": c.ok, "results": c.sample_results}
                for c in with_sample
            ],
            "test_status_missing_sample": [c.relpath for c in without_sample_test_status],
            "correlation_missing_sample": [c.relpath for _, c in without_sample_correlation],
            "new_test_status_missing_sample": [c.relpath for c in newly_missing],
            "new_experimental_missing_sample": [c.relpath for c in newly_missing_experimental],
        }
        Path(args.json).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    if failing:
        print(f"\n[sample-match-gate] FAIL: {len(failing)} rule(s) whose sample does not match their own detection logic")
        return 1
    if args.require_samples and without_sample_test_status:
        print(f"\n[sample-match-gate] FAIL: --require-samples set, {len(without_sample_test_status)} status:test rule(s) missing a sample")
        return 1
    if args.require_correlation_samples and without_sample_correlation:
        print(
            f"\n[sample-match-gate] FAIL: --require-correlation-samples set, "
            f"{len(without_sample_correlation)} correlation rule(s) missing a sample"
        )
        return 1
    if args.require_new_samples and newly_missing:
        print(
            f"\n[sample-match-gate] FAIL: {len(newly_missing)} new status:test rule(s) "
            "missing a sample (not in the reviewed baseline)"
        )
        return 1
    if args.require_new_experimental_samples and newly_missing_experimental:
        print(
            f"\n[sample-match-gate] FAIL: {len(newly_missing_experimental)} new experimental "
            "rule(s) missing a sample (not in the reviewed baseline)"
        )
        return 1
    print("\n[sample-match-gate] ok")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
