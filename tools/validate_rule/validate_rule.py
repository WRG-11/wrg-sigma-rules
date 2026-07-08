"""MCP tool: ``mcp__plugin_wrg-sigma-rules_wrg-sigma-rules__validate_rule``.

Two-tier validation:

* **Schema layer** -- structural checks (top-level required fields, type
  shapes, sigma spec vocabulary). Runs without pySigma installed so the
  tool is useful for first-pass review even on a fresh checkout.
* **pySigma layer** -- ``SigmaRule.from_yaml()`` round-trip. Surfaces line
  + column where the parser exposes them.

Plus a small linter producing actionable warnings: missing references,
empty falsepositives block, vague title, MITRE tag shape drift, condition
ambiguity.

Layer 4 gate coverage:
* G1 -- pySigma missing returns an actionable envelope; schema validation
  still runs (graceful degradation).
* G3 -- parse errors surface line + column.
* G4 -- output never echoes raw operator-internal identifiers; the rule
  is re-emitted with redaction placeholders if it contained any.
* G5 -- ASCII-only output.
"""
from __future__ import annotations

import json
import re
from typing import Any

import yaml

_PYSIGMA_INSTALL_HINT = (
    "pip install pysigma pysigma-backend-splunk"
)

_REQUIRED_TOP_LEVEL_FIELDS: tuple[str, ...] = (
    "title",
    "id",
    "logsource",
    "detection",
)

_RECOMMENDED_FIELDS: tuple[str, ...] = (
    "description",
    "references",
    "author",
    "date",
    "falsepositives",
    "level",
    "tags",
)

_VALID_LEVELS: frozenset[str] = frozenset(
    {"informational", "low", "medium", "high", "critical"}
)

_VALID_STATUSES: frozenset[str] = frozenset(
    {"experimental", "test", "stable", "deprecated", "unsupported"}
)

_MITRE_TAG_RE = re.compile(r"^attack\.t\d{4}(?:\.\d{3})?$")
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-"
    r"[0-9a-f]{12}$"
)

# Always-redact -- same redaction pattern set as draft_rule, applied to
# rule body strings before they are echoed back to the caller. Imported
# duplication is intentional: validate_rule MUST be runnable independently.
_REDACT_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"), "<internal-ip>"),
    (
        re.compile(r"\b192\.168\.\d{1,3}\.\d{1,3}\b"),
        "<internal-ip>",
    ),
    (
        re.compile(r"\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b"),
        "<internal-ip>",
    ),
    (
        re.compile(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
        ),
        "<email>",
    ),
    (
        re.compile(
            r"\b[A-Za-z0-9][A-Za-z0-9._-]*\.(corp|internal|lan|local)\b",
            re.IGNORECASE,
        ),
        "<internal-domain>",
    ),
)


def _ascii_safe(text: str) -> str:
    return text.encode("ascii", errors="replace").decode("ascii")


def _redact_string(value: str) -> tuple[str, bool]:
    """Return ``(redacted, was_redacted)`` for a single string value."""
    if not isinstance(value, str):
        return value, False
    redacted = value
    flagged = False
    for pattern, placeholder in _REDACT_PATTERNS:
        if pattern.search(redacted):
            redacted = pattern.sub(placeholder, redacted)
            flagged = True
    return redacted, flagged


def _parse_yaml(yaml_content: str) -> tuple[Any, list[dict[str, Any]]]:
    """Parse YAML; return ``(doc_or_None, schema_errors)``.

    Schema errors include line + column when PyYAML exposes them. Multi-doc
    YAML (``---`` separated) is supported -- only the first document is
    returned; subsequent documents produce a warning-class schema error.
    """
    errors: list[dict[str, Any]] = []
    try:
        docs = list(yaml.safe_load_all(yaml_content))
    except yaml.YAMLError as exc:
        err: dict[str, Any] = {
            "message": _ascii_safe(str(exc)),
            "kind": "yaml_parse",
        }
        mark = getattr(exc, "problem_mark", None)
        if mark is not None:
            err["line"] = getattr(mark, "line", None)
            err["column"] = getattr(mark, "column", None)
        errors.append(err)
        return None, errors
    docs = [d for d in docs if d is not None]
    if not docs:
        errors.append(
            {"message": "YAML document is empty", "kind": "schema"}
        )
        return None, errors
    if len(docs) > 1:
        errors.append(
            {
                "message": (
                    "multi-document YAML detected; only the first "
                    "document is validated"
                ),
                "kind": "schema",
            }
        )
    return docs[0], errors


def _schema_checks(rule: Any) -> list[dict[str, Any]]:
    """Structural schema checks against the parsed rule dict."""
    errors: list[dict[str, Any]] = []
    if not isinstance(rule, dict):
        errors.append(
            {
                "message": (
                    "top-level YAML must be a mapping (sigma rule object)"
                ),
                "kind": "schema",
            }
        )
        return errors

    for field in _REQUIRED_TOP_LEVEL_FIELDS:
        if field not in rule:
            errors.append(
                {
                    "message": f"required field missing: {field}",
                    "kind": "schema",
                    "field": field,
                }
            )

    if "id" in rule and isinstance(rule["id"], str):
        if not _UUID_RE.match(rule["id"].lower()):
            errors.append(
                {
                    "message": (
                        "'id' should be a UUID per sigma spec (got "
                        f"'{_ascii_safe(rule['id'])}')"
                    ),
                    "kind": "schema",
                    "field": "id",
                }
            )

    if "level" in rule:
        level = str(rule["level"]).lower()
        if level not in _VALID_LEVELS:
            errors.append(
                {
                    "message": (
                        f"'level' must be one of {sorted(_VALID_LEVELS)} "
                        f"(got '{_ascii_safe(str(rule['level']))}')"
                    ),
                    "kind": "schema",
                    "field": "level",
                }
            )

    if "status" in rule:
        status = str(rule["status"]).lower()
        if status not in _VALID_STATUSES:
            errors.append(
                {
                    "message": (
                        f"'status' must be one of {sorted(_VALID_STATUSES)} "
                        f"(got '{_ascii_safe(str(rule['status']))}')"
                    ),
                    "kind": "schema",
                    "field": "status",
                }
            )

    if "logsource" in rule and not isinstance(rule["logsource"], dict):
        errors.append(
            {
                "message": "'logsource' must be a mapping",
                "kind": "schema",
                "field": "logsource",
            }
        )

    if "detection" in rule:
        det = rule["detection"]
        if not isinstance(det, dict):
            errors.append(
                {
                    "message": "'detection' must be a mapping",
                    "kind": "schema",
                    "field": "detection",
                }
            )
        elif "condition" not in det:
            errors.append(
                {
                    "message": (
                        "'detection.condition' is required by sigma spec"
                    ),
                    "kind": "schema",
                    "field": "detection.condition",
                }
            )

    return errors


def _linter_warnings(rule: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    """Best-practices linter -- 6 rules covering known SOC pain points.

    Returns ``(warnings, mitre_tags_found)`` -- the caller tuple-unpacks both.
    """
    warnings: list[dict[str, Any]] = []

    title = rule.get("title")
    if isinstance(title, str):
        if len(title) < 5:
            warnings.append(
                {
                    "rule": "title_length",
                    "message": (
                        "title under 5 chars; SOC dashboard rows become "
                        "unreadable"
                    ),
                }
            )
        elif len(title) > 256:
            warnings.append(
                {
                    "rule": "title_length",
                    "message": (
                        "title over 256 chars; truncation risk in SIEM UIs"
                    ),
                }
            )

    description = rule.get("description")
    if not isinstance(description, str) or len(description.strip()) < 10:
        warnings.append(
            {
                "rule": "description_missing",
                "message": (
                    "description missing or under 10 chars; analysts "
                    "cannot reason about the rule"
                ),
            }
        )

    references = rule.get("references")
    if not isinstance(references, list) or not references:
        warnings.append(
            {
                "rule": "references_empty",
                "message": (
                    "references block empty; cite CVE / blog / incident "
                    "URL so the rule is auditable"
                ),
            }
        )

    falsepositives = rule.get("falsepositives")
    if not isinstance(falsepositives, list) or not falsepositives:
        warnings.append(
            {
                "rule": "falsepositives_empty",
                "message": (
                    "falsepositives block empty; top-3 cause of SOC "
                    "alert fatigue per WRG corpus"
                ),
            }
        )

    tags = rule.get("tags")
    mitre_found: list[str] = []
    if isinstance(tags, list):
        for tag in tags:
            if isinstance(tag, str) and _MITRE_TAG_RE.match(tag.lower()):
                mitre_found.append(tag.lower())
    if not mitre_found:
        warnings.append(
            {
                "rule": "mitre_tag_missing",
                "message": (
                    "no 'attack.txxxx' tag detected; MITRE ATT&CK "
                    "mapping is a sigma corpus convention"
                ),
            }
        )

    detection = rule.get("detection")
    if isinstance(detection, dict):
        condition = detection.get("condition")
        if isinstance(condition, str) and condition.strip() in {
            "selection",
            "selection_1",
        }:
            # Bare ``condition: selection`` is the scaffold default --
            # not an error, but flag as a smell so the writer iterates.
            warnings.append(
                {
                    "rule": "condition_default",
                    "message": (
                        "condition is the scaffold default ('selection'); "
                        "consider tightening with filters once the rule "
                        "is field-tested"
                    ),
                }
            )

    return warnings, mitre_found


def _pysigma_validate(yaml_content: str) -> dict[str, Any]:
    """Run pySigma ``SigmaRule.from_yaml`` round-trip.

    On ImportError: returns ``available=False`` envelope (G1). On parse
    failure: surfaces line + column when the underlying exception carries
    them (G3).
    """
    try:
        from sigma.rule import SigmaRule
    except ImportError:
        return {
            "available": False,
            "errors": [
                {
                    "message": (
                        "pySigma not installed; install via: "
                        f"{_PYSIGMA_INSTALL_HINT}"
                    ),
                    "kind": "pysigma_missing",
                    "hint": _PYSIGMA_INSTALL_HINT,
                }
            ],
        }
    errors: list[dict[str, Any]] = []
    try:
        SigmaRule.from_yaml(yaml_content)
    except Exception as exc:
        err: dict[str, Any] = {
            "message": _ascii_safe(str(exc)),
            "kind": "pysigma_parse",
        }
        for attr in ("line", "column"):
            value = getattr(exc, attr, None)
            if value is not None:
                err[attr] = value
        source = getattr(exc, "source", None)
        if source is not None:
            for attr in ("line", "column"):
                value = getattr(source, attr, None)
                if value is not None and attr not in err:
                    err[attr] = value
        errors.append(err)
    return {"available": True, "errors": errors}


def _detect_mitre_coverage(
    rule: dict[str, Any], lint_mitre_tags: list[str]
) -> dict[str, Any]:
    """Extract MITRE ATT&CK coverage from declared tags."""
    techniques: list[str] = []
    seen: set[str] = set()
    for tag in lint_mitre_tags:
        # ``attack.t1059.001`` -> ``T1059.001``
        ttp = tag.replace("attack.", "").upper()
        if ttp not in seen:
            techniques.append(ttp)
            seen.add(ttp)
    return {"techniques": techniques, "count": len(techniques)}


def _redact_rule_dict(rule: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    """Walk the rule dict and redact internal-looking identifiers in values.

    Returns ``(redacted_rule, was_redacted)``. Used to keep operator
    infrastructure out of the response payload (always-redact discipline).
    """
    flagged = False

    def _walk(node: Any) -> Any:
        nonlocal flagged
        if isinstance(node, dict):
            return {k: _walk(v) for k, v in node.items()}
        if isinstance(node, list):
            return [_walk(item) for item in node]
        if isinstance(node, str):
            new_value, was_flagged = _redact_string(node)
            if was_flagged:
                flagged = True
            return new_value
        return node

    return _walk(rule), flagged


def validate_rule_body(
    yaml_content: str,
    *,
    target_backend: str = "default",
    strict: bool = False,
) -> dict[str, Any]:
    """Validate a sigma YAML rule.

    Returns the schema described in ``skills/sigma-rule-reviewer/SKILL.md``:
    ``{valid, schema_errors, pysigma_errors, linter_warnings, mitre_coverage}``.
    ``strict=True`` collapses warnings into the error list (so callers that
    treat warnings as ship-blocking can short-circuit on ``valid``).
    """
    if not isinstance(yaml_content, str) or not yaml_content.strip():
        return {
            "ok": False,
            "error": "yaml_content is required (non-empty string)",
            "hint": (
                "Pass the rule YAML as a string; use Read tool first if "
                "the rule is on disk."
            ),
        }

    parsed, schema_parse_errors = _parse_yaml(yaml_content)
    schema_errors: list[dict[str, Any]] = list(schema_parse_errors)

    linter_warnings: list[dict[str, Any]] = []
    mitre_tags_found: list[str] = []
    mitre_coverage: dict[str, Any] = {"techniques": [], "count": 0}
    redacted_rule: dict[str, Any] | None = None
    redaction_applied = False

    if isinstance(parsed, dict):
        schema_errors.extend(_schema_checks(parsed))
        linter_warnings, mitre_tags_found = _linter_warnings(parsed)
        mitre_coverage = _detect_mitre_coverage(parsed, mitre_tags_found)
        redacted_rule, redaction_applied = _redact_rule_dict(parsed)

    pysigma_result = _pysigma_validate(yaml_content)
    pysigma_errors = pysigma_result.get("errors", [])
    pysigma_available = pysigma_result.get("available", False)

    has_errors = bool(schema_errors) or any(
        e.get("kind") == "pysigma_parse" for e in pysigma_errors
    )

    if strict and linter_warnings:
        # Promote warnings to errors so callers blocking on ``valid``
        # short-circuit on smells too.
        promoted = [
            dict(w, kind="linter_strict") for w in linter_warnings
        ]
        schema_errors.extend(promoted)
        has_errors = True

    valid = not has_errors

    out: dict[str, Any] = {
        "ok": True,
        "valid": valid,
        "schema_errors": schema_errors,
        "pysigma_errors": pysigma_errors,
        "pysigma_available": pysigma_available,
        "linter_warnings": linter_warnings,
        "mitre_coverage": mitre_coverage,
        "target_backend": target_backend,
        "strict": strict,
    }
    if redacted_rule is not None and redaction_applied:
        out["redaction_applied"] = True
        out["redacted_rule_preview"] = redacted_rule
    return out


def register_validate_rule_tool(mcp: Any) -> None:
    """Register the ``validate_rule`` tool on an MCP server."""

    @mcp.tool()
    def validate_rule(
        yaml_content: str,
        target_backend: str = "default",
        strict: bool = False,
    ) -> dict[str, Any]:
        """Validate a sigma YAML rule for schema correctness, pySigma compatibility, and best-practices linting.

        Use when the caller has a sigma rule (drafted, pasted, or
        read from disk) and needs to know whether it is parseable, spec
        compliant, and free of common quality smells (empty references,
        missing falsepositives, missing MITRE tag, vague condition).
        ``target_backend`` is informational at this layer; the linter is
        backend-agnostic. ``strict=True`` promotes warnings into the
        error list.
        """
        return validate_rule_body(
            yaml_content,
            target_backend=target_backend,
            strict=strict,
        )
