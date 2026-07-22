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
# Versions 1-8 (RFC 4122 + RFC 9562 UUIDv6/v7/v8) share the same variant
# nibble encoding; the nil UUID (all zeros) is RFC 4122's one explicit
# exception and is accepted as an alternate branch.
_UUID_RE = re.compile(
    r"^(?:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-"
    r"[0-9a-f]{12}|00000000-0000-0000-0000-000000000000)$"
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


_MAX_YAML_INPUT_BYTES = 256 * 1024  # plain-oversized-input guard


class _AnchorAliasDetectingLoader(yaml.SafeLoader):
    """SafeLoader that records whether the document used any ``&anchor``
    or ``*alias``, without altering parse behaviour.

    ``Composer.compose_document`` resets ``self.anchors`` back to ``{}``
    once a document finishes composing (anchors are per-document scope),
    so checking ``loader.anchors`` after the fact always reads empty --
    the sighting has to be recorded as it happens via this hook instead.
    """

    def __init__(self, stream: Any) -> None:
        super().__init__(stream)
        self.saw_anchor_or_alias = False

    def compose_node(self, parent: Any, index: Any) -> Any:
        event = self.peek_event()
        if getattr(event, "anchor", None) or isinstance(event, yaml.events.AliasEvent):
            self.saw_anchor_or_alias = True
        return super().compose_node(parent, index)


def _contains_yaml_anchor_or_alias(yaml_content: str) -> bool:
    """Return True if any YAML document in ``yaml_content`` uses anchors/aliases.

    Sigma rules have no legitimate need for YAML anchors/aliases. PyYAML
    resolves an alias to the SAME constructed Python object as its anchor
    (reference-sharing, not a copy) -- parsing itself stays fast even at
    absurd logical nesting depth (empirically: a <1KB document expressing
    10^12 logical list elements parses in under a millisecond). The
    exponential blowup instead hits ANY code that later walks/serializes
    that graph without reference-awareness (this module's own redaction
    walk, JSON serialization of the response, etc.) -- a byte-size cap on
    the source text does not bound that at all. Rejecting anchor/alias
    syntax outright avoids the whole downstream risk class.
    """
    loader = _AnchorAliasDetectingLoader(yaml_content)
    try:
        while loader.check_data():
            loader.get_data()
    finally:
        loader.dispose()
    return loader.saw_anchor_or_alias


_CORRELATION_KEY_RE = re.compile(r"^correlation\s*:", re.MULTILINE)


def _looks_like_correlation_collection(yaml_content: str) -> bool:
    """Cheap heuristic: does *yaml_content* contain a top-level
    ``correlation:`` key anywhere (i.e. a Sigma correlation rule document)?

    Used to decide whether a multi-document YAML is a genuine base-rule +
    correlation-rule pairing (every document matters, must all reach
    pySigma) versus generic multi-doc noise (only doc[0] matters, see
    ``_parse_yaml``'s ``multi_doc`` notice). A false positive here just
    means the full ``yaml_content`` reaches ``SigmaCollection.from_yaml``
    instead of a doc[0]-only re-serialization -- SigmaCollection parses a
    plain multi-doc, non-correlation stream fine too, so this is safe to
    over-trigger, never unsafe.
    """
    return bool(_CORRELATION_KEY_RE.search(yaml_content))


def _parse_yaml(yaml_content: str) -> tuple[Any, list[dict[str, Any]]]:
    """Parse YAML; return ``(doc_or_None, schema_errors)``.

    Schema errors include line + column when PyYAML exposes them. Multi-doc
    YAML (``---`` separated) is supported -- only the first document is
    returned; subsequent documents produce a ``multi_doc`` notice that does
    not by itself flip the caller's ``valid`` flag to False.

    Two DoS guards run before the real parse: a byte-size cap (plain
    oversized input) and an anchor/alias rejection (billion-laughs --
    see ``_contains_yaml_anchor_or_alias``). Deeply-nested-but-alias-free
    documents can still blow Python's recursion limit inside the YAML
    parser itself; that is caught separately as ``RecursionError`` below.
    """
    errors: list[dict[str, Any]] = []
    content_bytes = len(yaml_content.encode("utf-8", errors="replace"))
    if content_bytes > _MAX_YAML_INPUT_BYTES:
        errors.append(
            {
                "message": (
                    f"YAML input too large ({content_bytes} bytes > "
                    f"{_MAX_YAML_INPUT_BYTES} byte cap); rejected before parsing"
                ),
                "kind": "input_too_large",
            }
        )
        return None, errors
    # Both the anchor/alias scan and the real parse below walk the document
    # via PyYAML's (recursive) composer, so a deeply-nested-but-alias-free
    # document can raise RecursionError from EITHER call -- one shared
    # handler covers both rather than duplicating the except-clause.
    try:
        if _contains_yaml_anchor_or_alias(yaml_content):
            errors.append(
                {
                    "message": (
                        "YAML anchors/aliases (&name / *name) are not "
                        "accepted -- sigma rules have no legitimate use for "
                        "them and they enable alias-expansion "
                        "('billion laughs') DoS"
                    ),
                    "kind": "yaml_alias_rejected",
                }
            )
            return None, errors
        docs = list(yaml.safe_load_all(yaml_content))
    except RecursionError:
        errors.append(
            {
                "message": "YAML nesting too deep to parse safely (RecursionError)",
                "kind": "yaml_parse",
            }
        )
        return None, errors
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
                "kind": "multi_doc",
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

    if "id" in rule:
        if not isinstance(rule["id"], str):
            errors.append(
                {
                    "message": (
                        "'id' must be a string UUID per sigma spec (got "
                        f"{type(rule['id']).__name__})"
                    ),
                    "kind": "schema",
                    "field": "id",
                }
            )
        elif not _UUID_RE.match(rule["id"].lower()):
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
        if isinstance(condition, str) and "|" in condition:
            # A literal pipe INSIDE the condition string (not a field
            # modifier like ``Image|endswith``, which lives in the
            # selection block, never in ``condition:``) is the
            # pre-correlation-rule aggregation syntax, e.g.
            # ``selection | count() by Image > 20 in 5m``. SigmaRule.
            # from_yaml() parses it without complaint, so validate_rule
            # otherwise reports valid=true -- but every pySigma backend
            # rejects it at conversion time ("pipe syntax ... deprecated
            # ... replaced by Sigma correlations"), live-verified against
            # 8 real corpus rules using exactly this pattern. Warn here so
            # a schema-valid rule isn't silently unconvertible.
            warnings.append(
                {
                    "rule": "deprecated_pipe_condition",
                    "message": (
                        "condition contains a '|' aggregation pipe "
                        "(pre-correlation-rule syntax); every pySigma "
                        "backend (Splunk/Elastic/...) rejects this at "
                        "conversion time even though it parses -- migrate "
                        "the count()/aggregation logic to a separate "
                        "Sigma correlation rule (see the sigma spec's "
                        "'correlations' feature)"
                    ),
                }
            )

    return warnings, mitre_found


def _pysigma_validate(yaml_content: str) -> dict[str, Any]:
    """Run a pySigma ``SigmaCollection.from_yaml`` round-trip.

    SigmaCollection (not SigmaRule) so a multi-document YAML pairing a base
    detection rule with a Sigma correlation rule -- the modern replacement
    for the deprecated ``condition: X | count() by Y > N in Zm`` pipe
    syntax (see ``deprecated_pipe_condition`` linter warning above) --
    parses correctly. ``SigmaRule.from_yaml`` rejects a ``correlation:``
    block outright ("Sigma rule must have a log source"). Backward
    compatible: a plain single-document rule collects into a 1-rule
    collection and validates identically to before.

    On ImportError: returns ``available=False`` envelope (G1). On parse
    failure: surfaces line + column when the underlying exception carries
    them (G3).
    """
    try:
        from sigma.collection import SigmaCollection
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
        SigmaCollection.from_yaml(yaml_content)
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

    # _pysigma_validate now uses SigmaCollection (multi-doc-aware), so a
    # genuine base-rule + correlation-rule pairing gets the FULL original
    # yaml_content -- every document matters, the correlation rule (often
    # doc[1]) must actually reach pySigma, not just doc[0]. Generic
    # multi-doc noise (no correlation: block; e.g. a stray/incomplete
    # second document) keeps the established, tested behaviour: only
    # doc[0] is re-serialized and validated, consistent with
    # _parse_yaml's own "only the first document is validated" schema-
    # layer notice above -- so a broken/irrelevant trailing document can't
    # force pysigma_errors non-empty for a reason unrelated to doc[0].
    pysigma_input = yaml_content
    if (
        isinstance(parsed, dict)
        and any(e.get("kind") == "multi_doc" for e in schema_parse_errors)
        and not _looks_like_correlation_collection(yaml_content)
    ):
        pysigma_input = yaml.safe_dump(parsed, sort_keys=False)
    pysigma_result = _pysigma_validate(pysigma_input)
    pysigma_errors = pysigma_result.get("errors", [])
    pysigma_available = pysigma_result.get("available", False)

    # "multi_doc" is a notice, not a hard error: doc[0] can still be valid
    # even though the input contained trailing YAML documents.
    has_errors = any(
        e.get("kind") != "multi_doc" for e in schema_errors
    ) or any(
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
