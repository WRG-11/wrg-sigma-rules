"""MCP tool: ``mcp__wrg-sigma__draft_rule``.

Builds a sigma YAML detection rule scaffold from a natural-language threat
description plus structured hints (rule_type, target_platform, references,
severity, mitre_ttps). The tool is deterministic: it does NOT call any LLM.
LLM-assisted enrichment is the calling skill's responsibility
(see ``skills/sigma-rule-writer/SKILL.md``).

Design discipline:

* **Layer 4 G1** -- pySigma missing returns an actionable envelope including
  the exact ``pip install`` command. The tool still produces a YAML draft
  (best-effort) so the user can iterate without pySigma installed; only the
  round-trip ``validation`` block is omitted.
* **Layer 4 G3** -- YAML parse failures (post-draft pySigma round-trip)
  surface line + column when the underlying parser exposes them.
* **Layer 4 G4** -- Pattern 34 v1.1 always-redact: the user-supplied
  ``description`` is char-capped + scrubbed for common operator-internal
  identifier shapes (RFC1918 IPs, internal-style hostnames, simple email
  patterns) before being baked into the rule. Replacement placeholders are
  bracketed (``<internal-domain>``) so the operator can clearly see what was
  redacted.
* **Layer 4 G5** -- ASCII-only output (Pattern 33 Rule 5). YAML body is
  re-encoded through ``ascii`` with ``replace`` errors handler before
  return.

Sister R88-52b ``breach_corpus.py`` module-level register pattern;
canonical_patterns_resource.py 2nd application; D R88-52d helper-impl
first-attempt PASS reference.
"""
from __future__ import annotations

import json
import re
import uuid
from datetime import date
from typing import Any

# Layer 4 G4 -- redaction patterns. Applied to the user-supplied description
# BEFORE it is embedded in the YAML body. Kept conservative: only redact
# shapes that look like operator-internal identifiers.
_REDACT_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # RFC1918 + common internal CIDR shapes.
    (re.compile(r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"), "<internal-ip>"),
    (
        re.compile(r"\b192\.168\.\d{1,3}\.\d{1,3}\b"),
        "<internal-ip>",
    ),
    (
        re.compile(r"\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b"),
        "<internal-ip>",
    ),
    # Email -- generic shape; replace local-part + domain wholesale.
    (
        re.compile(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
        ),
        "<email>",
    ),
    # Internal-style hostnames (corp / internal / lan / local suffix).
    (
        re.compile(
            r"\b[A-Za-z0-9][A-Za-z0-9._-]*\.(corp|internal|lan|local)\b",
            re.IGNORECASE,
        ),
        "<internal-domain>",
    ),
)

# Pattern 34 v1.1 cap. Mirrors the 800-char ceiling used by other WRG
# OPSEC LLM-safe consumers (sister R88-51d llm_incident_draft summary cap).
_DESCRIPTION_CAP = 800

# Severity vocabulary -- matches sigma spec ``level:`` field.
_VALID_SEVERITY: frozenset[str] = frozenset(
    {"informational", "low", "medium", "high", "critical"}
)

# Logsource category by rule_type. Conservative defaults; the skill can
# override per-rule. ``rule_type`` value is normalised lowercase before
# lookup.
_RULE_TYPE_TO_LOGSOURCE: dict[str, dict[str, str]] = {
    "process_creation": {
        "category": "process_creation",
        "product": "windows",
    },
    "file_event": {"category": "file_event", "product": "windows"},
    "registry_event": {
        "category": "registry_event",
        "product": "windows",
    },
    "network_connection": {
        "category": "network_connection",
        "product": "windows",
    },
    "authentication": {
        "category": "authentication",
        "product": "windows",
    },
    "dns": {"category": "dns", "product": "windows"},
    "proxy": {"category": "proxy"},
    "webserver": {"category": "webserver"},
    "linux_audit": {"category": "process_creation", "product": "linux"},
    "macos": {"category": "process_creation", "product": "macos"},
    "cloud_audit": {"product": "aws", "service": "cloudtrail"},
}

# MITRE technique ID shape -- ``Txxxx`` or ``Txxxx.yyy``.
_MITRE_TTP_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")

_PYSIGMA_INSTALL_HINT = (
    "pip install pysigma pysigma-backend-splunk"
)


def _ascii_safe(text: str) -> str:
    """Return text re-encoded as ASCII (Pattern 33 Rule 5 / Layer 4 G5)."""
    return text.encode("ascii", errors="replace").decode("ascii")


def _redact_description(description: str) -> tuple[str, list[str]]:
    """Apply Pattern 34 v1.1 always-redact + char cap to user description.

    Returns ``(redacted_text, applied_redactions)``. ``applied_redactions``
    is a list of placeholder labels that were actually substituted at least
    once (useful for the draft_notes block so the operator sees what the
    tool considered sensitive).
    """
    text = description or ""
    applied: list[str] = []
    for pattern, placeholder in _REDACT_PATTERNS:
        if pattern.search(text):
            text = pattern.sub(placeholder, text)
            if placeholder not in applied:
                applied.append(placeholder)
    if len(text) > _DESCRIPTION_CAP:
        text = text[:_DESCRIPTION_CAP].rstrip() + " [TRUNCATED]"
        applied.append("[TRUNCATED]")
    return text, applied


def _slugify(value: str, *, max_len: int = 40) -> str:
    """Lowercase + hyphen slug; ASCII-only; no leading / trailing hyphen."""
    cleaned = re.sub(r"[^A-Za-z0-9]+", "-", value or "").lower()
    cleaned = cleaned.strip("-")
    if not cleaned:
        return "rule"
    return cleaned[:max_len].rstrip("-") or "rule"


def _deterministic_uuid(seed: str) -> str:
    """Stable UUIDv5 from a seed string (so tests are reproducible)."""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"wrg-sigma:{seed}"))


def _detect_mitre_ttps(
    description: str, declared: list[str] | None
) -> list[str]:
    """Extract MITRE ATT&CK technique IDs from declared list + description.

    Declared list wins -- entries are filtered against the ``Txxxx`` /
    ``Txxxx.yyy`` shape and de-duplicated while preserving order. If no
    declared TTPs are present, fall back to a regex scan of the description
    (covers the "user pasted a CVE blog post" case).
    """
    out: list[str] = []
    seen: set[str] = set()
    for raw in declared or []:
        candidate = (raw or "").strip()
        if _MITRE_TTP_RE.match(candidate) and candidate not in seen:
            out.append(candidate)
            seen.add(candidate)
    if out:
        return out
    for match in re.finditer(r"\bT\d{4}(?:\.\d{3})?\b", description or ""):
        candidate = match.group(0)
        if candidate not in seen:
            out.append(candidate)
            seen.add(candidate)
    return out


def _build_logsource(rule_type: str, target_platform: str) -> dict[str, str]:
    """Build the ``logsource:`` block from the typed hints."""
    base = _RULE_TYPE_TO_LOGSOURCE.get(
        rule_type.lower(),
        {"category": "process_creation", "product": "windows"},
    )
    out = dict(base)
    platform = (target_platform or "").lower()
    if platform in {"windows", "linux", "macos"}:
        out["product"] = platform
    elif platform == "network":
        out = {"category": "network_connection"}
    elif platform == "cloud":
        out.setdefault("product", "aws")
        out.setdefault("service", "cloudtrail")
    return out


def _draft_detection_block(
    rule_type: str, target_platform: str
) -> dict[str, Any]:
    """Return a starter ``detection:`` block matching the rule_type.

    Deliberately conservative: a single ``selection`` field with a
    placeholder so the LLM (skill side) can refine. The placeholder uses
    well-known sigma keys for the category so the rule is round-trip
    parseable even before refinement.
    """
    rt = rule_type.lower()
    if rt == "process_creation":
        return {
            "selection": {"Image|endswith": "REPLACE_ME.exe"},
            "condition": "selection",
        }
    if rt == "file_event":
        return {
            "selection": {"TargetFilename|endswith": ".REPLACE_ME"},
            "condition": "selection",
        }
    if rt == "registry_event":
        return {
            "selection": {
                "TargetObject|contains": "\\REPLACE_ME"
            },
            "condition": "selection",
        }
    if rt == "network_connection":
        return {
            "selection": {"DestinationPort": 0},
            "condition": "selection",
        }
    if rt == "authentication":
        return {
            "selection": {"EventID": 4625},
            "condition": "selection",
        }
    if rt == "dns":
        return {
            "selection": {"query|endswith": ".REPLACE_ME.tld"},
            "condition": "selection",
        }
    if rt in {"proxy", "webserver"}:
        return {
            "selection": {"cs-uri-stem|contains": "/REPLACE_ME"},
            "condition": "selection",
        }
    if rt == "cloud_audit":
        return {
            "selection": {"eventName": "REPLACE_ME"},
            "condition": "selection",
        }
    return {"selection": {"REPLACE_ME": "value"}, "condition": "selection"}


def _yaml_dump(payload: dict[str, Any]) -> str:
    """Serialize the rule dict to deterministic YAML.

    Avoids PyYAML's ``default_flow_style`` quirks by hand-emitting a stable
    field order. ASCII-coerced before return (Layer 4 G5).
    """
    lines: list[str] = []
    # Stable, sigma-spec field order.
    field_order = (
        "title",
        "id",
        "status",
        "description",
        "references",
        "author",
        "date",
        "logsource",
        "detection",
        "falsepositives",
        "level",
        "tags",
    )
    for key in field_order:
        if key not in payload:
            continue
        value = payload[key]
        if isinstance(value, list):
            if not value:
                lines.append(f"{key}: []")
                continue
            lines.append(f"{key}:")
            for item in value:
                lines.append(f"  - {item}")
        elif isinstance(value, dict):
            lines.append(f"{key}:")
            for sub_key, sub_value in value.items():
                if isinstance(sub_value, dict):
                    lines.append(f"  {sub_key}:")
                    for k2, v2 in sub_value.items():
                        lines.append(f"    {k2}: {v2}")
                elif isinstance(sub_value, list):
                    lines.append(f"  {sub_key}:")
                    for item in sub_value:
                        lines.append(f"    - {item}")
                else:
                    lines.append(f"  {sub_key}: {sub_value}")
        else:
            # Strings with leading special chars or embedded colons get
            # single-quoted to keep YAML deterministic.
            if isinstance(value, str) and (
                ":" in value or value.startswith(("'", '"', "@", "%", "!"))
            ):
                escaped = value.replace("'", "''")
                lines.append(f"{key}: '{escaped}'")
            else:
                lines.append(f"{key}: {value}")
    body = "\n".join(lines) + "\n"
    return _ascii_safe(body)


def _pysigma_validation(yaml_text: str) -> dict[str, Any]:
    """Round-trip the drafted YAML through pySigma when available.

    Returns ``{"available": bool, "valid": bool, "errors": [...], "hint": ...}``.
    On ImportError: ``available=False`` + actionable G1 envelope. On parse
    failure: ``valid=False`` + structured error (with line + column when the
    parser exposes them; Layer 4 G3).
    """
    try:
        from sigma.rule import SigmaRule
    except ImportError:
        return {
            "available": False,
            "valid": False,
            "errors": [],
            "hint": (
                "pySigma not installed; install via: "
                f"{_PYSIGMA_INSTALL_HINT}"
            ),
        }
    try:
        SigmaRule.from_yaml(yaml_text)
        return {"available": True, "valid": True, "errors": []}
    except Exception as exc:
        # pySigma raises a typed exception hierarchy; we surface the message
        # plus any line / column attributes the parser exposed. Errors are
        # stringified so the envelope is JSON-safe.
        err: dict[str, Any] = {"message": _ascii_safe(str(exc))}
        line = getattr(exc, "source", None)
        if line and hasattr(line, "line"):
            err["line"] = getattr(line, "line", None)
        if line and hasattr(line, "column"):
            err["column"] = getattr(line, "column", None)
        for attr in ("line", "column"):
            value = getattr(exc, attr, None)
            if value is not None and attr not in err:
                err[attr] = value
        return {
            "available": True,
            "valid": False,
            "errors": [err],
        }


def draft_rule_body(
    description: str,
    *,
    rule_type: str = "process_creation",
    references: list[str] | None = None,
    target_platform: str = "windows",
    severity: str = "medium",
    mitre_ttps: list[str] | None = None,
    title: str | None = None,
    author: str = "WRG sigma-rule-writer",
) -> dict[str, Any]:
    """Draft a sigma YAML scaffold from natural-language inputs.

    Returns the schema described in ``skills/sigma-rule-writer/SKILL.md``:
    ``{yaml, validation, mitre_mapping, draft_notes}``. Every string field
    is ASCII-coerced (Layer 4 G5). User-supplied ``description`` runs through
    Pattern 34 v1.1 always-redact + cap (G4).

    Public for testability; do not call MCP machinery here.
    """
    notes: list[str] = []

    if not description or not description.strip():
        return {
            "ok": False,
            "error": "description is required (non-empty string)",
            "hint": (
                "Pass a 1-3 sentence threat description; "
                "the tool will draft a sigma scaffold around it."
            ),
        }

    sev = (severity or "medium").lower()
    if sev not in _VALID_SEVERITY:
        return {
            "ok": False,
            "error": (
                f"severity '{severity}' not in sigma spec vocabulary"
            ),
            "valid_severity": sorted(_VALID_SEVERITY),
        }

    safe_description, applied_redactions = _redact_description(description)
    if applied_redactions:
        notes.append(
            "Pattern 34 v1.1 redactions applied: "
            + ", ".join(applied_redactions)
        )

    inferred_ttps = _detect_mitre_ttps(safe_description, mitre_ttps)

    # Title -- prefer caller-supplied, else build from the first sentence.
    if title:
        rule_title = title
    else:
        first_sentence = safe_description.split(".")[0].strip()
        rule_title = first_sentence[:80] or "Untitled sigma rule"

    slug = _slugify(rule_title)
    rule_id = _deterministic_uuid(slug)
    today = date.today().isoformat()

    logsource = _build_logsource(rule_type, target_platform)
    detection = _draft_detection_block(rule_type, target_platform)

    # Tags: MITRE TTPs + severity convention used by the WRG corpus
    # (sister: ``wrg.severity.<level>`` tag in D R88-56d examples).
    tags: list[str] = []
    for ttp in inferred_ttps:
        tags.append(f"attack.{ttp.lower()}")
    tags.append(f"wrg.severity.{sev}")
    if not inferred_ttps:
        notes.append(
            "No MITRE TTP detected from inputs; consider adding a "
            "'tags:' entry like 'attack.txxxx' before shipping."
        )

    # References block -- empty list is a smell flagged in
    # ``sigma-rule-writer`` Step 5 output discipline. We seed an empty list
    # so pySigma still parses; the skill nudges the user to populate.
    refs = [r for r in (references or []) if r]

    payload: dict[str, Any] = {
        "title": _ascii_safe(rule_title),
        "id": rule_id,
        "status": "experimental",
        "description": _ascii_safe(safe_description),
        "references": refs,
        "author": _ascii_safe(author),
        "date": today,
        "logsource": logsource,
        "detection": detection,
        "falsepositives": ["Unknown"],
        "level": sev,
        "tags": tags,
    }

    yaml_text = _yaml_dump(payload)
    validation = _pysigma_validation(yaml_text)

    if not validation["available"]:
        notes.append(
            "pySigma not available -- the YAML body was emitted but the "
            "validate round-trip was skipped. Install via: "
            f"{_PYSIGMA_INSTALL_HINT}"
        )
    elif not validation["valid"]:
        notes.append(
            "pySigma parse failed on first draft -- inspect "
            "'validation.errors' for line + column."
        )

    return {
        "ok": True,
        "yaml": yaml_text,
        "validation": validation,
        "mitre_mapping": inferred_ttps,
        "draft_notes": notes,
    }


def register_draft_rule_tool(mcp: Any) -> None:
    """Register the ``draft_rule`` tool on an MCP server.

    Sister to ``register_canonical_pattern_resources`` (D R88-52d Resources
    layer; B R88-56b Tools layer 1st application).
    """

    @mcp.tool()
    def draft_rule(
        description: str,
        rule_type: str = "process_creation",
        references: list[str] | None = None,
        target_platform: str = "windows",
        severity: str = "medium",
        mitre_ttps: list[str] | None = None,
        title: str | None = None,
        author: str = "WRG sigma-rule-writer",
    ) -> dict[str, Any]:
        """Draft a sigma detection YAML rule from a natural-language threat description.

        Use when the caller needs a starting-point sigma rule and only has a
        plain-English threat summary plus optional MITRE TTP hints. Returns
        a structured envelope with the YAML body, a pySigma round-trip
        validation result, the inferred MITRE technique IDs, and draft
        notes covering redactions + open issues. Tool is deterministic and
        local -- no network, no LLM call.
        """
        return draft_rule_body(
            description,
            rule_type=rule_type,
            references=references,
            target_platform=target_platform,
            severity=severity,
            mitre_ttps=mitre_ttps,
            title=title,
            author=author,
        )
