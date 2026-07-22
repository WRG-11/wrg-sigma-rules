"""MCP tool: ``mcp__plugin_wrg-sigma-rules_wrg-sigma-rules__convert_rule``.

Sigma YAML -> SIEM-native query string via pySigma backends. Supported
backends (matches the pySigma ecosystem packages declared in the plugin
requirements):

* ``splunk`` -- via ``pysigma-backend-splunk``
* ``elastic`` / ``kibana`` -- via ``pysigma-backend-elasticsearch``
  (Lucene query syntax). Kibana is an alias for the same Lucene backend.
* ``wazuh`` -- via ``pysigma-backend-elasticsearch`` (Wazuh ships with
  Elasticsearch under the hood; same Lucene output is operational with
  caveats noted in the warnings array).

Each backend ships separately on PyPI. Missing backend returns an
actionable envelope including the exact ``pip install`` command.

Design-discipline coverage:
* pySigma missing returns an actionable envelope.
* Backend missing returns an actionable envelope with the specific
  ``pip install`` hint.
* Pre-conversion YAML parse failure surfaces line + column.
* Output redacts internal-looking identifiers before echo.
* ASCII-only output.
"""
from __future__ import annotations

import re
from typing import Any

_PYSIGMA_INSTALL_HINT = (
    "pip install pysigma pysigma-backend-splunk"
)

# Backend registry: ``key -> (loader, install_hint, query_hint)``.
# ``loader`` is a thin callable that imports + constructs the backend on
# demand so missing extras only blow up for the specific call that needs
# them. Each entry returns a (backend_instance, target_label)
# tuple.
_BACKEND_KEYS: tuple[str, ...] = (
    "splunk",
    "elastic",
    "kibana",
    "wazuh",
)


def _ascii_safe(text: str) -> str:
    return text.encode("ascii", errors="replace").decode("ascii")


def _redact_string(value: str) -> tuple[str, bool]:
    """Always-redact -- redact operator-internal identifier shapes in a string."""
    if not isinstance(value, str):
        return value, False
    redacted = value
    flagged = False
    for pattern, placeholder in _REDACT_PATTERNS:
        if pattern.search(redacted):
            redacted = pattern.sub(placeholder, redacted)
            flagged = True
    return redacted, flagged


# Duplicate of the redact pattern set used by draft_rule + validate_rule.
# Kept inline so convert_rule is runnable in isolation (no cross-tool
# import) -- mirrors the canonical_patterns_resource.py "module-isolated"
# convention.
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


def _missing_pysigma_envelope() -> dict[str, Any]:
    """pySigma-missing envelope -- pySigma core missing."""
    return {
        "ok": False,
        "error": "pySigma not installed",
        "hint": (
            f"Install pySigma + backends: {_PYSIGMA_INSTALL_HINT}"
        ),
        "kind": "pysigma_missing",
    }


def _missing_backend_envelope(
    target: str, package: str
) -> dict[str, Any]:
    """Backend-missing envelope -- specific backend missing, actionable hint."""
    return {
        "ok": False,
        "error": f"backend '{target}' not installed",
        "hint": f"pip install {package}",
        "kind": "backend_missing",
        "target": target,
        "missing_package": package,
    }


def _load_backend(target: str) -> tuple[Any, list[str], dict[str, Any] | None]:
    """Construct a pySigma backend instance for ``target``.

    Returns ``(backend, warnings, error_envelope_or_None)``. ``warnings``
    is a list of conversion-lossiness hints specific to the backend.
    """
    warnings: list[str] = []
    target_lc = target.lower()

    if target_lc == "splunk":
        try:
            from sigma.backends.splunk import SplunkBackend
        except ImportError:
            return (
                None,
                warnings,
                _missing_backend_envelope(
                    target_lc, "pysigma-backend-splunk"
                ),
            )
        return SplunkBackend(), warnings, None

    if target_lc in {"elastic", "elasticsearch"}:
        try:
            from sigma.backends.elasticsearch import LuceneBackend
        except ImportError:
            return (
                None,
                warnings,
                _missing_backend_envelope(
                    target_lc, "pysigma-backend-elasticsearch"
                ),
            )
        return LuceneBackend(), warnings, None

    if target_lc == "kibana":
        try:
            from sigma.backends.elasticsearch import LuceneBackend
        except ImportError:
            return (
                None,
                warnings,
                _missing_backend_envelope(
                    target_lc, "pysigma-backend-elasticsearch"
                ),
            )
        warnings.append(
            "kibana target uses the elasticsearch Lucene backend; "
            "wrap the query in Kibana's saved-search UI"
        )
        return LuceneBackend(), warnings, None

    if target_lc == "wazuh":
        try:
            from sigma.backends.elasticsearch import LuceneBackend
        except ImportError:
            return (
                None,
                warnings,
                _missing_backend_envelope(
                    target_lc, "pysigma-backend-elasticsearch"
                ),
            )
        warnings.append(
            "wazuh target routed through the elasticsearch Lucene "
            "backend; review the output against Wazuh decoders before "
            "deploying (no native pySigma wazuh backend yet)"
        )
        return LuceneBackend(), warnings, None

    return (
        None,
        warnings,
        {
            "ok": False,
            "error": f"unknown target backend '{target}'",
            "hint": (
                "supported targets: "
                + ", ".join(_BACKEND_KEYS)
            ),
            "kind": "unknown_target",
        },
    )


def _redact_query(query: str) -> tuple[str, bool]:
    redacted, flagged = _redact_string(query)
    return _ascii_safe(redacted), flagged


def convert_rule_body(
    yaml_content: str,
    *,
    target: str = "splunk",
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Convert a sigma YAML rule to a SIEM-native query string.

    Returns ``{ok, query, target, warnings, metadata}`` on success; on
    failure returns ``{ok: False, error, hint, kind}``. The ``metadata``
    block preserves source rule title + id + level so the caller can
    correlate the query back to the rule (sister convention used by
    the WRG corpus ``observed_*`` rules).

    ``config`` is reserved for future backend-specific options (index name,
    field mappings, etc.) and is currently NOT applied to conversion -- a
    non-empty value is echoed in ``config_used`` and flagged in ``warnings``
    rather than silently dropped.
    """
    if not isinstance(yaml_content, str) or not yaml_content.strip():
        return {
            "ok": False,
            "error": "yaml_content is required (non-empty string)",
            "kind": "input_missing",
        }
    if not isinstance(target, str) or not target.strip():
        return {
            "ok": False,
            "error": "target backend is required (e.g. 'splunk')",
            "hint": (
                "supported targets: " + ", ".join(_BACKEND_KEYS)
            ),
            "kind": "input_missing",
        }

    # Pre-parse via pySigma -- gives the cleanest error envelope (G1+G3).
    # SigmaCollection (not SigmaRule) so a multi-document YAML pairing a
    # base detection rule with a Sigma correlation rule (the modern
    # replacement for the deprecated `condition: X | count() by Y > N in
    # Zm` pipe-aggregation syntax) parses correctly -- SigmaRule.from_yaml
    # rejects a `correlation:` block outright ("Sigma rule must have a log
    # source"). Backward compatible: a plain single-document rule collects
    # into a 1-rule collection and converts identically to before.
    try:
        from sigma.collection import SigmaCollection
    except ImportError:
        return _missing_pysigma_envelope()
    try:
        collection = SigmaCollection.from_yaml(yaml_content)
    except Exception as exc:
        err: dict[str, Any] = {
            "ok": False,
            "error": _ascii_safe(f"sigma rule parse failed: {exc}"),
            "kind": "yaml_parse",
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
        return err

    backend, warnings, backend_err = _load_backend(target)
    if backend_err is not None:
        return backend_err

    try:
        queries = backend.convert(collection)
    except Exception as exc:
        return {
            "ok": False,
            "error": _ascii_safe(
                f"pySigma backend '{target}' conversion failed: {exc}"
            ),
            "kind": "backend_conversion",
        }

    if not queries:
        return {
            "ok": False,
            "error": "backend produced no queries",
            "kind": "empty_output",
        }

    # pySigma backends return a list of strings; pick the first and warn
    # if there are multiple (multi-tier rule).
    primary, primary_flagged = _redact_query(str(queries[0]))
    redaction_applied = primary_flagged
    if len(queries) > 1:
        warnings.append(
            f"backend produced {len(queries)} queries; only the first "
            "is returned -- subsequent queries available via "
            "''alternate_queries''"
        )

    alternate: list[str] = []
    for q in queries[1:]:
        q_redacted, q_flagged = _redact_query(str(q))
        alternate.append(q_redacted)
        if q_flagged:
            redaction_applied = True

    # `config` is not yet wired into backend construction (no backend here
    # takes index names, field mappings, etc. at instantiation time) -- a
    # caller passing a non-empty config would otherwise have it silently
    # ignored, which is exactly the kind of unflagged behavior this corpus's
    # own quality discipline exists to prevent. Surface it honestly instead.
    if config:
        warnings.append(
            "config parameter is currently accepted but not applied to "
            "backend conversion (reserved for future use); the query below "
            "reflects backend defaults only"
        )

    # Pull metadata so callers can correlate query <-> source rule. The
    # LAST rule in the collection is the "primary"/user-facing one: for a
    # plain single-document rule it's the only rule; for a base-rule +
    # correlation-rule pair, sigma convention writes the base rule(s)
    # first and the correlation rule last (it references them by name),
    # so this naturally picks the correlation rule's own title/id/level --
    # not the base rule it merely reuses. SigmaCorrelationRule has no
    # logsource attribute; getattr's default keeps that field absent
    # rather than erroring.
    primary_rule = collection.rules[-1] if collection.rules else None
    metadata: dict[str, Any] = {}
    title = getattr(primary_rule, "title", None)
    if title:
        metadata["title"] = _ascii_safe(str(title))
    rule_id = getattr(primary_rule, "id", None)
    if rule_id:
        metadata["id"] = _ascii_safe(str(rule_id))
    level = getattr(primary_rule, "level", None)
    if level is not None:
        metadata["level"] = _ascii_safe(str(level))
    logsource = getattr(primary_rule, "logsource", None)
    if logsource is not None:
        metadata["logsource"] = _ascii_safe(str(logsource))

    out: dict[str, Any] = {
        "ok": True,
        "query": primary,
        "target": target.lower(),
        "warnings": warnings,
        "metadata": metadata,
        "config_used": config or {},
    }
    if alternate:
        out["alternate_queries"] = alternate
    if redaction_applied:
        out["redaction_applied"] = True
    return out


def register_convert_rule_tool(mcp: Any) -> None:
    """Register the ``convert_rule`` tool on an MCP server."""

    @mcp.tool()
    def convert_rule(
        yaml_content: str,
        target: str = "splunk",
        config: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Convert a sigma YAML rule into a SIEM-native query string.

        Use when the caller has a validated sigma rule and needs the
        equivalent query for Splunk SPL, Elasticsearch / Kibana Lucene,
        or Wazuh. Returns the primary converted query plus conversion
        lossiness warnings (e.g. unsupported modifiers). Missing pySigma
        or missing backend packages return actionable error envelopes
        with the exact pip install command.
        """
        return convert_rule_body(
            yaml_content, target=target, config=config
        )
