"""MCP tool: ``mcp__plugin_wrg-sigma-rules_wrg-sigma-rules__convert_rule``.

Sigma YAML -> SIEM-native query string via pySigma backends. Supported
backends (matches the pySigma ecosystem packages declared in the plugin
requirements):

* ``splunk`` -- via ``pysigma-backend-splunk``
* ``elastic`` / ``elasticsearch`` / ``kibana`` -- via
  ``pysigma-backend-elasticsearch`` (Lucene query syntax). Kibana is an
  alias for the same Lucene backend.
* ``wazuh`` -- via ``pysigma-backend-elasticsearch`` (Wazuh ships with
  Elasticsearch under the hood; same Lucene output is operational with
  caveats noted in the warnings array).
* ``opensearch`` / ``opensearch-ppl`` -- via ``pysigma-backend-opensearch``
  (Lucene and Piped Processing Language respectively).

Each backend ships separately on PyPI. Missing backend returns an
actionable envelope including the exact ``pip install`` command.

**Processing pipelines.** A Sigma rule is written against abstract
logsource taxonomy (``category: process_creation``), not against a
specific product's field names or event ids. Translating that taxonomy to
what a SIEM actually stores is the job of a pySigma *processing
pipeline*. Without one, the emitted query keeps the field names but drops
the event selection entirely -- a ``process_creation`` rule converts to a
query matching ``Image`` on *any* event carrying that field, not just
process-creation events. Pass ``config={"pipeline": "sysmon"}`` (or a
list) to apply one; the difference is visible in the output (``EventID=1``
appears only with the sysmon pipeline). Pipelines ship as their own PyPI
packages and are imported lazily, so a missing one fails only the call
that asked for it.

Design-discipline coverage:
* pySigma missing returns an actionable envelope.
* Backend missing returns an actionable envelope with the specific
  ``pip install`` hint.
* Pipeline missing / unknown returns its own actionable envelope rather
  than silently converting without the pipeline the caller asked for.
* Pre-conversion YAML parse failure surfaces line + column.
* Output redacts internal-looking identifiers before echo.
* ASCII-only output.
"""
from __future__ import annotations

import importlib
import re
from typing import Any

_PYSIGMA_INSTALL_HINT = (
    "pip install pysigma pysigma-backend-splunk"
)

# Backend registry: ``key -> (module, attribute, pip package, caveat)``.
# Declared as data rather than an if-chain so adding a backend is one row
# and the supported-target list cannot drift from what _load_backend
# actually accepts -- 'elasticsearch' used to be accepted by the chain but
# missing from the advertised keys, so the error hint hid a working target.
# The module/attribute pair is imported lazily (see _load_backend), so a
# missing extra only fails the call that asked for that specific backend.
_BACKEND_SPECS: dict[str, tuple[str, str, str, str | None]] = {
    "splunk": (
        "sigma.backends.splunk",
        "SplunkBackend",
        "pysigma-backend-splunk",
        None,
    ),
    "elastic": (
        "sigma.backends.elasticsearch",
        "LuceneBackend",
        "pysigma-backend-elasticsearch",
        None,
    ),
    "elasticsearch": (
        "sigma.backends.elasticsearch",
        "LuceneBackend",
        "pysigma-backend-elasticsearch",
        None,
    ),
    "kibana": (
        "sigma.backends.elasticsearch",
        "LuceneBackend",
        "pysigma-backend-elasticsearch",
        "kibana target uses the elasticsearch Lucene backend; "
        "wrap the query in Kibana's saved-search UI",
    ),
    "wazuh": (
        "sigma.backends.elasticsearch",
        "LuceneBackend",
        "pysigma-backend-elasticsearch",
        "wazuh target routed through the elasticsearch Lucene "
        "backend; review the output against Wazuh decoders before "
        "deploying (no native pySigma wazuh backend yet)",
    ),
    "opensearch": (
        "sigma.backends.opensearch",
        "OpensearchLuceneBackend",
        "pysigma-backend-opensearch",
        None,
    ),
    "opensearch-ppl": (
        "sigma.backends.opensearch",
        "OpenSearchPPLBackend",
        "pysigma-backend-opensearch",
        "opensearch-ppl emits Piped Processing Language, not Lucene; "
        "it is not interchangeable with the 'opensearch' target",
    ),
}

_BACKEND_KEYS: tuple[str, ...] = tuple(_BACKEND_SPECS)

# Processing-pipeline registry: ``key -> (module, factory, pip package)``.
# The factory is a zero-argument callable returning a ProcessingPipeline.
_PIPELINE_SPECS: dict[str, tuple[str, str, str]] = {
    "sysmon": (
        "sigma.pipelines.sysmon",
        "sysmon_pipeline",
        "pysigma-pipeline-sysmon",
    ),
    "windows": (
        "sigma.pipelines.windows",
        "windows_logsource_pipeline",
        "pysigma-pipeline-windows",
    ),
    "windows-audit": (
        "sigma.pipelines.windows",
        "windows_audit_pipeline",
        "pysigma-pipeline-windows",
    ),
}

_PIPELINE_KEYS: tuple[str, ...] = tuple(_PIPELINE_SPECS)

# Targets that can express sigma correlation rules, measured against the
# installed backends on 2026-07-29 by converting all 76 corpus rules to each:
# splunk and opensearch-ppl succeeded on all 76; elastic and opensearch
# (Lucene) failed on the same 10 -- every correlation rule in the corpus.
# kibana and wazuh route through the elasticsearch Lucene backend, so they
# share that limit. Re-measure rather than trust this list if a backend
# package is upgraded; it is a snapshot of what those versions could do.
_CORRELATION_CAPABLE_TARGETS: tuple[str, ...] = ("splunk", "opensearch-ppl")

# Config keys convert_rule actually acts on. Anything else is echoed back
# and flagged rather than silently ignored.
_RECOGNISED_CONFIG_KEYS: frozenset[str] = frozenset({"pipeline"})


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


def _normalise_pipelines(raw: Any) -> tuple[list[str], dict[str, Any] | None]:
    """Normalise a ``config["pipeline"]`` value to a list of pipeline keys.

    Accepts a single string or a list of strings; anything else is a
    caller error and returns an envelope rather than being coerced.
    """
    if raw is None:
        return [], None
    names = [raw] if isinstance(raw, str) else raw
    if not isinstance(names, (list, tuple)) or not all(
        isinstance(n, str) for n in names
    ):
        return [], {
            "ok": False,
            "error": "config['pipeline'] must be a string or list of strings",
            "hint": "known pipelines: " + ", ".join(_PIPELINE_KEYS),
            "kind": "invalid_pipeline",
        }
    return [n.strip().lower() for n in names if n.strip()], None


def _load_pipeline(names: list[str]) -> tuple[Any, dict[str, Any] | None]:
    """Build a combined ProcessingPipeline from ``names``.

    Returns ``(pipeline_or_None, error_envelope_or_None)``. Multiple
    pipelines are combined with pySigma's own ``+`` operator, which
    concatenates their processing items in the given order.
    """
    combined: Any = None
    for name in names:
        spec = _PIPELINE_SPECS.get(name)
        if spec is None:
            return None, {
                "ok": False,
                "error": f"unknown processing pipeline '{name}'",
                "hint": "known pipelines: " + ", ".join(_PIPELINE_KEYS),
                "kind": "unknown_pipeline",
            }
        module_name, factory_name, package = spec
        try:
            module = importlib.import_module(module_name)
        except ImportError:
            return None, {
                "ok": False,
                "error": f"processing pipeline '{name}' not installed",
                "hint": f"pip install {package}",
                "kind": "pipeline_missing",
                "pipeline": name,
                "missing_package": package,
            }
        pipeline = getattr(module, factory_name)()
        combined = pipeline if combined is None else combined + pipeline
    return combined, None


def _load_backend(
    target: str, pipeline: Any = None
) -> tuple[Any, list[str], dict[str, Any] | None]:
    """Construct a pySigma backend instance for ``target``.

    Returns ``(backend, warnings, error_envelope_or_None)``. ``warnings``
    is a list of conversion-lossiness hints specific to the backend.
    ``pipeline`` is an already-constructed ProcessingPipeline (or None).
    """
    warnings: list[str] = []
    target_lc = target.lower()

    spec = _BACKEND_SPECS.get(target_lc)
    if spec is None:
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

    module_name, attribute, package, caveat = spec
    try:
        module = importlib.import_module(module_name)
    except ImportError:
        return None, warnings, _missing_backend_envelope(target_lc, package)

    backend_cls = getattr(module, attribute)
    if caveat:
        warnings.append(caveat)
    if pipeline is not None:
        return backend_cls(processing_pipeline=pipeline), warnings, None
    return backend_cls(), warnings, None


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
    this corpus's ``observed_*`` rules).

    ``config`` accepts ``{"pipeline": "sysmon"}`` (or a list of pipeline
    keys), which IS applied to the conversion -- see the module docstring
    for why it matters. Any other config key (index name, field mappings,
    etc.) remains reserved for future use: it is echoed in ``config_used``
    and named in ``warnings`` rather than silently dropped.
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

    # Resolve the requested processing pipeline BEFORE constructing the
    # backend. Asking for a pipeline and silently converting without it
    # would emit a query that looks right and selects the wrong events --
    # the exact failure this parameter exists to prevent -- so an unknown
    # or uninstalled pipeline is an error, not a warning.
    cfg = config or {}
    pipeline_names, pipeline_err = _normalise_pipelines(cfg.get("pipeline"))
    if pipeline_err is not None:
        return pipeline_err
    pipeline, pipeline_load_err = _load_pipeline(pipeline_names)
    if pipeline_load_err is not None:
        return pipeline_load_err

    backend, warnings, backend_err = _load_backend(target, pipeline)
    if backend_err is not None:
        return backend_err

    try:
        queries = backend.convert(collection)
    except Exception as exc:
        message = str(exc)
        # A backend that cannot express correlation rules at all is a
        # capability gap, not a defect in the rule -- and it is worth
        # distinguishing, because the caller's next move is different. The
        # rule needs no edit; it needs a backend that supports correlations.
        # Naming those backends here saves the caller discovering the set by
        # trying each one, which is how this gap went unnoticed: 10 of the 76
        # corpus rules fail on every Lucene-family target (elastic, kibana,
        # wazuh and opensearch all route through the same backend), while
        # converting cleanly on splunk and opensearch-ppl.
        # Matched narrowly on the backend's own capability wording. A bare
        # "correlation" substring also appears in the deprecated-pipe-syntax
        # error ("...replaced by Sigma correlations"), which is a rule defect
        # and must keep the generic classification.
        if "does not support correlation" in message.lower():
            return {
                "ok": False,
                "error": _ascii_safe(
                    f"backend '{target}' does not support sigma correlation "
                    f"rules: {message}"
                ),
                "hint": (
                    "the rule is valid -- this backend cannot express "
                    "correlations. Targets in this plugin that can: "
                    + ", ".join(_CORRELATION_CAPABLE_TARGETS)
                ),
                "kind": "backend_capability_gap",
                "target": target.lower(),
                "capability": "correlation_rules",
            }
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

    # `config["pipeline"]` IS applied (above). Every other config key still
    # is not -- no backend here takes index names or field mappings at
    # instantiation time. A caller passing one would otherwise have it
    # silently ignored, which is exactly the kind of unflagged behavior
    # this corpus's own quality discipline exists to prevent. Name the
    # specific unapplied keys rather than blanket-warning about "config",
    # which would now be wrong for a caller who only passed a pipeline.
    unapplied = sorted(k for k in cfg if k not in _RECOGNISED_CONFIG_KEYS)
    if unapplied:
        warnings.append(
            "config parameter is currently accepted but not applied to "
            "backend conversion for key(s): "
            + ", ".join(unapplied)
            + " (reserved for future use); the query below reflects "
            "backend defaults for those settings"
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
        # Echoed so the caller can tell a taxonomy-mapped query from a raw
        # one without diffing the query text. Empty list = no pipeline, which
        # for a windows/sysmon rule means the event selection is NOT applied.
        "pipelines_applied": pipeline_names,
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
        OpenSearch (Lucene or PPL), or Wazuh. Returns the primary
        converted query plus conversion lossiness warnings (e.g.
        unsupported modifiers). Missing pySigma or missing backend
        packages return actionable error envelopes with the exact pip
        install command.

        For a rule written against a windows/sysmon logsource, pass
        config={"pipeline": "sysmon"} so the abstract logsource is mapped
        to the product's real event selection; without it the query keeps
        the field names but matches events of every type.
        """
        return convert_rule_body(
            yaml_content, target=target, config=config
        )
