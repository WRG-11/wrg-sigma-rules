"""MCP Resource module exposing the corpus's MITRE ATT&CK coverage state.

Resource exposed:

* ``wrg-sigma://coverage/mitre-attack-matrix`` -- markdown report of which
  ATT&CK techniques the published rule corpus actually covers, grouped by
  the tactic directory each rule lives in.

The report is computed from the corpus at read time rather than stored.
A checked-in coverage table is a second copy of the truth, and the corpus
is edited far more often than a hand-maintained table gets refreshed --
it would start drifting the first time a rule was added. Reading the
rules is cheap (73 small YAML files) and cannot go stale.

Test surface: ``coverage_matrix_body()`` and ``collect_coverage()`` are
exposed at module level so unit tests can assert content without invoking
the MCP machinery -- the convention used by
``canonical_patterns_resource.py``.

ASCII-only discipline (cross-platform safe).
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

import yaml

_EXAMPLES_DIR = (
    Path(__file__).resolve().parent.parent.parent / "resources" / "examples"
)

# Sigma tags are a flat namespace. `attack.t1059.001` is a technique,
# `attack.execution` is a tactic, and this corpus additionally carries
# `wrg.*` / `owasp.*` / `cve.*` provenance tags that are not ATT&CK at all.
# Only the technique tags belong in a coverage matrix.
_ATTACK_PREFIX = "attack."
_TECHNIQUE_PREFIX = "attack.t"


def _ascii_safe(text: str) -> str:
    return text.encode("ascii", errors="replace").decode("ascii")


def _rule_kind(filename: str) -> str:
    """Classify a corpus rule by its filename prefix convention."""
    if filename.startswith("observed_"):
        return "observed"
    if filename.startswith("template_"):
        return "template"
    return "other"


def collect_coverage() -> dict[str, Any]:
    """Walk the corpus and return its ATT&CK coverage as plain data.

    Returns a dict with ``tactics`` (per tactic-directory rollup),
    ``techniques`` (technique -> rule count + tactic dirs) and corpus
    totals. Unparseable or tagless rules are reported rather than
    dropped -- a rule that silently contributes nothing to coverage is
    exactly the thing this resource exists to surface.
    """
    tactics: dict[str, dict[str, Any]] = {}
    techniques: dict[str, dict[str, Any]] = {}
    unparseable: list[str] = []
    untagged: list[str] = []
    total_rules = 0

    for path in sorted(_EXAMPLES_DIR.rglob("*.yml")):
        rel = path.relative_to(_EXAMPLES_DIR).as_posix()
        tactic = path.parent.name
        kind = _rule_kind(path.name)
        total_rules += 1

        entry = tactics.setdefault(
            tactic,
            {"rules": 0, "observed": 0, "template": 0, "other": 0,
             "techniques": set()},
        )
        entry["rules"] += 1
        entry[kind] += 1

        try:
            docs = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
        except yaml.YAMLError:
            unparseable.append(rel)
            continue

        rule_techniques: set[str] = set()
        for doc in docs:
            if not isinstance(doc, dict):
                continue
            for tag in doc.get("tags") or []:
                tag = str(tag).strip().lower()
                if tag.startswith(_TECHNIQUE_PREFIX):
                    rule_techniques.add(tag[len(_ATTACK_PREFIX):].upper())

        if not rule_techniques:
            untagged.append(rel)
            continue

        entry["techniques"].update(rule_techniques)
        for technique in rule_techniques:
            tech = techniques.setdefault(
                technique, {"rules": 0, "tactics": set()}
            )
            tech["rules"] += 1
            tech["tactics"].add(tactic)

    return {
        "total_rules": total_rules,
        "total_techniques": len(techniques),
        "tactics": tactics,
        "techniques": techniques,
        "unparseable": unparseable,
        "untagged": untagged,
    }


def coverage_matrix_body() -> str:
    """Return the corpus ATT&CK coverage report as ASCII markdown."""
    if not _EXAMPLES_DIR.exists():
        return json.dumps(
            {
                "ok": False,
                "error": "rule corpus directory not found",
                "expected_path": str(_EXAMPLES_DIR),
            },
            indent=2,
        )

    data = collect_coverage()
    tactics = data["tactics"]
    techniques = data["techniques"]

    lines: list[str] = []
    lines.append("# WRG Sigma Corpus -- MITRE ATT&CK Coverage")
    lines.append("")
    lines.append(
        "Computed from the published rule corpus when this resource is read, "
        "not from a stored table."
    )
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    observed = sum(t["observed"] for t in tactics.values())
    template = sum(t["template"] for t in tactics.values())
    other = sum(t["other"] for t in tactics.values())
    lines.append(f"- Rules: {data['total_rules']}")
    lines.append(f"- Incident rules (observed_*): {observed}")
    lines.append(f"- Pattern rules (template_*): {template}")
    if other:
        lines.append(f"- Unprefixed rules: {other}")
    lines.append(f"- Distinct ATT&CK techniques covered: {data['total_techniques']}")
    lines.append(f"- Tactic groupings: {len(tactics)}")
    lines.append("")

    lines.append("## Coverage by tactic")
    lines.append("")
    lines.append("| Tactic | Rules | observed | template | Techniques |")
    lines.append("|---|---|---|---|---|")
    for tactic in sorted(tactics):
        entry = tactics[tactic]
        techs = ", ".join(sorted(entry["techniques"])) or "(none)"
        lines.append(
            f"| {tactic} | {entry['rules']} | {entry['observed']} | "
            f"{entry['template']} | {techs} |"
        )
    lines.append("")

    lines.append("## Technique index")
    lines.append("")
    lines.append("| Technique | Rules | Tactic grouping |")
    lines.append("|---|---|---|")
    for technique in sorted(techniques):
        info = techniques[technique]
        where = ", ".join(sorted(info["tactics"]))
        lines.append(f"| {technique} | {info['rules']} | {where} |")
    lines.append("")

    if data["untagged"] or data["unparseable"]:
        lines.append("## Rules contributing no coverage")
        lines.append("")
        for rel in data["unparseable"]:
            lines.append(f"- `{rel}` -- could not be parsed")
        for rel in data["untagged"]:
            lines.append(f"- `{rel}` -- no `attack.tNNNN` tag")
        lines.append("")

    lines.append("## What this does and does not tell you")
    lines.append("")
    lines.append(
        "This is the corpus's coverage *state*: which techniques are "
        "detected and where. It is not a gap analysis. Naming what is "
        "missing requires the full ATT&CK Enterprise matrix, which is "
        "deliberately not vendored here -- a copied-in matrix goes stale "
        "against ATT&CK releases and this repo has no way to notice. Pair "
        "this resource with the `threat-coverage-gap-analyzer` skill, which "
        "brings the matrix and uses this report as the 'what we have' half."
    )
    lines.append("")
    lines.append(
        "The tactic column is the corpus directory a rule is filed under, "
        "not an authoritative ATT&CK tactic mapping. A technique can belong "
        "to several tactics upstream; here it appears where its rules live."
    )
    lines.append("")

    return _ascii_safe("\n".join(lines))


def register_coverage_resources(mcp: Any) -> None:
    """Register the corpus coverage resource on an MCP server.

    Accepts any object exposing the ``@resource()`` decorator (the SDK's
    high-level server on either major). Called from ``server.py`` alongside
    the tool registrations; the module itself stays decoupled from the MCP
    runtime so ``coverage_matrix_body()`` remains directly unit-testable.
    """

    @mcp.resource(
        "wrg-sigma://coverage/mitre-attack-matrix",
        name="wrg-sigma-attack-coverage",
        description=(
            "MITRE ATT&CK coverage state of the published sigma rule "
            "corpus: technique-by-tactic rollup, per-technique rule "
            "counts, observed vs template split, and any rule that "
            "contributes no coverage. Computed from the corpus at read "
            "time. ASCII-only markdown body."
        ),
        mime_type="text/markdown",
    )
    def coverage_matrix() -> str:
        return coverage_matrix_body()
