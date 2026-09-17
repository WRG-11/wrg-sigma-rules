#!/usr/bin/env python3
"""Measure current conversion outcomes for every corpus correlation rule.

The audit distinguishes a backend capability gap from a backend that is simply
not installed. It records conversion envelopes; it does not prove that a
successful query has production-equivalent semantics.

Usage:
    python scripts/correlation_conversion_audit.py
    python scripts/correlation_conversion_audit.py --json output.json
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Callable

import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLES_DIR = REPO_ROOT / "resources" / "examples"
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.convert_rule.convert_rule import convert_rule_body
# Do not include aliases here: elastic/elasticsearch/kibana/wazuh share one
# converter implementation, and reporting aliases as independent evidence
# would inflate the apparent backend coverage.
CANONICAL_TARGETS = ("splunk", "elastic", "opensearch", "opensearch-ppl")
_REPORT_CONTRACT = {"tool": "correlation_conversion_audit", "version": 1}
Converter = Callable[..., dict[str, Any]]


def _has_correlation(path: Path) -> bool:
    """Return whether any mapping document in a YAML file has correlation."""
    try:
        return any(
            isinstance(document, dict) and "correlation" in document
            for document in yaml.safe_load_all(path.read_text(encoding="utf-8"))
        )
    except yaml.YAMLError:
        return False


def correlation_rule_paths(examples_dir: Path) -> list[Path]:
    """Find multi-document and single-document Sigma correlation files."""
    return [
        path
        for path in sorted(examples_dir.rglob("*.yml"))
        if _has_correlation(path)
    ]


def _outcome(result: dict[str, Any]) -> str:
    """Classify one converter envelope without interpreting query semantics."""
    if "error" not in result:
        return "converted"
    kind = result.get("kind")
    return kind if isinstance(kind, str) else "conversion_error"


def _capability(result: dict[str, Any], outcome: str) -> str | None:
    """Return a declared capability boundary without inferring semantics."""
    if outcome != "backend_capability_gap":
        return None
    capability = result.get("capability")
    return capability if isinstance(capability, str) else None


def audit_correlation_rules(
    examples_dir: Path,
    targets: tuple[str, ...] = CANONICAL_TARGETS,
    converter: Converter = convert_rule_body,
) -> dict[str, Any]:
    """Return per-rule conversion envelopes and aggregate mechanical outcomes."""
    records: list[dict[str, Any]] = []
    for path in correlation_rule_paths(examples_dir):
        relpath = "resources/examples/" + path.relative_to(examples_dir).as_posix()
        yaml_content = path.read_text(encoding="utf-8")
        outcomes: dict[str, str] = {}
        capabilities: dict[str, str] = {}
        for target in targets:
            try:
                result = converter(yaml_content, target=target)
                outcome = _outcome(result)
                outcomes[target] = outcome
                capability = _capability(result, outcome)
                if capability is not None:
                    capabilities[target] = capability
            except Exception:
                # An audit must report a converter fault as a result, not hide
                # the rest of the corpus behind an early exception.
                outcomes[target] = "audit_error"
        records.append(
            {"path": relpath, "outcomes": outcomes, "capabilities": capabilities}
        )

    by_target: dict[str, dict[str, int]] = {}
    for target in targets:
        by_target[target] = dict(Counter(record["outcomes"][target] for record in records))
    capabilities_by_target: dict[str, dict[str, int]] = {}
    for target in targets:
        capabilities_by_target[target] = dict(
            Counter(
                record["capabilities"][target]
                for record in records
                if target in record["capabilities"]
            )
        )
    return {
        "contract": _REPORT_CONTRACT,
        "summary": {
            "correlation_rule_files": len(records),
            "targets": list(targets),
            "outcomes_by_target": by_target,
            "capabilities_by_target": capabilities_by_target,
            "semantic_equivalence": "not_assessed",
            "limitations": (
                "Conversion outcomes and declared capability boundaries do not "
                "prove equivalent alert behavior in a deployed SIEM."
            ),
        },
        "records": records,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path, help="write audit JSON to this path")
    parser.add_argument(
        "--examples-dir",
        type=Path,
        default=EXAMPLES_DIR,
        help="Sigma examples root to inspect (default: repository corpus)",
    )
    args = parser.parse_args(argv)

    if not args.examples_dir.is_dir():
        print(f"[correlation-conversion-audit] examples directory unavailable: {args.examples_dir}")
        return 2

    payload = audit_correlation_rules(args.examples_dir)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    summary = payload["summary"]
    print(f"[correlation-conversion-audit] {summary['correlation_rule_files']} rule file(s)")
    for target, outcomes in summary["outcomes_by_target"].items():
        report = ", ".join(f"{kind}={count}" for kind, count in sorted(outcomes.items()))
        print(f"  {target}: {report}")
        capabilities = summary["capabilities_by_target"][target]
        if capabilities:
            report = ", ".join(
                f"{capability}={count}"
                for capability, count in sorted(capabilities.items())
            )
            print(f"    capability boundaries: {report}")
    print("  semantic equivalence: not_assessed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
