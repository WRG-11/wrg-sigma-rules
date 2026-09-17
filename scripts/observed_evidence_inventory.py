#!/usr/bin/env python3
"""Inventory mechanical evidence facts for ``observed_*`` Sigma rules.

This script intentionally does not infer that a source proves a rule.  It
reports facts that can be established locally (references, logsource, ATT&CK
tags and companion notes), then leaves attribution, platform and telemetry
manifestation as ``not_assessed`` for human source review.

Usage:
    python scripts/observed_evidence_inventory.py
    python scripts/observed_evidence_inventory.py --json output.json
"""
from __future__ import annotations

import argparse
import json
import re
from collections.abc import Iterable
from datetime import date
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLES_DIR = REPO_ROOT / "resources" / "examples"
NOTES_DIR = REPO_ROOT / "docs" / "detection-notes"
SOURCE_REVIEWS_DIR = REPO_ROOT / "docs" / "source-reviews"
_RULE_PATH_RE = re.compile(r"resources/examples/[A-Za-z0-9_./-]+\.ya?ml")
_REVIEW_STATUSES = frozenset({"not_assessed", "supported", "not_supported"})
_WRG_BREACH_CATALOG_RE = re.compile(r"\bWRG\s+breach\s+catalog\b", re.IGNORECASE)
_MAX_SOURCE_REVIEW_QUOTE_CHARS = 1_000
_REPORT_CONTRACT = {"tool": "observed_evidence_inventory", "version": 1}


def _is_mitre_reference(url: str) -> bool:
    """Return whether *url* is an ATT&CK taxonomy reference.

    ATT&CK is useful technique context, but it is not primary evidence that a
    named actor performed a rule's selected activity or that it manifests in
    the selected telemetry.
    """
    try:
        host = (urlsplit(url).hostname or "").lower()
    except ValueError:
        return False
    return host == "attack.mitre.org" or host.endswith(".attack.mitre.org")


def _covered_rule_paths(notes_dir: Path) -> set[str]:
    """Return rule paths mentioned by any detection note."""
    if not notes_dir.is_dir():
        return set()
    covered: set[str] = set()
    for note in notes_dir.glob("*.md"):
        covered.update(_RULE_PATH_RE.findall(note.read_text(encoding="utf-8")))
    return covered


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _documents(path: Path) -> list[dict[str, Any]]:
    """Load mapping documents, ignoring empty YAML document separators."""
    return [
        doc
        for doc in yaml.safe_load_all(path.read_text(encoding="utf-8"))
        if isinstance(doc, dict)
    ]


def _review_error(path: Path, message: str) -> ValueError:
    """Return a contextual error for a malformed human-review record."""
    return ValueError(f"source review {path}: {message}")


def load_source_reviews(reviews_dir: Path) -> dict[str, dict[str, Any]]:
    """Load explicit human-review outcomes without interpreting prose notes.

    A review record is deliberately narrow: it names one corpus rule, one
    source already listed by that rule, an ISO review date, and an outcome for
    each of CONTRIBUTING.md's three source matches.  ``supported`` and
    ``not_supported`` require a short source quote or location so a future
    reviewer can audit the judgment.  Missing records remain ``not_assessed``.
    """
    if not reviews_dir.is_dir():
        return {}

    reviews: dict[str, dict[str, Any]] = {}
    for path in sorted(reviews_dir.glob("*.yml")):
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
            raise _review_error(path, f"cannot parse YAML: {exc}") from exc
        if not isinstance(document, dict):
            raise _review_error(path, "must contain a mapping")
        if document.get("schema_version") != 1:
            raise _review_error(path, "schema_version must be 1")
        entries = document.get("reviews")
        if not isinstance(entries, list):
            raise _review_error(path, "reviews must be a list")

        for index, entry in enumerate(entries, start=1):
            if not isinstance(entry, dict):
                raise _review_error(path, f"review {index} must be a mapping")
            unknown_entry_fields = set(entry).difference(
                {
                    "rule",
                    "source",
                    "reviewed_on",
                    "attribution_evidence",
                    "platform_evidence",
                    "telemetry_manifestation_evidence",
                }
            )
            if unknown_entry_fields:
                raise _review_error(
                    path,
                    f"review {index} has unknown field(s): "
                    + ", ".join(sorted(unknown_entry_fields)),
                )
            rule = entry.get("rule")
            source = entry.get("source")
            reviewed_on = entry.get("reviewed_on")
            if (
                not isinstance(rule, str)
                or not _RULE_PATH_RE.fullmatch(rule)
                or ".." in rule.split("/")
            ):
                raise _review_error(path, f"review {index} has an invalid rule path")
            try:
                parsed_source = urlsplit(source) if isinstance(source, str) else None
            except ValueError:
                parsed_source = None
            if (
                parsed_source is None
                or parsed_source.scheme not in {"http", "https"}
                or not parsed_source.netloc
            ):
                raise _review_error(path, f"review {index} has an invalid source URL")
            try:
                is_iso_date = isinstance(reviewed_on, str) and (
                    date.fromisoformat(reviewed_on).isoformat() == reviewed_on
                )
            except ValueError:
                is_iso_date = False
            if not is_iso_date:
                raise _review_error(path, f"review {index} must use YYYY-MM-DD reviewed_on")
            if date.fromisoformat(reviewed_on) > date.today():
                raise _review_error(path, f"review {index} reviewed_on cannot be in the future")
            if rule in reviews:
                raise _review_error(path, f"duplicates review for {rule}")

            outcomes: dict[str, Any] = {}
            for field in (
                "attribution_evidence",
                "platform_evidence",
                "telemetry_manifestation_evidence",
            ):
                outcome = entry.get(field)
                if not isinstance(outcome, dict):
                    raise _review_error(path, f"review {index} {field} must be a mapping")
                unknown_outcome_fields = set(outcome).difference({"status", "quote"})
                if unknown_outcome_fields:
                    raise _review_error(
                        path,
                        f"review {index} {field} has unknown field(s): "
                        + ", ".join(sorted(unknown_outcome_fields)),
                    )
                status = outcome.get("status")
                quote = outcome.get("quote")
                if status not in _REVIEW_STATUSES:
                    raise _review_error(path, f"review {index} {field} has invalid status")
                if status != "not_assessed" and (
                    not isinstance(quote, str) or not quote.strip()
                ):
                    raise _review_error(path, f"review {index} {field} needs a source quote")
                if isinstance(quote, str) and len(quote.strip()) > _MAX_SOURCE_REVIEW_QUOTE_CHARS:
                    raise _review_error(
                        path,
                        f"review {index} {field} quote exceeds "
                        f"{_MAX_SOURCE_REVIEW_QUOTE_CHARS} characters",
                    )
                if status == "not_assessed" and quote is not None:
                    raise _review_error(
                        path,
                        f"review {index} {field} must not carry a quote when not_assessed",
                    )
                outcomes[field] = status
                if status != "not_assessed":
                    outcomes[f"_{field}_quote"] = quote.strip()

            outcomes["_source"] = source
            outcomes["_reviewed_on"] = reviewed_on
            outcomes["_record_path"] = path.relative_to(reviews_dir).as_posix()
            reviews[rule] = outcomes
    return reviews


def _references(documents: Iterable[dict[str, Any]]) -> list[str]:
    """Collect ordered unique reference URLs from every document in a rule."""
    result: list[str] = []
    for document in documents:
        for reference in _string_list(document.get("references")):
            if reference not in result:
                result.append(reference)
    return result


def build_inventory(
    examples_dir: Path,
    notes_dir: Path,
    source_reviews: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Build records without making source-quality claims.

    ``observed_*`` is a provenance claim.  This inventory makes missing or
    MITRE-only references visible, but all three CONTRIBUTING.md source-review
    matches deliberately remain human-assessed fields.
    """
    covered = _covered_rule_paths(notes_dir)
    source_reviews = source_reviews or {}
    records: list[dict[str, Any]] = []
    seen_reviews: set[str] = set()

    for path in sorted(examples_dir.rglob("observed_*.yml")):
        documents = _documents(path)
        if not documents:
            continue
        first = documents[0]
        relpath = "resources/examples/" + path.relative_to(examples_dir).as_posix()
        references = _references(documents)
        first_document_references = _references([first])
        later_document_references = _references(documents[1:])
        external_references = [ref for ref in references if not _is_mitre_reference(ref)]
        reference_shape = (
            "has_non_mitre_reference" if external_references else "mitre_only_or_missing"
        )
        tags = sorted(
            {
                tag
                for document in documents
                for tag in _string_list(document.get("tags"))
                if tag.startswith("attack.")
            }
        )
        logsource = first.get("logsource")
        review = source_reviews.get(relpath, {})
        if review:
            seen_reviews.add(relpath)
        if review.get("_source") not in {None, *references}:
            raise ValueError(
                f"source review for {relpath} cites a URL absent from the rule references"
            )
        records.append(
            {
                "path": relpath,
                "title": first.get("title", path.stem),
                "status": first.get("status"),
                "document_count": len(documents),
                "has_correlation": any("correlation" in document for document in documents),
                "attack_tags": tags,
                "logsource": logsource if isinstance(logsource, dict) else {},
                "reference_count": len(references),
                "external_reference_count": len(external_references),
                "first_document_reference_count": len(first_document_references),
                "later_document_reference_count": len(later_document_references),
                "references": references,
                "first_document_references": first_document_references,
                "later_document_references": later_document_references,
                "has_wrg_breach_catalog_mention": bool(
                    _WRG_BREACH_CATALOG_RE.search(path.read_text(encoding="utf-8"))
                ),
                # Preferred names describe what the inventory can establish,
                # not a judgment about source quality or note endorsement.
                "reference_shape": reference_shape,
                "is_mentioned_by_detection_note": relpath in covered,
                # Compatibility aliases retained for existing JSON consumers.
                "reference_hygiene": reference_shape,
                "has_companion_note": relpath in covered,
                "source_review": (
                    {
                        "source": review["_source"],
                        "reviewed_on": review["_reviewed_on"],
                        "record": review.get("_record_path"),
                        "evidence": {
                            field: review[f"_{field}_quote"]
                            for field in (
                                "attribution_evidence",
                                "platform_evidence",
                                "telemetry_manifestation_evidence",
                            )
                            if f"_{field}_quote" in review
                        },
                    }
                    if review
                    else None
                ),
                "attribution_evidence": review.get("attribution_evidence", "not_assessed"),
                "platform_evidence": review.get("platform_evidence", "not_assessed"),
                "telemetry_manifestation_evidence": review.get(
                    "telemetry_manifestation_evidence", "not_assessed"
                ),
            }
        )
    unknown_rules = sorted(set(source_reviews).difference(seen_reviews))
    if unknown_rules:
        raise ValueError(
            "source review targets unavailable observed rule(s): "
            + ", ".join(unknown_rules)
        )
    return records


def summarize(records: list[dict[str, Any]]) -> dict[str, int]:
    """Summarize mechanical inventory facts, not evidence quality."""
    evidence_fields = (
        "attribution_evidence",
        "platform_evidence",
        "telemetry_manifestation_evidence",
    )
    return {
        "observed_rule_files": len(records),
        "with_non_mitre_reference": sum(
            record["reference_shape"] == "has_non_mitre_reference"
            for record in records
        ),
        "mitre_only_or_missing_reference": sum(
            record["reference_shape"] == "mitre_only_or_missing"
            for record in records
        ),
        "with_companion_note": sum(record["has_companion_note"] for record in records),
        "with_wrg_breach_catalog_mention": sum(
            record["has_wrg_breach_catalog_mention"] for record in records
        ),
        "with_references_only_in_later_document": sum(
            record["first_document_reference_count"] == 0
            and record["later_document_reference_count"] > 0
            for record in records
        ),
        "public_traceability_review_queue": len(public_traceability_queue(records)),
        "with_structured_source_review": sum(
            record["source_review"] is not None for record in records
        ),
        "with_complete_source_review": sum(
            record["source_review"] is not None
            and all(record[field] != "not_assessed" for field in evidence_fields)
            for record in records
        ),
        "with_explicit_source_review_boundary": sum(
            record["source_review"] is not None
            and any(record[field] == "not_supported" for field in evidence_fields)
            for record in records
        ),
        "awaiting_human_source_review": sum(
            any(record[field] == "not_assessed" for field in evidence_fields)
            for record in records
        ),
    }


def public_traceability_queue(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return review cues without converting them into provenance judgments."""
    return [
        record
        for record in records
        if record["has_wrg_breach_catalog_mention"]
        or (
            record["first_document_reference_count"] == 0
            and record["later_document_reference_count"] > 0
        )
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path, help="write the inventory JSON to this path")
    parser.add_argument(
        "--examples-dir",
        type=Path,
        default=EXAMPLES_DIR,
        help="Sigma examples root to inspect (default: repository corpus)",
    )
    parser.add_argument(
        "--notes-dir",
        type=Path,
        default=NOTES_DIR,
        help="detection-notes root used for companion-note inventory",
    )
    parser.add_argument(
        "--source-reviews-dir",
        type=Path,
        default=SOURCE_REVIEWS_DIR,
        help="structured human source-review records (default: docs/source-reviews)",
    )
    args = parser.parse_args(argv)

    if not args.examples_dir.is_dir():
        print(f"[observed-evidence-inventory] examples directory unavailable: {args.examples_dir}")
        return 2

    try:
        source_reviews = load_source_reviews(args.source_reviews_dir)
        records = build_inventory(args.examples_dir, args.notes_dir, source_reviews)
    except ValueError as exc:
        print(f"[observed-evidence-inventory] {exc}")
        return 2
    summary = summarize(records)
    payload = {
        "contract": _REPORT_CONTRACT,
        "summary": summary,
        "records": records,
        "public_traceability_queue": public_traceability_queue(records),
        "limitations": (
            "reference_shape and is_mentioned_by_detection_note are mechanical "
            "facts; they "
            "do not prove attribution, platform, or telemetry manifestation. "
            "reference_hygiene and has_companion_note are compatibility aliases, "
            "not quality or endorsement labels. "
            "Listed URLs are preserved for human review without a source-quality "
            "ranking. "
            "A WRG breach-catalog mention is a literal public-traceability "
            "review cue, not a source-quality verdict. "
            "Only cited structured source-review records may change those "
            "fields from not_assessed; their recorded evidence locators are "
            "preserved with the review result and linked to the ledger file."
        ),
    }

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    print("[observed-evidence-inventory]")
    for key, value in summary.items():
        print(f"  {key}: {value}")
    print("  evidence fields remain not_assessed until a human reviews the source.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
