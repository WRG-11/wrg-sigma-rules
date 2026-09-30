# Evidence-review audits

The following local reports make review queues and conversion boundaries
visible. They are advisory: none promotes a rule, proves an actor attribution,
or replaces reading the cited source. Pass `--examples-dir` (and, where
applicable, `--notes-dir`) when auditing a copied or isolated corpus; a missing
examples directory is an error rather than an empty result.
The correlation-conversion audit also fails clearly if any selected corpus YAML
file cannot be read, decoded, or parsed; a partial conversion count is not a
reproducible measurement.
The observed-evidence inventory likewise fails clearly on unreadable or
invalid observed-rule YAML and unreadable detection notes, rather than
publishing a partial provenance inventory.
The detection-note gap report uses the same rule and note input boundary, so a
partial documentation queue cannot be mistaken for a complete review queue.

```bash
python scripts/observed_evidence_inventory.py --examples-dir resources/examples
python scripts/duplicate_rule_check.py --examples-dir resources/examples --exact-actor-logic
python scripts/duplicate_rule_check.py --examples-dir resources/examples --actor-review-queues
python scripts/correlation_conversion_audit.py --examples-dir resources/examples
python scripts/detection_note_gap.py --examples-dir resources/examples --notes-dir docs/detection-notes
```

Use `--json path/to/report.json` with any report when a review needs a
machine-readable snapshot; the advisory reports carry their scope limitation
inside that JSON so a copied count is not detached from its evidence boundary.
Each report creates the parent directory of its `--json` target, so the same
automation path can be used across all four tools.
Object-shaped report payloads carry `contract.tool` and `contract.version`;
consumers should ignore unknown keys and only treat a version change as a
compatibility boundary. `duplicate_rule_check` preserves its legacy bare-list
default JSON for existing consumers; pass `--json-envelope` to receive its
versioned `{contract, groups, limitations}` form.
That option only changes the default fingerprint report: the exact-logic and
actor-review-queue modes always write their own versioned envelopes when
`--json` is supplied.
`--actor-review-queues` instead writes a versioned envelope with three separate
mechanical queues: exact logic, same comparison shape with different numeric
thresholds, and shared adjacent sidecar bytes. They are source-review inputs,
not semantic-equivalence, attribution, provenance, or consolidation verdicts.
Versioned duplicate-report envelopes also carry `skipped_files` for YAML files
that the selected mode could not read, decode, or parse. The legacy default
bare-list JSON remains unchanged; use `--json-envelope` when that visibility is
needed in a default-mode automation.
For a fixed corpus and option set, report arrays are emitted deterministically;
JSON object-member order is not a compatibility guarantee, so consumers should
parse fields rather than byte-diff raw JSON.
The inventory retains its attribution, platform and
telemetry-manifestation fields as `not_assessed` until a human has documented
the three source matches in [`CONTRIBUTING.md`](../CONTRIBUTING.md). Those
review records live under [`docs/source-reviews/`](source-reviews/): each
must cite a URL already on the rule, record a review date that is not in the
future, and include a source quote for every supported or not-supported
conclusion. The inventory rejects malformed or future-dated records rather
than treating them as evidence; source or rule drift still requires human
re-review.
It also records whether a rule's text cites a private catalog that readers
cannot open (`has_wrg_breach_catalog_mention`) and whether a multi-document
rule keeps references only in a later document. Both are public
traceability review cues, never source-quality or attribution verdicts.
The JSON report preserves the public reference lists (including their
first/later-document split) for human review, without assigning source ranks.
Its summary distinguishes a structured review record, completion of all three
source matches, and an explicit unsupported boundary; none of those counts is
an attribution or promotion decision.
`public_traceability_queue` is a convenience subset for the two mechanical
public-review cues; it is not a verdict about a rule or its sources.
For per-rule JSON, prefer `reference_shape` and
`is_mentioned_by_detection_note`: both are literal inventory facts, not source
quality or note-endorsement labels. The older `reference_hygiene` and
`has_companion_note` fields remain compatibility aliases with identical values.

The correlation audit separately counts a backend's declared capability
boundaries (for example, `correlation_rules` or
`correlation_type:temporal_ordered`) and, for each converted rule, the
deviations `convert_rule` checks for (`semantic_deviations_by_target`).
`semantics_checked_by_target` says how many conversions were checked, so "no
deviation found" stays distinguishable from "not checked". A conversion with no
listed deviation is still not a claim of equivalent alert behavior in a deployed
SIEM.
