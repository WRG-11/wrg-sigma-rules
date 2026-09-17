# Source-review ledger

`observed_*` rules make claims about the world. Before a reviewer records an
outcome here, they must read the cited primary source and evaluate the three
matches in [`CONTRIBUTING.md`](../../CONTRIBUTING.md): attribution, platform,
and telemetry manifestation.

Create a `*.yml` file from `TEMPLATE.yml.example`. Every record must name a
single rule, a source URL already present in that rule's `references:`, and an
ISO `reviewed_on` date. Each outcome is one of:

- `not_assessed`: no source-backed conclusion is recorded.
- `supported`: the source supports this one match; include a short `quote` or
  precise source location.
- `not_supported`: the source does not support this one match; include the
  source wording or location that establishes the boundary.

The inventory rejects malformed records, duplicate rule entries, a review URL
that is absent from the rule, and a supported/not-supported outcome without a
quote. This is intentionally a ledger of review judgments, not an automatic
promotion mechanism: a rule hit remains detection evidence, not actor
attribution.

For an accepted supported or not-supported outcome, the inventory's JSON
output preserves the recorded quote under `source_review.evidence`. This lets
a consumer audit the recorded boundary without turning the status itself into
a detached assertion.
