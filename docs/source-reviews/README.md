# Source-review ledger

`observed_*` rules make claims about the world. Before a reviewer records an
outcome here, they must read the cited primary source and evaluate the three
matches in [`CONTRIBUTING.md`](../../CONTRIBUTING.md): attribution, platform,
and telemetry manifestation.

Create a `*.yml` file from `TEMPLATE.yml.example`. Every record must name a
single rule, an HTTPS source URL already present in that rule's `references:`, and an
ISO `reviewed_on` date that is not in the future. Each outcome is one of:

- `not_assessed`: no source-backed conclusion is recorded.
- `supported`: the source supports this one match; include a short `quote` or
  precise source location.
- `not_supported`: the source does not support this one match; include the
  source wording or location that establishes the boundary.

Keep a quote or locator to 1,000 characters or fewer. It is evidence to audit
one judgment, not a copied source document.

The source URL must use a normal HTTPS authority: credentials in the URL
(`user:password@host`) and invalid ports are rejected before the record can be
rendered into an advisory report. Do not put tokens or credentials in a public
review record.

The loader validates record shape, linkage, dates, and quote length; it does
not establish that a recorded quote is accurate. That remains a reviewer and
pull-request-review responsibility. A record can also become stale if its
source changes behind a stable URL or the rule changes while retaining the same
reference. `reviewed_on` is only a human-facing freshness cue; re-review is a
manual decision.

Schema version 1 accepts only the documented fields. Do not attach a quote to
`not_assessed`: that status records no conclusion. Add a later version rather
than silently extending a record with custom fields.

The inventory rejects malformed records, duplicate rule entries, a review URL
that is absent from the rule, and a supported/not-supported outcome without a
quote. This is intentionally a ledger of review judgments, not an automatic
promotion mechanism: a rule hit remains detection evidence, not actor
attribution.

For an accepted supported or not-supported outcome, the inventory's JSON
output preserves the recorded quote under `source_review.evidence`. This lets
a consumer audit the recorded boundary without turning the status itself into
a detached assertion. `source_review.record` points back to the ledger file
that supplied it. Render an evidence quote with its matching field and status,
never as a standalone endorsement.
