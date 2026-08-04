# Detection notes

Prose write-ups for rules where the reasoning behind the detection logic —
why the signal is specific, what the false-positive trap looks like, what the
coverage gaps are — does not fit in a Sigma rule's `description:` field. Not
every rule has one; these exist for cases worth explaining at length,
usually a novel or actively-exploited technique.

Each note names the rule it accompanies and the merged PR that shipped it, so
the note and the YAML cannot silently drift apart.

| Note | Rule |
|---|---|
| [Detecting the Gogs Rebase RCE Before a Patch Exists](gogs-rebase-rce-detection-2026-06-01.md) | [`execution/observed_gogs_rebase_rce_t1059.yml`](../../resources/examples/execution/observed_gogs_rebase_rce_t1059.yml) |
