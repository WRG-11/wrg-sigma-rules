# Changelog

All notable changes to the WRG-11 Sigma detection corpus are documented here.

The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this corpus
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Scope note:** this repository is a Sigma **detection corpus**, not a pip
> package. A "release" here is a GitHub tag that marks a public-corpus
> milestone — there is no PyPI artifact, and the detection logic is already
> live on `main`.

## [1.3.0] - 2026-07-29

Corpus 73 → 76 rules, and 12 → 13 tactic categories. The larger part of this
release is not the new rules: it is that several things this repo claimed
were either untrue or unmeasured, and are now one or the other.

### Fixed

- **The plugin did not import.** `mcp` 2.0.0, released 2026-07-28, removed
  `mcp.server.fastmcp`, which `server.py` imports. `requirements.txt` had no
  upper bound, so a fresh clone installed an SDK the entry-point could not
  load. Every recorded CI run was green because the last push predated the
  release by four days and nothing re-ran.
- **`convert_rule` applied no processing pipeline.** A Sigma rule is written
  against abstract logsource taxonomy; mapping it to a product's real event
  selection is a pipeline's job. Without one, a `process_creation` rule
  converted to a Splunk query that kept the field names and dropped the event
  selection — matching `Image` on any event carrying that field, with no
  `EventID=1`. 46 of the 73 rules were `product: windows`, so this was the
  common case. `config={"pipeline": "sysmon"}` now applies one, and an
  unknown or uninstalled pipeline is an error rather than a silent fallback.
- **`elasticsearch` was a working target that the tool denied having.** The
  loader accepted it; the advertised target list omitted it, so the
  unknown-target hint hid a target `DEMO.md` itself uses. The backend
  registry is now a data table, so the two cannot disagree again.
- **`wrg-sigma://coverage/mitre-attack-matrix` did not exist.** It was listed
  under Resources in the README and referenced by the gap-analyzer skill's
  description, but nothing registered it — a client following the README hit
  an unresolvable URI.

### Added

- `wrg-sigma://coverage/mitre-attack-matrix`, implemented: technique-by-tactic
  rollup, per-technique rule counts, observed/template split, and any rule
  contributing no coverage. Computed from the corpus at read time so it
  cannot go stale. It does not vendor the ATT&CK matrix and says so — it is
  the "what we have" half, not a gap analysis.
- OpenSearch conversion targets (`opensearch` Lucene, `opensearch-ppl` PPL).
- Support for `mcp` 1.x and 2.x through an import shim, with CI running the
  suite against both majors.
- Docker image build in CI plus `scripts/mcp_stdio_smoke.py`, which speaks
  real JSON-RPC to the server over stdio and requires it to announce the
  tools and resources the plugin promises. The Dockerfile had never been
  built by anything.
- Coverage measurement in CI against an 80% floor. It had been documented as
  impossible here (pysigma's YAML loader corrupts under coverage.py's C
  tracer, 94/287 false failures in 2026-07); re-measured on Python 3.12's
  `sys.monitoring` backend it is 319/319 clean at 87%.
- `CONTRIBUTING.md`, setting out the sourcing bar for rules claiming
  real-world observation — attribution, platform and manifestation each
  matched against the cited source — derived from three upstream SigmaHQ
  submissions that closed without merging.
- Two correlation templates covering the types the corpus never used: password
  spraying via `value_count` (T1110.003) and a ransomware execution chain via
  `temporal` (T1490 + T1486). All 8 prior correlation rules were
  `event_count`. `temporal_ordered` is deliberately absent — the Splunk
  backend does not support it.
- `privilege_escalation` tactic coverage (T1098.003, AWS IAM wildcard-admin
  policy creation via CloudTrail), the corpus's first rule in that tactic and
  its first `aws`/`cloudtrail` logsource. The rule existed unpublished in the
  monorepo mirror and is published here as part of closing that drift.
- Weekly scheduled test run, so a break originating outside the repo can hide
  for at most a week rather than indefinitely.

### Changed

- Every dependency carries an upper bound at the next major. An unbounded
  `>=` is satisfied by every future release, so Dependabot proposes nothing
  and a breaking major arrives silently — which is exactly how the mcp 2.0.0
  break happened.
- README marketplace claims re-counted: 0 of 2283 community plugins mention
  sigma (the niche claim holds), but 315 are security-themed, against the
  "1 generic security plugin" the README had asserted since May. The
  submission route is now named correctly — a form, not a pull request.

## [1.2.1] - 2026-07-23

Wording only — no detection rule, tool logic or schema changed. Eleven places in
published content named an **internal** corpus that is not part of this
repository. (The removed term is deliberately not reprinted here: this repo
scans its own published content for exactly that name, and quoting it in the
changelog would reintroduce what the release removes.)

### Changed

- Three of them claimed provenance from a private asset a reader cannot inspect
  or verify — the plugin marketplace description, the `canonical-patterns`
  index, and the description of the `wrg-sigma://patterns/canonical-5` MCP
  resource. They now describe what is actually published: a 73-rule corpus
  across 12 MITRE ATT&CK tactics.
- The other eight used that internal name where they meant *this* corpus — the
  73 published rules — in a validation message, a skill instruction, two
  docstrings, a code comment, a test docstring and the pattern index. They now
  say "this corpus" / "the published corpus", which is both accurate and
  unambiguous to a reader outside the project.
- `migrate_sigma_corpus.py`'s truncation warning pointed readers at a full
  source that is not published. It now states plainly that the untruncated rule
  is not published.

## [1.2.0] - 2026-07-23

Corpus grew from 68 to 73 rules (net +5) alongside a public MCP-server
integration, an honesty relabel of synthetic rules, a correlation-rule
migration for the 8 rules still on the deprecated pipe-aggregation syntax,
and a YAML alias-bomb hardening pass on `validate_rule`.

### Added

- Photo ZIP campaign Node.js Run-key persistence rule (count 68 to 69):
  real-incident-grounded detection for registry Run-key persistence.
- Four rules via corpus sync (69 to 73): Jellyfin CVE-2026-35033 FFmpeg
  argument-injection LFI (real observed) plus three MCP database-server
  SQL-abuse templates (local-file-read, SSRF-to-metadata, read-only
  write-bypass).
- MCP server wired into the plugin (.mcp.json) with naming, version and
  rule-count consistency plus a pytest CI gate.
- `deprecated_pipe_condition` linter in `validate_rule`: flags
  `condition: X | count() by Y > N in Zm` (schema-valid but rejected by every
  pySigma backend at convert time). (#44)
- Sigma correlation-rule support in `convert_rule` / `validate_rule` via
  `SigmaCollection` — base-rule + correlation-rule two-document pairs now parse
  and convert; single-document rules unchanged. (#44)
- `--regenerate-index` in `scripts/migrate_sigma_corpus.py`: rebuilds
  `INDEX.json` by scanning the rule files on disk (no monorepo dependency),
  with `tests/test_index_consistency.py` asserting a regenerate-vs-committed
  snapshot diff so index drift cannot re-accumulate silently. (#42)
- `test_module_count` as a second self-stamped README metric alongside
  `sigma_rule_count`, closing the doc-drift class that the existing stamp
  marker did not cover.
- `.gitignore` — this repository previously had none, leaving `__pycache__/`,
  `.coverage` and `.pytest_cache/` untracked-but-not-ignored.

### Changed

- Relabeled three synthetic rules from observed_ to template_: these are
  internal-adversarial-derived scenarios, not real-world-observed incidents,
  so the template_ prefix and wrg.template tag remove the prior over-claim.
- README: added the persistence tactic (12th ATT&CK category) and corrected
  the title to "Claude Code Plugin" (a third-party plugin, not an Anthropic
  product).
- Migrated the 8 remaining rules using the deprecated pipe-aggregation
  condition to correlation-rule syntax (a base document plus an `event_count`
  correlation document; original `id`/`title`/`references`/`tags` preserved so
  id-based consumers do not break). Splunk convert verified per rule; Elastic
  correctly reports it does not support correlation rules. (#44)
- `convert_rule`: a non-empty `config` argument was accepted and echoed back in
  `config_used` but never applied to backend construction. It now raises a
  warning instead of silently pretending the config took effect.
- `draft_rule` now emits YAML through `yaml.safe_dump` instead of a
  hand-rolled emitter. The hand-rolled version only quoted problem characters
  in top-level scalars, so a `references` entry containing `:` silently
  re-parsed as a one-key mapping rather than a string. (#42)

### Fixed

- `draft_rule`: 80-char title truncation cut mid-word with no ellipsis when the
  description had no period (silent data loss). (#44)
- `validate_rule`: a non-string `id` field skipped the schema check entirely;
  now flagged with a distinct error. (#44)
- `INDEX.json` drift: regenerated from disk (`total_rules` 68 to 73). The
  `persistence` tactic — the 12th ATT&CK category — was completely unindexed,
  3 stale `observed_` to `template_` renames were still listed under their old
  names, and 5 new rules were missing. The three stale rule-count siblings
  (`plugin.json`, `resources/canonical-patterns/INDEX.md`, `DEMO.md`) were
  corrected in the same pass. (#42)
- `canonical_patterns_resource`: `register_canonical_pattern_resources()` was
  fully implemented and covered by 12 tests, but `server.py` never called it —
  so the resource URI that `canonical-patterns/INDEX.md` documented as a
  working feature was unreachable from any real MCP client. Now wired into
  `server.py`, with a test that imports the real server module and asserts the
  resource and template are registered. (#42)
- `validate_rule`: a multi-document YAML file no longer forces `valid=False`
  when the first document is otherwise clean (fixed on the separate
  `_pysigma_validate` path as well, which re-parses the raw multi-doc text
  independently). (#42)
- `validate_rule`: the UUID regex now accepts v6/v7/v8 (RFC 9562) and the nil
  UUID, which removed the need for the `lockbit_btc` schema-quality allowlist
  entry. (#42)
- Rule references corrected across six `observed_*` rules — real sources and
  accurate MITRE ATT&CK attribution replacing the prior placeholders. (#33)
- Doc drift: README claimed "8 Python test modules" against an actual 10. That
  metric is now self-stamped and has since auto-tracked to 11 on its own.
- `DEMO.md` no longer carries a hard-coded suite pass count. The hand-corrected
  286 to 287 fix rotted again within this same release cycle (actual: 302), so
  the line now points at the CI workflow instead. The count cannot be
  self-stamped the way the rule and module counts are — deriving it requires
  invoking pytest, and `readme_stamp.py` is deliberately stdlib-only.

### Security

- `validate_rule` YAML denial-of-service: the byte-size cap alone does not stop
  an alias bomb (billion-laughs). PyYAML resolves aliases to shared object
  references, so parsing itself stays fast at any nesting depth and the
  exponential blowup instead hits downstream code that walks the parsed graph
  without reference-awareness. Anchor/alias syntax is now rejected outright via
  a PyYAML composer event hook (not a regex) — Sigma rules have no legitimate
  use for `&anchor`/`*alias`. `RecursionError` is handled for deep but
  alias-free nesting, and the byte-size cap is retained as a separate guard
  against plain oversized input. (#42)
- Internal wave-dispatch identifiers and fleet-topology metadata were removed
  from public content, and a regression test now blocks them from reaching the
  public surface. (#37, #38, #43)

### Known limitations

- `coverage run -m pytest` produces **false** failures on this repository — 94
  of 287 when the effect was characterised on Python 3.12, matching CI. Root
  cause is upstream: pysigma's
  `SigmaYAMLLoader(yaml.CSafeLoader)` — a C-extension YAML loader subclass in
  the dependency, not in this repo's code — breaks specifically under
  coverage.py's tracer (reproduces with `core=ctrace` forced, does not
  reproduce under a bare no-op `sys.settrace`; `branch=True` additionally
  hangs). CI therefore stays on plain `pytest` deliberately; wiring in
  `coverage run` as-is would make CI red for reasons unrelated to code quality.

### Maintenance

- ci(deps): `actions/checkout` 6.0.3 -> 7.0.1 (#28, #46); `actions/setup-python`
  6.2.0 -> 7.0.0 (#27, #49); `github/codeql-action` 4.36.2 -> 4.37.3
  (#39, #40, #41, #47, #48, #50); `pysigma` `>=1.3.3` -> `>=1.4.0` (#34);
  `mcp` `>=1.2.0` -> `>=1.28.1` (#29, #36); plus a
  `pysigma-backend-elasticsearch` requirement bump (#35).


## [1.1.1] - 2026-06-10

Corpus rule-file count unchanged at **68** — no detection rules added or
removed. Tag/metadata refreshes on existing rules, repository-hygiene
removals of internal-only docs, plus CI security and dependency maintenance.

### Changed

- **`wrg.observed` tag added to 4 `observed_*` rules** — token type-confusion,
  audit-log-gap, scanner-crash defense-evasion, and a GitHub Actions base64
  payload rule now carry the consistent `wrg.observed` tag. Tag/metadata only;
  the detection logic is unchanged. (`f245f46`, #12)
- **Rule-description + INDEX context refresh** — refreshed the human-readable
  descriptions on seven existing `observed_*` rules and the README/index
  context for accuracy. No `detection:` / `logsource:` changes. (`dbb70a6`, #22)

### Removed

- Removed internal-only draft and self-audit documents (`.claude-plugin/`
  audit notes and `PR-DRAFT.md`) from the public corpus and corrected the
  documented marketplace status. Detection content untouched. (`5c96c1e`, #21)

### Added

- `SECURITY.md` — private vulnerability disclosure via GitHub Security
  Advisories. (`7e5c26c`, #19)
- `dependabot.yml` — dependency monitoring (GitHub Actions + pip). (`cc8835c`)

### Maintenance

- ci(security): pinned `codeql-action` / `checkout` workflow refs to commit
  SHAs. (`1489f7c`, #20)
- ci(deps): `pysigma` `>=0.10` -> `>=1.3.3` (#17); `pyyaml` `>=6.0` -> `>=6.0.3`
  (#15); `actions/checkout` 4.3.1 -> 6.0.3 (#13); `github/codeql-action` 3 -> 4
  (#14); plus pysigma Splunk / Elasticsearch backend requirement bumps
  (#18, #16).

## [1.1.0] - 2026-06-02

Twelve commits past `v1.0.0`. The published corpus grew from 61 to 68 rule
files (6 detection rules plus the Gogs rebase-RCE rule), and the index field was
resynced to match. Disk rule-file count, `INDEX.json` `total_rules`, and the
README `sigma_rule_count` self-stamp are all in sync at **68**.

### Added

- **6 detection rules** synced to the public corpus, raising the
  rule-file count 61 → 67. (`3b2b6c2`, #4)
- **Gogs rebase-RCE rule** — `observed` detection for the authenticated
  argument-injection RCE (CWE-88, CVSSv4 9.4) in which a malicious `--exec`
  base-branch name is injected into the `git rebase` that Gogs runs; mapped to
  T1059 with a zero-false-positive `ParentImage|endswith: '/gogs'` scope. Brings
  the rule-file count to 68. (`184918f`, #8)
- **Gogs companion detection note** documenting the shell-intermediary coverage
  limitation (`gogs → sh → git` breaks the gogs-parent scope), for accuracy
  alongside the merged rule. (`05ca757`, #9)

### Fixed

- **`INDEX.json` `total_rules` resync 62 → 68** — the index field had gone
  stale while the on-disk corpus advanced; six previously unindexed rules were
  added across all three index dimensions (categories / detection type /
  target platform). This is an index-*field* resync, not new detection logic.
  (`7962f1e`, #10)
- **corpus publication gap** — backported 3 published-rule environment
  filters that were missing from the public corpus. (`b17f8af`, #1)
- **corpus full-clean** — 4 `template_*` SCCM + RDP environment
  filters. (`16e9b1f`, #3)
- **`draft_rule` control-character collapse** — collapse control characters in
  YAML emit and correct the linter return type. (`54612d6`, #7)

### Maintenance

- README self-stamp — auto-sync `sigma_rule_count` via a free GitHub Actions
  workflow (`readme-stamp.yml`). (`a61c0fc`, #6)
- SHA-pin all GitHub Actions to commit SHAs (supply-chain hardening).
  (`1f07570`, #5)
- CodeQL static-analysis workflow (security-extended, Python). (`b6f78ef`)
- `FUNDING.yml` — Detection Frontier subscribe plus future sponsor channels.
  (`db6a02e`)
- README — Detection Frontier subscribe CTA and star nudge. (`67519ff`)

[1.1.0]: https://github.com/WRG-11/wrg-sigma-rules/compare/v1.0.0...v1.1.0
[1.1.1]: https://github.com/WRG-11/wrg-sigma-rules/compare/v1.1.0...v1.1.1
[1.2.0]: https://github.com/WRG-11/wrg-sigma-rules/compare/v1.1.1...v1.2.0
[1.2.1]: https://github.com/WRG-11/wrg-sigma-rules/compare/v1.2.0...v1.2.1
