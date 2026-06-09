# Changelog

All notable changes to the WRG-11 Sigma detection corpus are documented here.

The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this corpus
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Scope note:** this repository is a Sigma **detection corpus**, not a pip
> package. A "release" here is a GitHub tag that marks a public-corpus
> milestone — there is no PyPI artifact, and the detection logic is already
> live on `main`.

## [Unreleased]

Commits that have landed on `main` after the `v1.1.0` tag. The corpus rule-file
count is unchanged at **68** — no detection rules were added or removed. These
are tag/metadata and description refreshes on existing rules, repository-hygiene
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
