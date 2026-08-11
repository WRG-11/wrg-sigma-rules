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

Corpus 100 → 122 rules.

### Added

- **Two more CVE rules, after rejecting two weaker candidates on sourcing
  grounds.** Checked Eclipse Theia's indirect-prompt-injection advisory
  (CVE-2026-44688) and Warp's branch-name command injection
  (CVE-2026-48719) against the three-match sourcing bar and rejected
  both: both sources turned out to be high-level summaries with no
  quoted payload, no example malicious identifier, and no described
  trigger mechanism to key detection logic on — the same failure class
  that got this project's three upstream SigmaHQ PRs closed. Wrote rules
  only for the two candidates whose sources actually name the mechanism:

  - `execution/observed_ragflow_canvas_jinja2_ssti_t1059.yml` —
    CVE-2026-45312 (CVSS 9.9). RAGFlow's citation-prompt generator uses
    an unsandboxed Jinja2 environment; any authenticated user can chain
    a Canvas DuckDuckGo+LLM workflow to reach it, and the advisory quotes
    a working object-graph-traversal payload verbatim (`__globals__` ->
    `__builtins__` -> `__import__('os')`). No patch exists at authoring
    time — noted explicitly rather than assuming a version cutoff.
  - `collection/observed_github_copilot_fetchpage_file_uri_exfil_t1005.yml` —
    CVE-2025-66389. VS Code's `fetchPage` tool (which Copilot wraps
    without re-applying its own `readFile` tool's workspace-boundary
    check) accepts `file://` URIs, letting indirect prompt injection
    read paths outside the workspace; chained with `$schema`-triggered
    IntelliSense fetches for exfiltration. Filed as `high` not
    `critical` and flagged for re-evaluation, since no specific patched
    version number is stated in the available sources.

  Both `validate_rule`-clean and convert cleanly to Splunk + Elasticsearch.

- **Three prompt-injection-chain vendor-disclosed CVE rules** — sourced
  after checking whether `sigma_scout` (this monorepo's deterministic
  vendor-blog discovery funnel) had anything queued first; its 4-feed
  registry (GTIG/Microsoft/Cisco Talos/Unit42) returned an empty
  shortlist and one dead feed URL at authoring time, so these three came
  from the same `cve_lookup` + first-party-advisory process as the ten
  above:

  - `execution/observed_langroid_sqlchatagent_llm_rce_t1059.yml` —
    CVE-2026-25879 (CVSS 9.8). Langroid's `SQLChatAgent` executed
    LLM-generated SQL with no validation; prompt injection (including
    indirect, via data the agent reads back) could coerce it into
    emitting `COPY ... FROM PROGRAM`/`xp_cmdshell`-class primitives,
    reaching RCE on the database host when the configured role permits
    it. Filed under `execution`, not `credential_access` — this is
    command execution reached through a SQL interface, not a
    credential-theft primitive.
  - `execution/observed_pgadmin_ai_assistant_readonly_bypass_t1059.yml` —
    CVE-2026-12045 (CVSS 9.4). pgAdmin 4's AI Assistant wrapped
    LLM-generated SQL in `BEGIN TRANSACTION READ ONLY` but never
    restricted it to one statement; a payload starting with
    `COMMIT`/`END`/`ROLLBACK`/`ABORT` terminates that wrapper early,
    so everything after runs in ordinary autocommit mode.
  - `initial_access/observed_kong_konnect_mcp_indirect_prompt_injection_t1190.yml` —
    CVE-2026-13341. Kong's `mcp-konnect` server returned gateway
    analytics metadata (attacker-fully-controlled HTTP headers, e.g.
    User-Agent) to the AI agent without neutralization. The rule detects
    only the host-observable delivery vector (instruction-shaped header
    content); the advisory's separate path-manipulation half is not
    attempted since no example malformed identifier is quoted to key on.

  All three `validate_rule`-clean and convert cleanly to Splunk +
  Elasticsearch.

- **Three more MCP-ecosystem vendor-disclosed CVE rules**:

  - `initial_access/observed_network_ai_empty_default_secret_t1190.yml` —
    CVE-2026-48814 (CVSS 9.1). An "incomplete prior fix" case: an earlier
    advisory (CVE-2026-46701) closed the CORS hole, but the deeper bug —
    an empty-string default secret that the authorization check treats as
    always-authorized — survived untouched, leaving all 22 MCP tools
    reachable to any non-browser caller.
  - `execution/observed_windows_mcp_wildcard_cors_powershell_t1059_001.yml` —
    CVE-2026-48989 (CVSS 8.9). Wildcard CORS on an unauthenticated MCP
    control plane exposed a `PowerShell` tool that runs caller-controlled
    commands via `-EncodedCommand`; detection targets that specific
    process-execution artifact.
  - `lateral_movement/observed_foreman_mcp_session_id_disclosure_t1563.yml` —
    CVE-2026-12112 (Red Hat/Bugzilla 2488031). `foreman-mcp-server` caches
    authenticated sessions keyed by a non-secret `mcp-session-id`, logs
    every new one at INFO level, and never re-validates the
    `foreman_token` after the first request — the rule detects the
    disclosure half of the chain and says explicitly that the log-source
    signal alone cannot distinguish routine logging from active
    hijacking, since the vulnerable behavior is systemic on every session.

  All three `validate_rule`-clean and convert cleanly to Splunk +
  Elasticsearch.

- **Three MCP-ecosystem vendor-disclosed CVE rules**, selected for
  mechanism diversity rather than repeating the same unauthenticated-
  endpoint shape:

  - `initial_access/observed_mcp_pinot_unauth_confused_deputy_t1190.yml` —
    CVE-2026-49257 (CVSS 10.0). `mcp-pinot` defaulted OAuth off and bound
    to `0.0.0.0:8080`; the server proxied every call with its OWN Pinot
    credentials rather than the (nonexistent) caller identity — a
    confused-deputy, not merely a missing check.
  - `execution/observed_flowise_custom_mcp_header_spoof_rce_t1059.yml` —
    CVE-2025-71336 (CVSS 9.3). Flowise's Custom MCP endpoint trusted a
    spoofable `x-request-from: internal` header for internal-request
    classification; VulnCheck's corroborating PoC payloads (quoted in the
    rule) demonstrate direct OS command execution from one unauthenticated
    HTTP request.
  - `privilege_escalation/observed_mcp_toolbox_protocol_downgrade_scope_bypass_t1548.yml` —
    CVE-2026-11719 (Google's MCP Toolbox for Databases). Only the newest
    MCP protocol-version handler enforced per-tool `scopesRequired`; three
    older (still-supported) handlers omitted the check, and OMITTING the
    `MCP-Protocol-Version` header entirely defaulted to the most
    vulnerable one. Mapped to the T1548 parent technique rather than a
    sub-technique, since none of the existing sub-techniques describes a
    protocol-version selector silently disabling its own newest auth
    check.

  All three `validate_rule`-clean and convert cleanly to Splunk +
  Elasticsearch. `duplicate_rule_check.py` flags mcp-pinot and the
  corpus's existing Ruflo rule as sharing a (T1190, proxy) key —
  expected and non-blocking: two different CVEs/campaigns legitimately
  sharing one MITRE technique + logsource pairing, the same pattern this
  corpus already has for T1027 across 4 AI-fingerprint rules.

- **Three more vendor-disclosed CVE rules**, same sourcing discipline as
  the four above (first-party GHSA advisories):

  - `execution/observed_praisonai_claude_gha_branch_injection_t1059_004.yml` —
    CVE-2026-48168 (CVSS 10.0). PraisonAI's bundled Claude GitHub Actions
    workflow interpolated an unquoted, attacker-controlled PR branch name
    into a Bash `run:` block, with no `author_association` gate on the
    `@claude` trigger. Filed under `execution` (T1059.004) rather than
    `initial_access` like its GHA siblings, because the injection artifact
    is the branch-name string reaching the shell, not a trusted config file.
  - `initial_access/observed_agenticmail_bridge_wake_unverified_sender_t1566.yml` —
    CVE-2026-57495 (CVSS 8.2). An inbound email to AgenticMail's bridge
    inbox resumed a fully-privileged agent session
    (`permissionMode: 'bypassPermissions'`) with attacker-controlled
    `from`/`subject`/`preview` embedded verbatim into the resumed prompt,
    with no sender verification -- a sibling handler in the same codebase
    already had the equivalent check, and bridge-wake simply lacked it.
    Falsepositives section says plainly that on an unpatched install this
    is the systemic shape of every bridge-wake event, not an attack-only
    signature.
  - `collection/observed_claude_code_copy_tmp_symlink_t1552.yml` —
    CVE-2026-46406 (CVSS 4.4). Claude Code's `/copy` command wrote to a
    hardcoded `/tmp/claude/response.md` with no UID isolation or symlink
    protection, letting a local unprivileged user pre-plant a symlink and
    have a privileged user's `/copy` output overwrite an arbitrary file.
    Only the symlink-planting half is detected; the rule states outright
    that the read-disclosure half of the advisory is not something a host
    log can distinguish from a benign file read.

  All three `validate_rule`-clean and convert cleanly to Splunk +
  Elasticsearch.

- **Four MCP/agent-tooling vendor-disclosed CVE rules** (each sourced from a
  first-party GHSA security advisory, not a third-party restatement — the
  project disclosing its own vulnerability is the strongest form of
  attribution this corpus's sourcing bar recognizes). This is the corpus's
  first coverage of the MCP protocol's own request shape rather than a
  downstream OS-level effect, which is directly relevant to this plugin's
  own threat model since it is itself an MCP server:

  - `initial_access/observed_ruflo_mcp_bridge_unauth_terminal_execute_t1190.yml` —
    CVE-2026-59726 (CVSS 10.0). Ruflo's default `docker-compose` deployment
    exposed `POST /mcp` and `POST /mcp/:group` without authentication; the
    `terminal_execute` tool blocklist was enforced only in the autopilot
    flow, so these two endpoints bypassed it entirely.
  - `collection/observed_whatsapp_mcp_bridge_path_traversal_t1005.yml` —
    CVE-2026-46555 (CVSS 7.7). `whatsapp-mcp`'s bridge API on
    `127.0.0.1:8080` accepted an unconfined absolute `media_path`, plus no
    Host-header validation (DNS-rebinding reachable from a webpage).
  - `persistence/observed_claude_code_worktree_git_confusion_t1546_004.yml` —
    CVE-2026-55607 (CVSS 7.7). Claude Code allowed creating a git worktree
    literally named `.git`; combined with symlink manipulation and git
    fsmonitor execution this overwrote `.zshenv` outside the macOS seatbelt
    sandbox. Requires a chained prompt-injection precondition (cloning a
    malicious repo), noted explicitly in the rule rather than implied.
  - `initial_access/observed_claude_code_action_mcp_json_pr_rce_t1195_002.yml` —
    CVE-2026-47751 (CVSS 5.3). `claude-code-action` checked out the PR head
    branch and read `.mcp.json` from it with `enableAllProjectMcpServers`
    unconditionally on, letting a PR author's malicious MCP server command
    run on the Actions runner. Same root shape as this corpus's existing
    `observed_megalodon_github_actions_base64_payload_t1195_002` and
    `observed_tanstack_pwn_request_actions_cache_poisoning_t1195_002` —
    attacker PR content reaching a privileged CI context — distinct in the
    specific artifact abused (`.mcp.json`, not a workflow file or cache key).

  All four `validate_rule`-clean and convert cleanly to Splunk +
  Elasticsearch.

- **Three "Miasma" / "Phantom Gyp" npm supply-chain worm rules**
  (StepSecurity + Snyk, 2026-06-03 — two independent technical write-ups,
  cross-checked against each other rather than taken from a single vendor):

  - `initial_access/observed_miasma_binding_gyp_command_substitution_t1195_002.yml` —
    the initial code-execution stage: a 157-byte `binding.gyp` abuses gyp's
    `<!(...)` command-substitution syntax so `npm install`'s automatic
    `node-gyp rebuild` runs an attacker command with no
    preinstall/postinstall script declared in `package.json`. Detection
    keys on a `node-gyp` build step immediately followed by a Bun binary
    fetch/execution in the same process lineage — Bun has no legitimate
    reason to appear inside a native-addon compile step, and the campaign
    uses Bun specifically because process-tree monitors that only watch
    `node.exe` children miss it.
  - `persistence/observed_miasma_ai_ide_config_poisoning_t1546.yml` — the
    standout TTP: the worm writes auto-executing config into every
    AI-assisted IDE/agent integration it finds (`.claude/setup.mjs`,
    `.cursor/rules/setup.mdc`, `.gemini/settings.json`,
    `.vscode/tasks.json`, `.github/setup.js`), so the backdoor re-fires the
    next time a developer opens the project with an AI coding tool. Mapped
    to the T1546 parent technique rather than a sub-technique, because none
    of the existing sub-techniques describes an AI tool's own
    project-open hook. Not covered by any prior rule in this corpus.
  - `exfiltration/observed_miasma_github_graphql_exfil_t1567_001.yml` — the
    worm self-propagates via the GitHub GraphQL API's `createCommitOnBranch`
    mutation (not a plain `git push`) and exfiltrates stolen credentials as
    RSA-encrypted JSON to newly created private repos under a themed naming
    convention (Dune terms, Greek-mythology terms) that StepSecurity
    documents verbatim. `level: medium`, not `high` like its two siblings —
    the naming-pattern half of the detection is weaker evidence on its own
    (a coincidental repo-name match is plausible), so the rule says so
    rather than overclaiming.

  All three `validate_rule`-clean (pySigma round-trip) and convert cleanly
  to both Splunk SPL and Elasticsearch Lucene — none is a correlation rule,
  so the Lucene-family conversion gap that affects 10 other rules in this
  corpus does not apply here.

- **`collection/observed_diffusers_weight_map_path_traversal_t1005.yml`** —
  CVE-2026-65920, an out-of-directory file read in HuggingFace Diffusers
  (≤ 0.39.0) reached by loading a malicious sharded checkpoint. Root cause read
  from the fix commit (`cee298c`): `_get_checkpoint_shard_files` took shard
  filenames verbatim from the checkpoint index's `weight_map` and joined them
  to the model directory, so `"../secret/SECRET.safetensors"` escaped it. The
  fix requires each entry to be a plain filename.

  The rule states its own telemetry requirement rather than assuming it: the
  manifestation is a file **read**, and Sysmon EventID 11 records writes, so it
  uses `category: file_access` (EventID 4663 / auditd) — the first rule in this
  corpus to do so. On a host without object-access auditing the rule cannot
  fire, which is not the same as clean. It also names the normalisation trap:
  a sensor that collapses `model/../secret/x` erases the traversal marker the
  detection keys on.

  Two sibling CVEs on the same AI-runtime watch list were deliberately **not**
  given rules. CVE-2026-17500 (null-pointer dereference) and CVE-2026-17501
  (uncontrolled recursion) are availability-only crashes in llama.cpp's
  JSON-schema→GBNF conversion; the only host signal is "the server died", which
  does not meet this corpus's bar for a named, specific detection.

## [1.4.0] - 2026-08-05

Corpus 80 → 100 rules, and OpenSearch joins the conversion targets. Landed on
`main` via #56, #57, #59 and #60.

### Added

- **Corpus 80 → 100 rules** (#59), in three groups. Four AI-fingerprint
  detectors on the `code_review` logsource (`ai_prose`, `unicode_watermark`,
  `ai_provenance`, `hallucinated_import`); six observed campaigns each bound to
  a named, dated incident (UNC1069/WAVESHAPER axios npm compromise, TanStack
  Pwn Request Actions cache poisoning, SharePoint CVE-2026-58644 w3wp shell
  spawn, N-able N-central CVE-2026-18577 cloudflared persistence, Storm-2949
  Azure management-plane credential harvest, keyv/cacheable npm worm ETH C2);
  and ten canonical templates (T1082, T1083, T1189, T1195.002, T1204, T1485,
  T1546, T1552.004, T1567.001, T1574). Nothing was invented to reach a round
  number — the corpus stopped at 94 when cross-verifiable material ran out, and
  three further candidates were rejected for single-source or self-contradictory
  IOCs. T1071.001 was checked and skipped: its frequency in the source corpus
  is 0.
- OpenSearch as a fifth conversion target (Lucene and PPL are separate
  targets; a test asserts they do not silently resolve to the same one).
- Processing pipelines are applied by `convert_rule` rather than ignored; an
  unknown pipeline name is an error, a missing pipeline package names itself
  in the returned envelope instead of a bare traceback.
- One new rule for each of the four thinnest ATT&CK tactics, plus the two
  correlation types the templates had not yet used and a previously-withheld
  privilege-escalation rule (#56).
- Coverage measurement is gated on again, and the Docker image is built and
  smoke-tested by speaking MCP to the container over stdio rather than
  assuming it starts.

### Fixed

- **`write_rule_yaml` date-regression guard** (#59). Found via a real
  near-miss: running the corpus migration overwrote an already-deployed,
  *fresher* rule with content re-rendered from a *stale* test fixture, silently
  backdating it. The guard refuses any write that would backdate a deployed
  rule; a blocked write means the source needs refreshing, not that the guard
  should be bypassed.
- **`mcp` 2.0.0 support, properly this time.** 1.3.0 responded to the SDK 2.0
  break by pinning `mcp<2`; this rewrites `server.py` to import
  `mcp.server.MCPServer` on 2.x and fall back to `mcp.server.fastmcp.FastMCP`
  on 1.x, so both majors work and CI runs the suite against both instead of
  excluding one.
- The Docker image shipped without the rule corpus baked in, so both MCP
  resources that read `resources/examples/` answered `ok: false` inside the
  container even though the same server worked outside it (#57).
- Placeholder `falsepositives:` entries (`REPLACE_ME` and similar) are gone
  from the corpus, and `validate_rule` now flags any that reappear.

## [1.3.0] - 2026-07-29

Corpus 73 → 80 rules, and 12 → 13 tactic categories. The larger part of this
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
