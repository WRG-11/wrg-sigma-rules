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

Corpus 222 -> 253 rules (+31 observed actor-bound rules).

### Added

- **31 observed actor rules**, every one bound to an actor with at least one
  recorded incident in the upstream breach catalog. Tactic spread:
  initial_access 15, credential_access 3, impact 3, collection 2, execution 2,
  exfiltration 2, lateral_movement 2, command_and_control 1, defense_evasion 1.
  No new tactic directory -- all 14 categories already existed.
- All 31 carry `status: test`, lifting the corpus test tier from 8 to 39
  (3.6% -> 15.4% of 253). `status: stable` remains 0; nothing here is
  deploy-without-review.

### Changed

- **Eight rules moved from deprecated pipe-aggregation syntax to real Sigma
  correlation documents.** They previously carried
  `condition: selection | count() by <field> > N in Nm`, which pySigma rejects
  outright (`SigmaConditionError: the pipe syntax ... has been deprecated and
  replaced by Sigma correlations`) -- not a lint warning, a hard parse failure.
  Each is now a two-document file: the base rule matches single events, and a
  `---`-separated correlation document carries the threshold. The counting
  intent is preserved exactly (same group-by field, same window, same
  threshold); a strict `> N` becomes `condition: {gte: N+1}`, since "more than
  N" means "N+1 or more" and writing `gte: N` would silently widen every one of
  them by one event. Correlation rules: 10 -> 18.
- The correlation type on those rules is `event_count`, not `value_count`.
  `value_count` counts distinct values of a named field and pySigma requires a
  `field:` reference for it; none of these entries had one, and all of them
  group by a field while counting events. The label had been wrong from the
  start and nothing read it closely enough to notice.
- Actor tags now use the `wrg.observed.actor.<id>` form the rest of the corpus
  already used (778 existing occurrences), replacing the `wrg.actor.<id>` form
  the generator emitted. Bare `wrg.observed` added alongside.
- `falsepositives` on skeleton rules now opens with Sigma's own `Unknown`
  convention instead of a developer to-do ("Phase 6 v1 placeholder detection --
  bind to a real pattern before deployment"). That field is read by whoever
  deploys the rule; it should answer "what legitimate activity trips this",
  not describe work we still owe ourselves.

### Fixed

- `scripts/migrate_sigma_corpus.py` reads multi-document rule files. Three
  `yaml.safe_load` call sites raised `ComposerError` on the correlation pairs;
  two of them had no handler and would crash the script outright, and the third
  -- the date-regression guard -- swallowed the error as `return None`, which
  silently disabled backdate protection for exactly the 18 rules that needed
  it. Measured before the fix: 235 of 253 corpus files parsed, 18 did not.
- Redaction now genericises internal wave-dispatch ids (`internal wave`).
  The public corpus had zero prior instances; 7 leaked in across 3 of the
  staged rules, two of them inside `falsepositives`. The reasoning in each
  comment survives -- only the internal tracking number goes.

### Notes

- The DEMO coverage block is quoted from the live resource and was re-read off
  it rather than incremented: rules 222 -> 253, incident rules 156 -> 187,
  distinct techniques 87 -> 88. Pattern rules (66) and tactic groupings (14)
  were already correct.

## [1.5.0] - 2026-08-12

Corpus 100 → 222 rules.

### Added

- **Fifteen Flowise rules — this corpus's first agentflow/low-code-LLM-
  builder theme**, out of ~23 high/critical Flowise CVEs disclosed in a
  single window; 15 selected for technique diversity rather than
  exhausting every CVE (several additional CSVAgent/sandbox-escape
  variants were left uncovered as redundant with the mechanisms below):

  - `credential_access/observed_flowise_oauth2_refresh_whitelisted_token_leak_t1528.yml` —
    CVE-2026-70478. The OAuth2 refresh endpoint is whitelisted from all
    authentication and returns the live `access_token` in its response
    body.
  - `privilege_escalation/observed_flowise_stripe_subscription_idor_t1548.yml` —
    CVE-2026-70476. Billing endpoints trust a client-supplied
    `subscriptionId` with no ownership check against the caller's
    organization.
  - `credential_access/observed_flowise_oauth2_credential_workspace_scoping_missing_t1552.yml` —
    CVE-2026-70474. Three OAuth2 credential handlers look up by `id`
    alone with no `workspaceId` filter; two are additionally
    whitelisted from auth.
  - `collection/observed_flowise_upsert_history_server_wide_disclosure_t1005.yml` —
    CVE-2026-70473. `GET /api/v1/upsert-history` returns the entire
    server-wide history unscoped (>100MB in the vendor's own PoC).
  - `execution/observed_flowise_csvagent_datauri_pyodide_bridge_rce_t1059.yml` —
    CVE-2026-69264 (CVSS 9.9). A `csvFile` data-URI segment is
    interpolated verbatim into a Python template; escaping the string
    literal reaches Pyodide's `js` bridge and Node's `child_process`.
  - `defense_evasion/observed_flowise_python_validator_unicode_homoglyph_bypass_t1027.yml` —
    CVE-2026-70470. The Python code validator's `\b`-anchored regex
    blacklist is ASCII-only; PEP 3131 NFKC-normalizes Unicode
    homoglyphs back to the blocked identifiers at parse time.
  - `defense_evasion/observed_flowise_mcp_npm_config_yes_env_bypass_t1562_001.yml` —
    CVE-2026-69263, a patch bypass of CVE-2025-8943. `npm_config_yes`
    reproduces the blocked `--yes` flag; the env-var denylist checks
    only four hardcoded names.
  - `impact/observed_flowise_chatflow_delete_resource_type_confusion_t1485.yml` —
    CVE-2026-69262. Either `chatflows:delete` or `agentflows:delete`
    deletes either flow type — permission domains aren't bound to
    resource type.
  - `execution/observed_flowise_sqlite_recordmanager_database_path_override_rce_t1059.yml` —
    CVE-2026-69259. `additionalConfig` spreads after the intended
    `database` path, silently overwriting it; combined with SQLite
    binary-encoding injection, becomes an RCE via a Chromium config
    file.
  - `impact/observed_flowise_overrideconfig_ungated_flow_context_injection_t1565_001.yml` —
    CVE-2026-69258. Two spreads into `flowConfig`/`flowData` were
    missed by an earlier `overrideConfig` fix — unauthenticated session
    hijack and chat-history injection.
  - `initial_access/observed_flowise_ipv4_mapped_ipv6_ssrf_bypass_t1190.yml` —
    CVE-2026-69257. `ipaddr.js` `.kind()` reports `'ipv6'` for
    IPv4-mapped addresses vs. `'ipv4'` for deny-list CIDR entries — the
    mismatch skips every IPv4 SSRF deny rule.
  - `privilege_escalation/observed_flowise_nodevm_options_spread_sandbox_escape_t1611.yml` —
    CVE-2026-69254. Caller-supplied `nodeVMOptions` spreads after the
    sandbox defaults, re-enabling `child_process` inside a nested VM —
    verified root RCE.
  - `impact/observed_flowise_files_endpoint_missing_permission_check_t1485.yml` —
    CVE-2026-69252. `/api/v1/files` is gated by a feature flag only;
    any API key, regardless of granted permissions, lists and deletes
    other workspaces' files.
  - `execution/observed_flowise_typeorm_datasource_entities_rce_t1059.yml` —
    CVE-2026-69251. Five nodes grant unrestricted TypeORM `DataSource`
    options via `additionalConfig`; `entities` loads and executes
    arbitrary JavaScript.
  - `credential_access/observed_flowise_vars_injection_bypasses_permission_t1552.yml` —
    CVE-2026-70471. `$vars` is unconditionally injected into the
    custom-function sandbox with no `variables:view` check, exposing
    every workspace secret including `process.env`-backed runtime
    variables.

  All 15 validate_rule-clean, convert cleanly to Splunk + Elasticsearch
  on the first pass. INDEX.json regenerated (207→222), readme_stamp.py
  re-run, CHANGELOG corpus claim updated 207→222, DEMO.md Summary
  re-read from the live resource. Full suite: 669 passed. `claude
  plugin validate .` passed. This batch closes the 222-rule target set
  for this work session.

- **Four NLTK rules — the corpus's first non-runtime AI/NLP-tooling
  theme**, sourced from `gh api advisories?ecosystem=pip` filtered to
  high/critical severity:

  - `initial_access/observed_nltk_pathsec_dns_rebind_ssrf_bypass_t1190.yml` —
    CVE-2026-12075 (CVSS 8.6). `pathsec.urlopen()` validates a
    hostname's resolved IP, then hands the raw hostname to `urllib`,
    which resolves it AGAIN independently at connect time — a TTL-0
    DNS-rebinding record defeats the filter even under strict
    `ENFORCE = True`.
  - `impact/observed_nltk_reviews_corpus_reader_redos_t1499.yml` —
    CVE-2026-12061 (CVSS 7.5). The `FEATURES` regex's unbounded label
    sub-pattern causes O(n²) backtracking on a long bracket-less
    line — a single ~100,000-word line hangs the reader for minutes.
  - `collection/observed_nltk_nkjp_corpus_reader_path_traversal_t1005.yml` —
    CVE-2026-12072 (CVSS 7.5). `NKJPCorpusReader` builds file paths by
    plain string concatenation and opens them with the builtin
    `open()`, bypassing the `pathsec` sandbox's `PathPointer`-only
    enforcement entirely.
  - `collection/observed_nltk_framenet_corpus_reader_path_traversal_t1005.yml` —
    CVE-2026-12074 (CVSS 7.5). Same builtin-`open()`-bypasses-sandbox
    class as the NKJP rule above, but in `FramenetCorpusReader.frame()`
    — a distinct reader class and code path with its own CVE.

  All 4 validate_rule-clean, convert cleanly to Splunk + Elasticsearch.
  INDEX.json regenerated (203→207), readme_stamp.py re-run, CHANGELOG
  corpus claim updated 203→207, DEMO.md Summary re-read from the live
  resource. Full suite: 639 passed. `claude plugin validate .` passed.

- **Ten more rules: two new runtimes (Flyto2 Core AI-agent workflow
  engine, AWS Bedrock AgentCore SDK), one MCP server (AWS API MCP
  Server), and four more Open WebUI access-control/auth gaps**, sourced
  by cross-checking `gh api advisories` against pip-ecosystem
  high/critical CVEs not yet covered by this corpus:

  - `initial_access/observed_flyto2_http_redirect_ssrf_revalidation_gap_t1190.yml` —
    CVE-2026-67424 (CVSS 8.6). Flyto2's guarded HTTP modules validate
    only the initial URL; aiohttp's default `allow_redirects=True`
    follows a 302 into internal/metadata space with no per-hop
    revalidation.
  - `initial_access/observed_flyto2_sibling_modules_missing_ssrf_guard_t1190.yml` —
    CVE-2026-67428 (CVSS 8.6). A dozen HTTP-emitting modules carry an
    inert `ssrf_protected` metadata tag but never call the guard their
    siblings apply — direct-IP SSRF to cloud metadata, no encoding
    trick needed.
  - `credential_access/observed_flyto2_env_interpolation_denylist_bypass_t1552.yml` —
    CVE-2026-67427 (CVSS 8.6). `${env.VAR}` template interpolation
    resolves any host environment variable with no allowlist, bypassing
    the `env.get` module denylist the vendor built specifically to
    block secret exfiltration.
  - `command_and_control/observed_flyto2_image_download_arbitrary_file_write_t1105.yml` —
    CVE-2026-67429 (CVSS 8.6). `image.download`'s path check validates
    the target against a caller-supplied `output_dir` — the attacker
    controls both the value and the base it's checked against — so
    arbitrary attacker-hosted bytes land outside `FLYTO_SANDBOX_DIR`.
  - `execution/observed_bedrock_agentcore_install_packages_extras_metachar_injection_t1059.yml` —
    CVE-2026-16796. The pre-1.18.1 extras-group regex accepted any
    character inside `[...]`, and specifiers were joined without shell
    quoting — `requests[$(id)]` reached a shell intact inside the Code
    Interpreter sandbox.
  - `defense_evasion/observed_aws_api_mcp_server_policy_load_failure_silent_bypass_t1562_001.yml` —
    CVE-2026-16584. A startup security-policy load failure logs and
    continues rather than failing closed — the per-request deny/gate
    check is silently skipped for the process's entire lifetime.
  - `defense_evasion/observed_open_webui_terminal_proxy_9x_encoding_traversal_bypass_t1027.yml` —
    CVE-2026-59221, an incomplete fix for an earlier terminal-proxy
    traversal. The sanitizer's fixed 8-round decode cap lets a 9x
    percent-encoded `../` survive as literal text through the traversal
    check, then get re-decoded by the upstream terminal server.
  - `privilege_escalation/observed_open_webui_terminal_identity_spoofing_unsigned_forward_t1548.yml` —
    CVE-2026-59224. The terminal WebSocket path concatenates an
    unvalidated, unencoded `session_id` into the upstream URL — an
    encoded `?`/`&` injects an attacker-chosen `user_id` ahead of the
    one Open WebUI appended.
  - `impact/observed_open_webui_channel_message_cross_channel_overwrite_t1565_001.yml` —
    CVE-2026-59714. A `channel:`-prefixed `chat_id` skips ownership
    verification entirely; a caller-supplied `message_id` (or
    multimodel `message_ids` map) writes directly to the `Messages`
    table with no channel-membership check.
  - `credential_access/observed_open_webui_realtime_revoked_jwt_accepted_t1550.yml` —
    CVE-2026-59219. Socket.IO and terminal-WebSocket auth call
    `decode_token()` only — never consulting the Redis revocation keys
    HTTP auth checks — so a JWT revoked by sign-out or back-channel
    logout still authenticates new realtime connections.

  Flyto2 and AWS advisories were fetched via `gh api advisories?cve_id=`
  for full technical detail (root cause, source line, PoC); the
  Bedrock AgentCore and AWS API MCP Server rules were additionally
  cross-checked against the actual current source (fix commit diff for
  the former, the live `policy.py` log message text for the latter) to
  confirm the manifestation claim independent of the advisory's own
  wording. 13 candidate Open WebUI CVEs from the W-cohort radar batch
  were checked first; only 4 were not already covered.

  All 10 validate_rule-clean, convert cleanly to Splunk + Elasticsearch.
  INDEX.json regenerated (193→203), readme_stamp.py re-run, CHANGELOG
  corpus claim updated 193→203, DEMO.md Summary re-read from the live
  resource. Full suite: 631 passed. `claude plugin validate .` passed.

- **Two more Open WebUI rules, found via the W-cohort `ai_runtime_cve_radar`
  archive after cross-checking 13 candidate CVEs against the existing
  corpus (11 were already covered by earlier entries in this file)**:

  - `privilege_escalation/observed_open_webui_chat_features_image_gen_permission_bypass_t1548.yml` —
    CVE-2026-70484 (CVSS 4.3). The two direct image routes and the
    native function-calling path all re-check the caller's
    `image_generation` permission; the legacy chat-completions path
    dispatches on the client-supplied `features` flag alone, letting a
    permission-revoked user still trigger generation and spend the
    operator's provider quota.
  - `impact/observed_open_webui_knowledge_search_catastrophic_backtrack_dos_t1499.yml` —
    CVE-2026-70493 (CVSS 6.5). The built-in `grep_knowledge_files` tool
    compiles a caller-chosen pattern with the backtracking `re` engine
    and no time limit; a pattern like `(x|x)*y` grows exponentially with
    subject length (measured: 30 chars → 74s) and, running synchronously
    on the shared event loop, starves every other request the worker is
    serving.

  All 2 validate_rule-clean, convert cleanly to Splunk + Elasticsearch.
  INDEX.json regenerated (191→193), readme_stamp.py re-run, CHANGELOG
  corpus claim updated 191→193, DEMO.md Summary re-read from the live
  resource. Full suite: 611 passed.

- **Four more rules: one stable-diffusion.cpp sibling bug, three Open WebUI
  access-control gaps**:

  - `collection/observed_stable_diffusion_cpp_ckpt_missing_bounds_check_oob_read_t1005.yml` —
    CVE-2026-47748 (CVSS 5.5). A distinct root cause from this corpus's
    sign-confusion `.ckpt` write bugs: throughout the pickle parser,
    opcode handlers advance the buffer position (`buffer += N`) without
    checking `buffer + N <= buffer_end` first — a simply-truncated
    `.ckpt` file causes reads past the metadata buffer. LibFuzzer found
    crashes in under one second against malformed inputs.
  - `impact/observed_open_webui_skill_mention_regex_redos_t1499.yml` —
    CVE-2026-59220 (CVSS 6.5). `SKILL_MENTION_RE` / `strip_re` use
    overlapping quantifiers; a chat message containing `<$` with no
    closing `>` triggers quadratic backtracking on the shared `asyncio`
    event loop, blocking every other in-flight request, not just the
    sender's.
  - `privilege_escalation/observed_open_webui_arena_task_endpoint_submodel_bypass_t1548.yml` —
    CVE-2026-59225 (CVSS 5.4). The normal chat route resolves an arena
    wrapper's underlying model before re-checking that model's access
    permission; task endpoints instead call
    `generate_chat_completion()` directly, resolving arena fallback
    AFTER the wrapper's own check and recursing with
    `bypass_filter=True` — skipping the submodel's access check
    entirely.
  - `privilege_escalation/observed_open_webui_image_edit_permission_check_missing_t1548.yml` —
    CVE-2026-59227 (CVSS 4.3). `POST /api/v1/images/edit` required only
    a VERIFIED account — it never checked the deployment's global
    image-edit switch or the caller's per-user image-generation
    permission, letting any verified non-admin invoke server-side
    image editing on the administrator's provider credentials.

  All 4 validate_rule-clean, convert cleanly to Splunk + Elasticsearch.
  INDEX.json regenerated (187→191), readme_stamp.py re-run, CHANGELOG
  corpus claim updated 187→191, DEMO.md Summary re-read from the live
  resource. Full suite: 607 passed. `claude plugin validate .` passed.

- **Five more rules: four Open WebUI, one stable-diffusion.cpp sibling
  bug**:

  - `impact/observed_open_webui_calendar_event_destination_bypass_t1565_001.yml` —
    CVE-2026-54006. Event-update validates write access to the SOURCE
    calendar but never checks the destination `calendar_id` — moves an
    event into any calendar whose id is known.
  - `collection/observed_open_webui_image_url_file_id_ocr_exfil_t1005.yml` —
    CVE-2026-54009 (CVSS 6.5). A non-URL `image_url.url` value resolves
    as a raw file id with no ownership check; the file is read,
    base64-encoded, and injected into the LLM request — attacker OCRs
    a victim's private file back through the model's own response.
  - `collection/observed_open_webui_upload_knowledge_id_writeaccess_bypass_t1005.yml` —
    CVE-2026-59217. File upload's `metadata.knowledge_id` auto-link
    skips the write-access check the dedicated `/file/add` endpoint
    correctly enforces — a read-only KB user adds files anyway.
  - `discovery/observed_open_webui_signin_timing_account_enumeration_t1087.yml` —
    CVE-2026-59218. bcrypt only runs when an email lookup matches, so
    registered accounts respond measurably slower — a timing
    side-channel for account enumeration. Filed under `discovery`
    (T1087), not `credential_access` — corrected mid-authoring after
    initially placing it wrong.
  - `execution/observed_stable_diffusion_cpp_ckpt_global_opcode_heap_overflow_t1059.yml` —
    CVE-2026-47750 (CVSS 7.8). The `GLOBAL` opcode's sibling bug to the
    already-covered `SHORT_BINUNICODE` one, same file, same disclosure
    round, same fix commit — a missing newline yields a `-1` copy
    length reaching `memcpy` directly.

  All five `validate_rule`-clean and convert cleanly to Splunk +
  Elasticsearch.

- **Five more Open WebUI rules, remaining CVEs from the 2026-06-23
  disclosure batch**:

  - `execution/observed_open_webui_mermaid_loose_security_xss_t1059_007.yml` —
    CVE-2026-54011 (CVSS 8.7). Mermaid diagrams render with
    `securityLevel: 'loose'` and the SVG output goes into `innerHTML` —
    a working payload was validated through the Markdown file-preview
    path specifically.
  - `collection/observed_open_webui_model_metadata_knowledge_file_bypass_t1005.yml` —
    CVE-2026-54012 (CVSS 7.1). `meta.knowledge` entries on a model are
    stored with no ownership check; `view_file` and
    `has_access_to_file()`'s model branch both trust them downstream —
    a sibling bug class to this corpus's shared-chat file-ownership
    rule, different vector.
  - `execution/observed_open_webui_model_profile_svg_xss_takeover_t1059_007.yml` —
    CVE-2026-54013 (CVSS 7.6). A prior SVG-XSS fix for user/webhook
    profile images was never applied to MODEL profile images —
    `ModelMeta` has no validator, full account takeover just from
    navigating to the image URL.
  - `collection/observed_open_webui_cache_serve_prefix_traversal_t1005.yml` —
    CVE-2026-54014. `serve_cache_file()`'s containment check uses
    `startswith(CACHE_DIR)` with no trailing separator — the classic
    prefix-bypass bug (`cache_sibling`, `cache_backup` all pass).
  - `initial_access/observed_open_webui_milvus_collection_name_injection_t1190.yml` —
    CVE-2026-54019. Milvus-multitenancy mode lets an unescaped,
    user-controlled collection name become a `resource_id` interpolated
    into a Milvus query expression — an incomplete fix for an earlier
    CVE that closed a different path.

  All five `validate_rule`-clean and convert cleanly to Splunk +
  Elasticsearch. One more instance of the backtick-colon YAML footgun
  caught and fixed.

- **Four more rules — one candidate (CVE-2026-12491, EXIF/PNG
  transparency mishandling) rejected as a data-integrity bug, not a
  security signal a detection rule can act on:**

  - `impact/observed_vllm_audio_decompression_bomb_t1499.yml` —
    CVE-2026-54233. The compressed-upload size limit ignores decoded
    PCM expansion — advisory's own measured ratio: 25MB OPUS decodes to
    ~14.9GB float32 PCM.
  - `execution/observed_stable_diffusion_cpp_ckpt_sign_confusion_heap_overflow_t1059.yml` —
    CVE-2026-47749 (CVSS 7.8). `.ckpt` pickle parser's
    `SHORT_BINUNICODE` length field has a sign-confusion bug; a
    negative-interpreted length reaches `memcpy` directly. First
    stable-diffusion.cpp (C/C++ memory corruption) rule in this corpus.
  - `execution/observed_open_webui_cross_origin_postmessage_prompt_injection_t1059.yml` —
    CVE-2026-54007 (CVSS 7.1). The chat listener accepts
    `input:prompt`/`action:submit` `postMessage` events with no
    same-origin check — an external page triggers `submitPrompt()` in
    an authenticated victim's tab.
  - `collection/observed_open_webui_shared_chat_file_ownership_bypass_t1005.yml` —
    CVE-2026-54010 (CVSS 8.3). Attaching a `file_id` to a chat message
    skips the ownership check; sharing that chat then makes
    `has_access_to_file()` treat the victim's file as accessible through
    the share.

  All four `validate_rule`-clean and convert cleanly to Splunk +
  Elasticsearch.

- **Four more rules: three vLLM, one more Open WebUI**, from the same
  older W-cohort archive batches:

  - `initial_access/observed_vllm_assert_security_check_optimized_mode_rce_t1195_002.yml` —
    CVE-2026-41523 (CVSS 7.5). A security check written as a plain
    `assert` is stripped entirely when vLLM runs under `python -O` /
    `PYTHONOPTIMIZE=1` — a common production-performance flag that
    silently removes the one line standing between an untrusted
    HuggingFace model and RCE.
  - `impact/observed_vllm_audio_upload_pre_limit_memory_exhaustion_t1499.yml` —
    CVE-2026-55646. Audio-transcription endpoints call
    `request.file.read()` to fully buffer an upload BEFORE checking the
    configured size limit — an oversized request was always going to be
    rejected, but only after paying for the full allocation first.
  - `impact/observed_vllm_mrope_prompt_embeds_assertion_crash_t1499.yml` —
    CVE-2026-55514 (CVSS 7.1). A pure prompt-embeds payload against an
    M-RoPE model fails an internal `EngineCore` assertion — fatal, not
    request-scoped, taking down the whole server from one ordinary,
    authorized request.
  - `initial_access/observed_open_webui_playwright_redirect_ssrf_bypass_t1190.yml` —
    CVE-2026-54018 (CVSS 7.7). `SafePlaywrightURLLoader` validates only
    the initial URL; Playwright follows redirects automatically, so a
    safe URL redirecting to an internal address bypasses the check
    entirely. Mechanistically distinct from this corpus's other
    Playwright SSRF rule (sub-resource requests vs. HTTP redirects).

  All four `validate_rule`-clean and convert cleanly to Splunk +
  Elasticsearch.

- **Three vLLM rules — another new runtime family**, sourced from older
  W-cohort archive batches (vLLM had no prior coverage in this corpus):

  - `initial_access/observed_vllm_hardcoded_trust_remote_code_bypass_t1195_002.yml` —
    CVE-2026-4944 (CVSS 8.8). Two model files hardcode
    `trust_remote_code=True`, silently overriding the operator's own
    `--trust-remote-code=False` — an incomplete fix for two PRIOR CVEs
    that missed these code paths.
  - `impact/observed_vllm_sparse_tensor_multimodal_dos_t1499.yml` —
    CVE-2026-56340 (CVSS 8.7). Missing sparse-tensor index validation in
    multimodal embeddings; PyTorch disables invariant checks by default,
    so malformed indices reach unchecked ops — a continuation of an
    earlier CVE whose fix only flipped a feature default rather than
    validating.
  - `impact/observed_vllm_structured_outputs_regex_redos_t1499.yml` —
    CVE-2026-55574 (CVSS 8.7). `structured_outputs.regex` has no
    compilation timeout; the `outlines` backend blocks unsafe regex
    constructs structurally but does no complexity analysis, so nested
    quantifiers pass every check while still exploding combinatorially.

  All three `validate_rule`-clean and convert cleanly to Splunk +
  Elasticsearch.

- **Six SGLang rules — a brand-new runtime family for this corpus**,
  from a coordinated multi-CVE disclosure series (independent researcher
  + SGLang's own GHSA advisories, same week) plus one CERT/CC-noted bug
  verified directly against the cited source file:

  - `execution/observed_sglang_lora_adapter_safeunpickler_bypass_rce_t1059.yml` —
    CVE-2026-15969 (CVSS 9.8). `/load_lora_adapter_from_tensors`'s
    `SafeUnpickler` denylist is incomplete; a crafted base64-pickle
    payload reaches unauthenticated RCE.
  - `execution/observed_sglang_dumper_subsystem_sandbox_escape_t1059.yml` —
    CVE-2026-15971 (CVSS 9.8). The optional dumper subsystem
    (`DUMPER_SERVER_PORT`) enables sandbox escape on ordinary inference
    requests once enabled.
  - `execution/observed_sglang_weights_from_disk_pickle_rce_t1059.yml` —
    CVE-2026-15976 (CVSS 9.8). `/update_weights_from_disk` falls back to
    `torch.load(weights_only=False)` — PyTorch's own docs call this
    unsafe for untrusted input — on `.bin` files pulled from a
    caller-directed HuggingFace repo.
  - `credential_access/observed_sglang_server_info_credential_leak_t1552.yml` —
    CVE-2026-15977 (CVSS 7.5). `/server_info` returns API keys and SSL
    keyfile info when only `--admin-api-key` is configured.
  - `exfiltration/observed_sglang_nccl_weight_broadcast_exfil_t1041.yml` —
    CVE-2026-15978 (CVSS 7.5). With no API key configured, two endpoints
    chained trigger NCCL distributed weight broadcasting then a data
    transfer — exfiltrates the entire served model.
  - `initial_access/observed_sglang_expert_backup_zeromq_pull_rce_t1190.yml` —
    CVE-2026-14890 (CVSS 9.1). A ZeroMQ PULL socket bound to a routable
    interface has no auth and no deserialization safeguard; verified
    directly against `expert_backup_manager.py` (bind address, port
    formula, and the client-count-only gate quoted from the source
    itself, not just the advisory).

  All six `validate_rule`-clean and convert cleanly to Splunk +
  Elasticsearch. Deliberately excluded from this batch: llama.cpp's
  CVE-2026-17500/17501 (already named and rejected in this corpus's
  Diffusers rule's own description — availability-only crashes with no
  signal beyond "the server died") and the already-covered
  CVE-2026-65920.

- **Five more CVE rules from earlier W-cohort radar batches the same
  day** (05:00-07:00 + one earlier 2026-08-04 batch), one from a
  different vendor entirely:

  - `credential_access/observed_open_webui_oauth_token_exchange_audience_confusion_t1528.yml` —
    CVE-2026-70482 (CVSS 8.1). Token-exchange validates a raw provider
    token via userinfo but never confirms which OAuth CLIENT it was
    issued to — any token minted for any client on the same provider
    exchanges for a session.
  - `initial_access/observed_open_webui_playwright_subresource_ssrf_t1190.yml` —
    CVE-2026-70479 (CVSS 7.7). Playwright loader validates only the
    top-level page; sub-resource requests the rendered page's own JS
    issues reach blocked internal addresses unchecked.
  - `initial_access/observed_open_webui_vega_resource_loader_ssrf_t1190.yml` —
    CVE-2026-70480. Vega/vega-lite chart rendering has no restricted
    resource loader — a chart spec in a shared chat makes the VIEWER's
    browser issue attacker-chosen GETs.
  - `collection/observed_nvidia_triton_mlflow_model_name_traversal_t1005.yml` —
    CVE-2026-47487. A different vendor (NVIDIA) — Triton's MLflow plugin
    builds a filesystem path from a caller-supplied model name with no
    repository confinement.
  - `initial_access/observed_open_webui_nat64_ipv6_transition_ssrf_t1190.yml` —
    CVE-2026-70485 (CVSS 7.1). `ipaddress.is_global` checks the literal
    IPv6 form but not IPv4 addresses embedded in NAT64 transition
    encoding — the same class of wrapper-vs-unwrapped-target bug as
    Pydantic AI's, here in Open WebUI's own URL-ingest path.

  All five `validate_rule`-clean and convert cleanly to Splunk +
  Elasticsearch. Two more instances of the bare-`127.`-parsed-as-float
  YAML footgun caught and quoted before commit.

- **Four more Open WebUI CVE rules, remaining W-cohort radar output from
  the same 2026-08-11 batch**:

  - `collection/observed_open_webui_knowledge_file_id_cross_user_read_t1005.yml` —
    CVE-2026-70487. Inline knowledge attachments skip the per-file read
    filter; a guessable file id returns another user's indexed chunks.
  - `impact/observed_open_webui_sync_cleanup_cross_kb_delete_t1485.yml` —
    CVE-2026-70488. Sync-cleanup authorizes write on the URL's knowledge
    base but acts on body-supplied ids without checking they belong to
    it — write access to KB-A deletes files from KB-B.
  - `impact/observed_open_webui_automation_recurrence_dos_t1499.yml` —
    CVE-2026-70489 (CVSS 6.5). Minutely/hourly recurrence rules anchor at
    a fixed `2000-01-01` epoch and walk forward synchronously — a single
    `FREQ=MINUTELY` rule enumerates ~25 years on the same event loop
    serving every other user's traffic. First `T1499` (DoS) rule in this
    corpus.
  - `credential_access/observed_open_webui_tool_source_field_readmission_t1552.yml` —
    CVE-2026-70491 (CVSS 6.5). `ToolResponse` deliberately omits
    `source`/`specs`; a sibling model (`ToolUserResponse`) permits extra
    fields and handlers spread the full model dump, re-admitting them —
    non-admin read access leaks tool source with embedded API keys.

  All four `validate_rule`-clean and convert cleanly to Splunk +
  Elasticsearch. (A third instance of the same YAML footgun as the last
  two rounds — a falsepositives line containing `` `text: like this` ``
  parsed as a mapping key on the colon inside the backticks — caught and
  fixed by quoting the whole line.)

- **Five more Open WebUI CVE rules, sourced from WinstonRedGuard's own
  `ai_runtime_cve_radar` sentry** (cohort W in the monorepo this plugin
  ships from) instead of another ad-hoc `cve_lookup` keyword sweep — the
  radar already polls hourly and had flagged 10 new AI-runtime CVEs
  earlier today, all quoting exact source files/lines in their NVD
  entries:

  - `execution/observed_open_webui_katex_stack_overflow_xss_t1059_007.yml` —
    CVE-2026-70492 (CVSS 8.7). `KatexRenderer.svelte`'s stack-overflow
    catch branch renders the raw math source via `{@html}` instead of
    escaped text — stored XSS in shared chats, steals the viewer's
    session token.
  - `execution/observed_open_webui_terminal_preview_iframe_sandbox_t1059_007.yml` —
    CVE-2026-70486 (CVSS 8.2). Terminal file-preview's iframe always
    granted `allow-same-origin` WITH `allow-scripts` for same-origin
    HTML — the combination the sandbox spec itself warns defeats origin
    isolation.
  - `initial_access/observed_open_webui_dns_rebind_toctou_ssrf_t1190.yml` —
    CVE-2026-54020. Classic TOCTOU: hostname validated against one DNS
    answer, HTTP client resolves again at connection time — a
    DNS-rebinding attacker flips public->private between the two,
    reaching cloud metadata; the OAuth profile-picture path forwards the
    victim's OAuth token to wherever the second answer points.
  - `impact/observed_open_webui_folder_delete_ownership_bypass_t1485.yml` —
    CVE-2026-70494 (CVSS 8.1). `DELETE /api/v1/folders/{id}`'s subfolder
    check accepts any inherited WRITE grant instead of requiring
    ownership — a collaborator can destroy the folder owner's entire
    chat subtree.
  - `privilege_escalation/observed_open_webui_terminal_ws_role_gate_bypass_t1548.yml` —
    CVE-2026-70490 (CVSS 6.3). The terminal WebSocket route authenticates
    its JWT but skips the `get_verified_user` role gate the equivalent
    HTTP route enforces — a `pending`-role (unapproved) account reaches
    an interactive terminal.

  All five `validate_rule`-clean and convert cleanly to Splunk +
  Elasticsearch. (One more YAML slip: bare `127.`/`10.` list items parsed
  as floats rather than strings — fixed by quoting.)

- **Three more CVE rules**, all first-party Open WebUI/F5-TTS maintainer
  fixes:

  - `execution/observed_open_webui_socketio_session_hijack_t1059_007.yml` —
    CVE-2026-59216 (CVSS 7.7). `get_event_call()` delivers
    `execute:python`/`execute:tool` Socket.IO events to a caller-supplied
    `session_id` after checking only that it's connected, never who it
    belongs to; a victim's session_id leaks via `ydoc:document:join` when
    an attacker shares a document with them. Advisory quotes both the
    vulnerable code and the fix's ownership check verbatim.
  - `privilege_escalation/observed_open_webui_url_idx_backend_bypass_t1548.yml` —
    CVE-2026-54021. Indexed Ollama proxy routes use a caller-supplied
    `url_idx` as a raw list index with no authorization on the index
    itself — access control checks model permission, never which backend
    the request reaches, so an admin-disabled backend stays reachable.
  - `collection/observed_f5_tts_finetune_project_name_traversal_t1005.yml` —
    CVE-2026-43624 (CVSS 8.8). `os.path.join(base, project_name)` across
    ~10 call sites discards `base` entirely when `project_name` is
    absolute; fix PR quotes the exact before/after PoC directory.

  All three `validate_rule`-clean and convert cleanly to Splunk +
  Elasticsearch.

- **Three more CVE rules**, all first-party Gradio/RAGFlow maintainer
  fixes:

  - `collection/observed_gradio_fileexplorer_path_traversal_t1005.yml` —
    CVE-2026-49119 (CVSS 8.7). `FileExplorer.preprocess()`'s
    `os.path.join(root_dir, *segments)` silently discards `root_dir` on
    an absolute segment (a classic Python footgun); fix switches to the
    `_safe_join()` helper the component's `ls()` endpoint already used.
  - `initial_access/observed_gradio_file_fetch_ssrf_metadata_t1190.yml` —
    CVE-2026-59806. `/gradio_api/file=<url>` redirected to any supplied
    URL unvalidated; advisory quotes the before/after curl behavior
    against the AWS metadata endpoint verbatim.
  - `execution/observed_ragflow_agent_node_name_stored_xss_t1059_007.yml` —
    CVE-2026-58579 (CVSS 5.1). An agent DSL's node name survives
    `normalize_dsl` unsanitized and renders via
    `dangerouslySetInnerHTML` with i18next's `escapeValue: false` —
    stored XSS across the workspace trust boundary, not self-XSS. No
    specific payload is quoted in the source; the rule keys on the
    unsanitized-field -> `dangerouslySetInnerHTML` mechanism instead,
    stated explicitly rather than inventing a payload.

  All three `validate_rule`-clean and convert cleanly to Splunk +
  Elasticsearch. (One more YAML slip caught in validation: an unquoted
  `javascript:` list item parsed as an empty-mapping key rather than a
  string, because of the trailing colon -- fixed by quoting.)

- **Five more CVE rules; one candidate (AWS Bedrock AgentCore
  install_packages) rejected** — its source offered only a speculative,
  self-admitted "potentially" example rather than a quoted real payload:

  - `credential_access/observed_mem0_unauth_config_apikey_ssrf_t1552.yml` —
    CVE-2026-59706 (CVSS 9.2). mem0's config API leaks plaintext LLM API
    keys via an unauthenticated `GET`, and a separate `PUT` endpoint's
    caller-controlled `ollama_base_url` reaches internal/metadata
    addresses with no validation.
  - `collection/observed_ollama_gguf_heap_overread_exfil_t1005.yml` —
    CVE-2026-7482 (CVSS 8.8). Ollama's GGUF quantization path trusted a
    file's declared tensor offset/size without validating against actual
    file length, reading past the heap; the leaked bytes (env vars, API
    keys, other users' conversations) can be smuggled out via `/api/push`
    baked into the resulting model artifact.
  - `persistence/observed_ollama_windows_update_rce_startup_t1547_001.yml` —
    chained CVE-2026-42248 + CVE-2026-42249. Windows update verification
    unconditionally returns success (no signature check) AND the update
    path is built from unvalidated HTTP response headers passed to
    `filepath.Join` (traversal) — together, silent auto-update writes an
    unsigned executable straight into the Startup folder. No patched
    version confirmed by maintainers at authoring time, stated explicitly.
  - `execution/observed_code_runner_mcp_unauth_run_code_t1059.yml` —
    CVE-2026-5029. Code Runner MCP Server's `/mcp` endpoint (port 3088,
    HTTP transport) has no auth at all; `run-code` executes arbitrary
    submitted source via `child_process.exec()`. Unfixed in all versions
    at authoring time.
  - `execution/observed_gpt_sovits_webui_shell_injection_t1059.yml` —
    CVE-2026-63766 (CVSS 9.3). GPT-SoVITS's `webui.py` interpolates
    Gradio textbox values into `Popen(cmd, shell=True)` across four
    handlers; the project's own `clean_path()` strips quotes/whitespace
    but not shell metacharacters.

  All five `validate_rule`-clean and convert cleanly to Splunk +
  Elasticsearch. (One YAML syntax slip caught during validation: an
  unquoted falsepositives list item starting with `selection_name:` was
  parsed as a mapping key rather than list-item text — fixed by quoting.)

- **Four more CVE rules**, widening beyond the MCP/npm themes into
  code-sandbox internals:

  - `defense_evasion/observed_maxkb_sendto_fastopen_sandbox_bypass_t1562_001.yml` —
    CVE-2026-39418. MaxKB's sandbox hooks `connect()` via `LD_PRELOAD` to
    enforce a banned-hosts policy; `sendto()` with `MSG_FASTOPEN`
    establishes a TCP connection entirely kernel-side, never calling the
    hooked function.
  - `execution/observed_autogpt_redis_pickle_cache_poisoning_rce_t1059.yml` —
    CVE-2026-33233 (CVSS 7.6). AutoGPT's Redis cache read path calls bare
    `pickle.loads()` with no HMAC/schema check; advisory's own PoC proves
    RCE by creating a named file. Same bug class as any pickle-cache
    poisoning, cited here with the vendor's own captured proof.
  - `initial_access/observed_agenticmail_mcp_http_unauth_masterkey_tools_t1190.yml` —
    CVE-2026-50287 (CVSS 8.7). AgenticMail's MCP HTTP mode has no auth on
    `/mcp`; master-key-gated tools (`delete_agent`, `setup_email_relay`,
    etc.) still execute under the server's own master key regardless of
    caller auth. Distinct code path from this corpus's existing
    AgenticMail bridge-wake rule (same product, different vulnerability).
  - `defense_evasion/observed_maxkb_frame_introspection_result_spoofing_t1036.yml` —
    CVE-2026-39419. Sandboxed code reads its own wrapper's embedded UUID
    via `sys._getframe().f_code.co_consts`, then forges a matching result
    line written directly to fd 1 before `sys.exit(0)` — defeating the
    UUID-prefix trust mechanism entirely from inside the sandbox it's
    meant to constrain.

  All four `validate_rule`-clean and convert cleanly to Splunk +
  Elasticsearch.

- **Two more CVE rules; one candidate (Cursor Desktop hook execution)
  rejected** — its advisory states impact and fix in prose but names no
  concrete hook JSON, sandbox-escape mechanism, or example payload:

  - `initial_access/observed_microsoft_apm_symlink_dereference_deploy_t1195_002.yml` —
    CVE-2026-45539. Microsoft APM's file-discovery integrators used bare
    `Path.glob()`/`read_text()`, which follows symlinks; a remote
    dependency's committed symlink (advisory quotes the PoC `ln -s`
    commands) is dereferenced into `.github/`/`.claude/`/`.codex/` as a
    plain file, missed by all three controls in place (`content_hash`
    computed pre-dereference, `SecurityGate` walks with
    `followlinks=False`, `.gitignore` covers only `apm_modules/`).
  - `execution/observed_agno_clickhouse_metadata_sqli_t1059.yml` —
    CVE-2026-10105 (CVSS 8.7). agno's ClickHouse `delete_by_metadata()`
    f-string-interpolated caller-controlled metadata straight into SQL;
    advisory + fix PR quote both the vulnerable line and the exact
    named-parameter fix.

  Both `validate_rule`-clean and convert cleanly to Splunk + Elasticsearch.

- **Three more CVE rules; three n8n candidates rejected in the same
  pass.** n8n disclosed 10 CVEs the same day (2026-05-04); three looked
  promising by NVD summary (prototype-pollution RCE via xml2js, MCP OAuth
  client_name XSS, foreign-credential exfiltration) but each advisory
  turned out to be a high-level restatement with no quoted payload, XML,
  or code — rejected on the same sourcing grounds as the Eclipse
  Theia/Warp candidates earlier in this file. The three that DID carry
  line numbers, working payloads, and captured output:

  - `initial_access/observed_gitlab_mcp_server_unauth_pat_abuse_t1190.yml` —
    CVE-2026-44895 (CVSS 9.2). `mcp-gitlab-server`'s HTTP transport
    called `httpServer.listen(port)` with no host argument
    (`transport.ts:97`), defaulting the bind to `0.0.0.0` with no auth
    and wildcard CORS, exposing GitLab-PAT-backed mutation tools
    (`delete_repository`, `push_files`) to any caller.
  - `credential_access/observed_mcp_kubernetes_log_injection_token_exfil_t1557.yml` —
    CVE-2026-47250. `kubectl_generic`'s unallowlisted `flags` object let
    an attacker with only pod-log-write access plant a JSON instruction
    that, once a privileged operator's agent read the log and followed
    it, redirected `kubectl`'s `--server` to an attacker host with
    `--insecure-skip-tls-verify`, capturing the operator's bearer token
    (advisory's own PoC: `CAPTURED: Bearer EXFIL-CONFIRM-THIS-TOKEN-12345`).
  - `execution/observed_fastgpt_sandbox_regex_bypass_import_t1059_007.yml` —
    CVE-2026-44287. FastGPT's sandbox blocked dynamic `import()` with a
    whitespace-only regex; a block comment's delimiter bytes aren't in
    `\s`, so `import/**/("child_process")` parses as valid JS the filter
    never sees, reaching unrestricted `execSync`.

  All three `validate_rule`-clean and convert cleanly to Splunk +
  Elasticsearch.

- **Four more CVE rules; one candidate (IBM Langflow SSRF) dropped after
  its primary source returned HTTP 403 and could not be read directly** —
  consistent with this corpus's rule that a source must be read, not
  assumed from an NVD summary alone:

  - `credential_access/observed_librechat_mcp_oauth_resource_mismatch_t1528.yml` —
    CVE-2026-54030 (CVSS 8.0). LibreChat's MCP OAuth handler used a
    resource-metadata field to build the authorization URL without
    verifying it matched the configured server (RFC 9728 §7.3/§3.3),
    letting a malicious MCP server redirect a legitimate-looking consent
    flow's token to itself. Advisory quotes the vulnerable code
    (`handler.ts:542-548`) and the fix's comparison logic verbatim.
  - `exfiltration/observed_openclaw_mcp_header_redirect_leak_t1567.yml` —
    CVE-2026-53840 (CVSS 7.1). OpenClaw forwarded operator-configured MCP
    custom headers across cross-origin redirects. Neither the specific
    header name nor the legitimate server host is fixed by the vulnerable
    code, so the rule deliberately detects only the necessary
    precondition (an MCP-context cross-origin redirect) rather than
    overclaiming header-content detection the source doesn't support —
    an earlier draft used a `{{ placeholder }}` for the unknown host,
    caught and rewritten before commit.
  - `execution/observed_banks_prompt_jinja2_ssti_t1059.yml` —
    CVE-2026-44209. Same Jinja2-SSTI bug CLASS as
    `observed_ragflow_canvas_jinja2_ssti_t1059` but a different library
    (`banks`, an LLM prompt-templating package) and reachable code path;
    advisory quotes a working PoC payload and its captured `id` output.
  - `execution/observed_apostrophecms_apos_create_password_injection_t1059_004.yml` —
    CVE-2026-42853 (CVSS 6.5). `apos create`'s password prompt is
    interpolated into an `exec()` shell string
    (`lib/commands/create.js:186`); advisory quotes the vulnerable line,
    a working PoC password payload, and its captured proof-of-execution
    output. No patch exists at authoring time.

  All four `validate_rule`-clean and convert cleanly to Splunk +
  Elasticsearch.

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

### Changed

- **`readme_stamp.py` now stamps `DEMO.md` too, and carries three more
  metrics.** The corpus growing 100 → 222 left DEMO.md's prose behind in
  three places — "66 of the 100 corpus rules are `product: windows`",
  "convert 90 of 100 rules", "convert all 100" — while every *marked*
  number in README.md stayed correct. The mechanism was never the defect;
  its reach was. DEMO.md now carries markers for `sigma_rule_count`,
  `windows_product_count` and `lucene_convert_count`, and README.md's
  previously-unmarked "full 101-rule corpus" / "the 10 correlation rules"
  claims are marked as well.

  The three numbers were **re-measured, not search-replaced**:
  `product: windows` is 72 of 222 (the windows share itself had moved,
  66 → 72, so substituting the corpus total alone would still have been
  wrong); the Lucene-family targets convert 212 of 222; Splunk and
  OpenSearch-PPL convert all 222. Each hand-rolled count was cross-checked
  against `yaml.safe_load_all` before being wired in — the stamp script
  stays stdlib-only, so the counting is by hand, but not unverified.

- **`.claude-plugin/plugin.json` is stamped too — the most public stale
  number of the three.** Its `description` said "Ships a 100-rule published
  corpus" while the corpus held 222, and that field is what a marketplace
  listing renders. A JSON file cannot carry an HTML-comment marker, so it
  gets a regex rewriter under the same contract as the shields badge, which
  had the same limitation for the same reason. `PLUGIN_CLAIMS` covers the
  rule count and the tactic count; `--check` fails on drift in either.

  Same reach defect, third instance in one file's history — README's marked
  numbers were correct the whole time.

### Added

- **`tests/test_lucene_convert_claim.py`** — converts the entire live corpus
  with the real backends on all four Lucene targets and asserts the result
  equals the stamped `lucene_convert_count`. That metric is derived (corpus
  minus correlation rules) so the stamp script can install nothing, and the
  derivation rests on one assumption: correlations are the only thing those
  backends reject. This test is what makes that assumption fail loudly
  instead of silently skewing a published number. It also asserts all four
  targets fail on an *identical* set, which is what DEMO.md's prose claims
  when it groups them together.

### Fixed

- **`readme_stamp.py` wrote a scratch corpus's counts into the real
  DEMO.md.** The multi-file target map was first a module-level dict built
  from the real README/DEMO paths at import time, so redirecting `README`
  (what every test here does) left the repo's own DEMO.md in the write set —
  a 2-rule tmp corpus stamped "0 of 2" into the published file. Targets are
  resolved at call time now, relative to wherever `README` currently points,
  with DEMO located next to it and skipped when absent.
  `test_main_leaves_the_real_demo_alone_when_readme_is_redirected` locks it.
- `.gitignore` matched `.venv/` but not `.venv_c_check/`, leaving 2885
  untracked files in the working tree; the pattern is `.venv*/` now.

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
