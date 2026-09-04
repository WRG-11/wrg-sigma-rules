<!--
Companion detection note covering FIVE unrelated single-vendor Sigma rules, grouped together only for
authoring efficiency (each is genuinely distinct, no shared vendor or mechanism):
- resources/examples/execution/observed_apostrophecms_apos_create_password_injection_t1059_004.yml
- resources/examples/credential_access/observed_mcp_kubernetes_log_injection_token_exfil_t1557.yml
- resources/examples/collection/observed_stable_diffusion_cpp_ckpt_missing_bounds_check_oob_read_t1005.yml
- resources/examples/execution/observed_ragflow_agent_node_name_stored_xss_t1059_007.yml
- resources/examples/initial_access/observed_gradio_file_fetch_ssrf_metadata_t1190.yml
Advisory sources: GHSA-hcwq-x9fw-8cfq (apostrophecms/apostrophe) / GHSA-6mx4-4h42-r8vh (global advisory
endpoint) / GHSA-rx4w-x86j-vx57 (leejet/stable-diffusion.cpp) -- all fetched via `gh api`. RAGFlow and
Gradio rules have no GHSA in their own references; sourced via GitHub issue #16507 (infiniflow/ragflow,
fetched via `gh api repos/infiniflow/ragflow/issues/16507`) and PR #13596 (gradio-app/gradio) + VulnCheck
respectively.
Detection/defense only, no exploit/PoC reproduced beyond what the sources already published.
-->

# Five More Vulnerabilities: CLI Password Injection, MCP Log-Injection, Parser OOB Read, Stored XSS, Open Redirect/SSRF (CVSS 4.9-6.5)

Five unrelated vulnerabilities across five different projects, each distinct enough to stand alone rather than force into a shared theme.

## What each flaw actually does

**1. An interactive password prompt reaches a full shell (CVE-2026-42853, CVSS 6.5, unpatched).** `@apostrophecms/cli`'s `create.js` collects a password interactively and interpolates it directly into a shell command via `exec()` (full shell interpreter, not `execFile()`): `exec(\`echo "${response.pw}" | ${createUserCommand}\`)`. The advisory's own PoC password — `"; id > /tmp/apos_rce_proof.txt; echo "` — breaks out of the intended string and appends an arbitrary command, captured executing as the invoking user (including sudo/docker group membership in the PoC environment). No patched version exists at authoring time.

**2. An MCP tool with no flag allowlist becomes an indirect-injection amplifier (CVE-2026-47250, CVSS 6.1).** `mcp-server-kubernetes`'s `kubectl_generic` forwards every caller-supplied flag straight into `execFileSync("kubectl", cmdArgs)` with no allowlist. An attacker with only limited cluster access (e.g. pod-deploy, no cluster-admin) plants a structured JSON line in an application's log output naming `--server=https://attacker.example.com` and `--insecure-skip-tls-verify=true`. When a PRIVILEGED operator later uses the MCP server to read those logs, the flags get forwarded to a real `kubectl` invocation — redirecting the privileged operator's own kubectl call to the attacker's server and disabling TLS verification, exfiltrating the cluster's bearer token to infrastructure the attacker controls.

**3. A parser that advances position without checking bounds (CVE-2026-47748, CVSS 5.5).** A sibling bug to this corpus's other stable-diffusion.cpp `.ckpt` rules, but a distinct root cause: opcode handlers throughout the pickle parser advance the buffer position (`buffer += N`) without checking `buffer + N <= buffer_end` first. A simply-truncated `.ckpt` file — no sign-confusion trickery needed — causes reads past the metadata buffer end. The advisory notes LibFuzzer found crashes in under one second of fuzzing, itself a signal of how shallow this bug class is to trigger.

**4. A DSL field preserved verbatim, rendered with `dangerouslySetInnerHTML` and `escapeValue: false` (CVE-2026-58579, CVSS 5.1).** RAGFlow's agent-update endpoint validates a submitted pipeline DSL only for JSON structure — the node name is preserved verbatim, no HTML encoding. The frontend later renders that name into a confirmation modal via `dangerouslySetInnerHTML`, and i18next is configured with `escapeValue: false`. An authenticated user who can edit an agent stores arbitrary JavaScript in a node name; it executes in the session of ANY other workspace member who opens that result and clicks rerun.

**5. An open redirect that's also client-side SSRF (CVE-2026-59806, CVSS 4.9).** Gradio's `/gradio_api/file=<url>` endpoint returned a plain 302 redirect to whatever URL a caller supplied, no validation. The advisory's own before/after PoC: requesting `file=http://169.254.169.254/latest/meta-data/` redirected straight to the AWS instance-metadata service pre-fix, and `gradio_client` follows redirects automatically — turning a file-loading convenience feature into both an open redirect and an SSRF primitive reaching cloud-metadata credentials.

## The detection signals

- **#1 (process-creation logsource):** a shell process spawned as a child of `apos create`, whose command line shows a shell metacharacter following an `echo "` prefix.
- **#2 (process-creation logsource):** a `kubectl` invocation carrying both `--server=` and `--insecure-skip-tls-verify` together — the specific combination that redirects AND disables verification.
- **#3 (file-event logsource):** a `.ckpt` file loaded by a stable-diffusion.cpp process — identical coarse signal to this corpus's sibling `.ckpt` rules, since host-level file-event logging can't distinguish which opcode handler within the load is reached.
- **#4 (application logsource):** an agent-update (`normalize_dsl`) event whose content contains HTML/script injection markup (`<script`, `<svg`, `onerror=`, etc.).
- **#5 (proxy logsource):** a `/gradio_api/file=` request whose target is a private/loopback/link-local/metadata address.

## Known limitations (per rule)

**#1** has no patched-deployment negative case (unpatched at authoring time) — every match deserves review.

**#2** requires both flags together as the discriminator; either alone (a legitimate use of `--insecure-skip-tls-verify` in a dev/test cluster, or a legitimate `--server=` override for multi-cluster tooling) is common and would be noisy alone.

**#3** shares the exact same coarse-signal limitation as this corpus's other `.ckpt` rules: cannot distinguish this specific opcode-handler bug from any other `.ckpt`-load event by file-event logging alone; content-level inspection would be needed for precision.

**#4** cannot rule out a legitimate node name that happens to contain HTML-like text for unrelated documentation purposes — narrow in practice given the specific markup patterns matched.

**#5** cannot distinguish a legitimate internal-tooling use case (if the operator genuinely wants the file endpoint to reach specific internal resources) from abuse by request shape alone in that unusual configuration.

## What to do right now

1. **Upgrade where a fix exists**: #3 to stable-diffusion.cpp past `master-584-0a7ae07`; #4 to RAGFlow 0.26.3+; #5 to Gradio 6.20.0+. **#1 has no fix as of authoring** — avoid interactive password prompts in `apos create` workflows on affected versions, or audit/replace the CLI's `create.js` locally. **#2** check current `mcp-server-kubernetes` for a fix beyond what was confirmed at authoring time.
2. **#1's general lesson**: never interpolate user input (interactive or not) into a full-shell `exec()` call — use `execFile()`/argument-array forms that don't invoke a shell interpreter at all.
3. **#2's general lesson**: any MCP tool wrapping a CLI with caller-supplied flags needs an explicit allowlist of permitted flags, especially ones that override trust boundaries (`--server`, `--insecure-*`, credential/endpoint overrides).
4. **#4's general lesson**: if you use `dangerouslySetInnerHTML` (or equivalent) anywhere, verify your i18n/templating layer's auto-escaping is actually ON for that path — `escapeValue: false` defeats the protection i18next otherwise provides.
5. Deploy the five detection rules above against the log source each requires.

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of five vendor-disclosed vulnerabilities (three now patched, two — apostrophecms and mcp-kubernetes fix status — unconfirmed as of authoring). References: [apostrophecms/apostrophe GHSA-hcwq-x9fw-8cfq](https://github.com/apostrophecms/apostrophe/security/advisories/GHSA-hcwq-x9fw-8cfq), [GHSA-6mx4-4h42-r8vh](https://github.com/advisories/GHSA-6mx4-4h42-r8vh), [leejet/stable-diffusion.cpp GHSA-rx4w-x86j-vx57](https://github.com/leejet/stable-diffusion.cpp/security/advisories/GHSA-rx4w-x86j-vx57), [infiniflow/ragflow issue #16507](https://github.com/infiniflow/ragflow/issues/16507), [gradio-app/gradio PR #13596](https://github.com/gradio-app/gradio/pull/13596).*
