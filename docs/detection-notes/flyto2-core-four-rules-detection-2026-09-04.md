<!--
Companion detection note covering FOUR sibling Sigma rules against the same project (flyto-core / Flyto2
Core), each a distinct CVE from a coordinated disclosure batch:
- resources/examples/command_and_control/observed_flyto2_image_download_arbitrary_file_write_t1105.yml
- resources/examples/credential_access/observed_flyto2_env_interpolation_denylist_bypass_t1552.yml
- resources/examples/initial_access/observed_flyto2_http_redirect_ssrf_revalidation_gap_t1190.yml
- resources/examples/initial_access/observed_flyto2_sibling_modules_missing_ssrf_guard_t1190.yml
Advisory sources: GHSA-2956-977x-2w3r / GHSA-hr7p-wg7r-hg9m / GHSA-c9hr-64h3-gxpc / GHSA-pgwh-4jj4-qm8v,
all fetched via `gh api advisories/<id>` (global endpoint -- these GHSA URLs are not repo-scoped in the
corpus rules' own references).
RESOLVED correction (2026-09-04): the image.download rule's description originally stated "CVSS 8.6
HIGH" and the rule itself carried level: high. The advisory's own live CVSS score is 10.0 CRITICAL
(CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:H) -- the rule's description and level: field were
corrected to CVSS 10.0 CRITICAL the same day. Two sibling rules (#3 SSRF-redirect and #4
sibling-modules-missing-guard) also carried a stale CVSS 8.6 where the advisory's live value is 8.5 --
corrected likewise. All four rules also originally stated "not yet fixed at time of publication";
live GHSA data confirms a fixed range (`< 2.26.7`/`<= 2.26.6`, both meaning 2.26.7+ is patched) for
all four, and descriptions were corrected accordingly. This note previously used the advisory's number and flagged the
discrepancy explicitly -- see "A note on severity" below.
Detection/defense only, no exploit/PoC reproduced beyond what the vendor advisories already published.
-->

# Detecting Four Flyto2 Core SSRF/File-Write/Secret-Leak Vulnerabilities (CVSS 8.5-10.0)

Flyto2 Core (`flyto-core`) is a workflow engine reachable through both an API and an MCP agent surface — meaning the caller supplying attack input can be an LLM processing untrusted content, not necessarily a human operator. Four CVEs from the same disclosure batch share a pattern: a real security guard exists in the codebase, and each bug finds a specific way around it.

## A note on severity (resolved)

The `image.download` rule (CVE-2026-67429) originally carried a description stating "CVSS 8.6 HIGH" and `level: high`. The advisory's own live CVSS score, checked directly via the GitHub advisories API, is **10.0 CRITICAL** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:H`) — the same score class as this corpus's highest-severity rules. Both the rule's `description:` and `level:` fields were corrected to match (2026-09-04). The two sibling rules that also carried a stale CVSS 8.6 (actual: 8.5) were corrected the same way.

## What each flaw actually does

**1. `image.download` — the validation base is caller-controlled too (CVE-2026-67429, CVSS 10.0 — see note above).** Most Flyto2 file-writing modules use a central `validate_path_with_env_config()` guard confining writes to `FLYTO_SANDBOX_DIR`. `image.download` instead checks its target path against `output_dir` — a parameter the SAME caller also controls. Setting `output_dir` to `/` makes `os.path.commonpath()` accept any absolute target: the caller chooses both the value being validated and the base it's validated against, so the check is self-defeating. The HTTP response body — fully attacker-controlled bytes, since the source URL is only SSRF-checked, not content-checked — is written verbatim to the resulting path. Several sibling modules (`image.convert`, `document.excel_write`, `document.pdf_fill_form`) share the pattern, though their content is format-constrained; `image.download` is the strongest because the written bytes are arbitrary.

**2. `${env.VAR}` interpolation bypasses the module denylist entirely (CVE-2026-67427, CVSS 8.6).** Flyto2 denies the `env.get` module by default specifically because it reads arbitrary host environment variables. But `VariableResolver` expands `${env.VAR}` template syntax for ANY variable with no allowlist and no policy check — the interpolation happens earlier in the engine than the module-policy enforcement, so it is never subject to the denylist at all. A workflow parameter containing `${env.AWS_SECRET_ACCESS_KEY}` resolves to the live secret in plaintext.

**3. The SSRF guard checks the URL, not where the URL redirects to (CVE-2026-67424, CVSS 8.5).** `http.get`/`http.request`/`http.batch` correctly call the project's own SSRF guard, `validate_url_with_env_config()` — unlike the modules in flaw #4 below. But the guard validates only the caller-supplied URL, and the subsequent request call carries no `allow_redirects=False`, so the HTTP client's default of following redirects transparently follows any 3xx response into internal or cloud-metadata address space with no re-validation of the `Location` target.

**4. A metadata tag that enforces nothing (CVE-2026-67428, CVSS 8.5).** The SSRF guard from #3 is applied per-module with no global egress interception — and a long list of HTTP-emitting modules (`core.api.http_get`, `graphql.query`, `monitor.http_check`, several notification senders, an Anthropic vision-analysis path, and more) never call it at all. Each carries only an `ssrf_protected` metadata tag string that enforces nothing; the advisory's own source grep for guard-related calls in the affected modules returns zero hits.

## The shared lesson

None of these four is "no SSRF/path guard exists." Three of the four (#1, #3, #4) are cases where a real guard is present and working *somewhere in the codebase*, and the specific bug is that a sibling code path either checks the wrong thing (#1: validates against a caller-controlled base), stops checking too early (#3: only the first hop), or was simply never wired up (#4: metadata tag, no call). #2 is the odd one structurally — the bypass is a matter of execution order (interpolation before policy enforcement), not a missing guard call — but it shares the family trait: a real, working control (`env.get`'s denylist) that a different code path routes around entirely. If you build a workflow/agent engine with per-module security guards, the actionable question these four raise is: does EVERY code path that reaches the sensitive operation actually call the guard, or does only the one you tested?

## The detection signals

Each rule targets its specific module/parameter shape:

- **#1 (application logsource):** an `image.download` or sibling file-writing module call whose `output_dir` targets a filesystem root or escapes with `..`.
- **#2 (application logsource):** a workflow-run request whose step parameter contains the literal `${env.` interpolation syntax.
- **#3 (network-connection logsource):** an outbound Flyto2 HTTP-module call that receives a 3xx redirect whose destination is a private/loopback/metadata address.
- **#4 (application logsource):** an invocation of one of the advisory's named unguarded modules whose URL parameter targets the cloud metadata address or a private range directly (no redirect needed).

## Known limitations (per rule)

**All four require application-level logging** (module parameters, workflow step content, or redirect-chain-to-subsequent-connection correlation) that most infrastructure log sources do not capture by default — this is the single most repeated caveat across this corpus's rules, and it applies here without exception.

**All four now have a confirmed fixed version** (flyto-core 2.26.7+, corrected in each rule's description 2026-09-04) — a deployment confirmed at 2.26.7+ has the reliable "already patched" negative case these rules originally lacked. A deployment on an older version still warrants review on any match.

**#2** additionally cannot distinguish a legitimate, operator-intended non-sensitive variable interpolation (a public region name, a feature flag) from a genuine secret read by syntax alone — application logs would need to capture which specific variable name was requested to tell the two apart.

**#4**'s affected modules have no SSRF protection by design in the vulnerable version, so a legitimate internal-monitoring use case is indistinguishable from abuse without a policy-level allowlist this rule cannot see.

## What to do right now

Because none of the four has a confirmed patch, the near-term mitigations are operational:

1. **Treat `image.download` and its file-writing siblings as unsandboxed** until a fix ships — do not rely on `output_dir`-based confinement for anything security-relevant.
2. **Audit workflow content reaching Flyto2 for `${env.` syntax** before it executes, especially content originating from the MCP agent surface (untrusted-content-to-LLM-to-workflow is the realistic attack path the advisory itself calls out).
3. **Restrict outbound network access from the Flyto2 host at the network layer** (not just the application-level SSRF guard) to internal and metadata address ranges — this compensates for both #3 (redirect gap) and #4 (missing guard entirely) at once, since neither depends on the application-level check working correctly.
4. Deploy the four detection rules above against the log source each requires, with the application-level logging caveat addressed first.
5. If you maintain this corpus, correct the `image.download` rule's `description:` CVSS figure and `level:` field per the note at the top of this document.

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of four vendor-disclosed, currently unpatched vulnerabilities. References: [GHSA-2956-977x-2w3r](https://github.com/advisories/GHSA-2956-977x-2w3r), [GHSA-hr7p-wg7r-hg9m](https://github.com/advisories/GHSA-hr7p-wg7r-hg9m), [GHSA-c9hr-64h3-gxpc](https://github.com/advisories/GHSA-c9hr-64h3-gxpc), [GHSA-pgwh-4jj4-qm8v](https://github.com/advisories/GHSA-pgwh-4jj4-qm8v).*
