<!--
Companion detection note covering SIX sibling Sigma rules against FlowiseAI/Flowise, all sandbox-escape/
RCE/SSRF bugs from the same disclosure round, distinct from the authorization-boundary theme in
flowise-authz-batch-detection-2026-09-04.md:
- resources/examples/defense_evasion/observed_flowise_mcp_npm_config_yes_env_bypass_t1562_001.yml
- resources/examples/defense_evasion/observed_flowise_python_validator_unicode_homoglyph_bypass_t1027.yml
- resources/examples/execution/observed_flowise_sqlite_recordmanager_database_path_override_rce_t1059.yml
- resources/examples/execution/observed_flowise_typeorm_datasource_entities_rce_t1059.yml
- resources/examples/privilege_escalation/observed_flowise_nodevm_options_spread_sandbox_escape_t1611.yml
- resources/examples/initial_access/observed_flowise_ipv4_mapped_ipv6_ssrf_bypass_t1190.yml
Advisory sources: GHSA-xc48-889x-5qmw / GHSA-52fh-8v99-63c2 / GHSA-x3hf-7cj6-3r4m / GHSA-g32j-mmxr-gfq5 /
GHSA-3769-jgqc-cxm7 / GHSA-c6xh-wv4j-ppv5, all fetched via
`gh api repos/FlowiseAI/Flowise/security-advisories/<id>` (all six show patched_versions "3.1.3" live --
same freshness gap as the authz batch, see that note for detail).
Detection/defense only, no exploit/PoC reproduced beyond what the vendor advisories already published.
-->

# Detecting Six Flowise Sandbox-Escape and RCE Bugs: The Incomplete-Fix Pattern

Six more Flowise vulnerabilities, all reaching code execution or SSRF by getting past a security control that was clearly INTENDED to block exactly this — four of the six are explicitly incomplete fixes for prior CVEs. This is the densest "same mitigation, second bypass" cluster in this corpus.

## What each flaw actually does

**1. An environment variable reproduces a blocked flag, by name it wasn't on the list (CVE-2026-69263 — incomplete fix for CVE-2025-8943).** The prior patch blocks `-y`/`--yes` on `npx` and denies exactly four hardcoded env var names. `npm` reads config from `npm_config_*` variables; `npm_config_yes=true` reproduces `--yes` exactly and isn't in the four-item blocklist. An attacker-supplied MCP config with `env: {"npm_config_yes": "true"}` auto-installs and executes an arbitrary package — even with the security check enabled.

**2. A word-boundary regex computed against the wrong character class (CVE-2026-70470 — reopens two prior CVEs: GHSA-3hjv-c53m-58jj, GHSA-v38x-c887-992f).** The Python code validator blacklists patterns like `\b__class__\b`, but JavaScript's `\b` is ASCII-only — a Unicode mathematical-bold letter (U+1D41A) is treated as non-word, so `__cl𝐚ss__` never matches. Python's PEP 3131 NFKC-normalizes it back to `__class__` at parse time. The attacker reaches `catch_warnings` → `__subclasses__` → assembles `__import__` from `chr()` calls to dodge string-literal blacklist entries → gets the `js` module → `child_process.execSync`.

**3. A spread operator places attacker input after the intended value (CVE-2026-69259).** `SQLiteRecordManager_RecordManager.init()` builds TypeORM options as `{ database, ...additionalConfiguration, type: 'sqlite' }` — the caller-controlled config is spread AFTER `database`, silently overwriting it. Combined with a SQLite binary-encoding trick to smuggle a quote character past a regex filter, an attacker redirects the database write to a system config path, achieving RCE when a later Chromium config read executes the crafted bytes.

**4. The same spread-order bug, reaching TypeORM's own code-loading options (CVE-2026-69251 — sibling to #3, five affected nodes).** `additionalConfig` reaches TypeORM's `entities`/`subscribers`/`migrations` options — filesystem paths TypeORM loads and EXECUTES as JavaScript. Upload a reverse-shell file through the ordinary File Loader, set `additionalConfig.entities` to that path, trigger a DataSource init — confirmed root RCE.

**5. A default sandbox configuration, overridable by the caller (CVE-2026-69254).** `executeJavaScriptCode()`'s NodeVM sandbox restricts `require.builtin` via `{ ...defaultNodeVMOptions, ...nodeVMOptions }` — caller-supplied options are spread AFTER the safe defaults, silently overriding them. From inside one correctly-sandboxed execution, an attacker requires a Flowise internals file by absolute path (bypassing the module allowlist since it's loaded, not required through the restricted API), gets a reference to `executeJavaScriptCode()` itself, and calls it again with `require.builtin: ["*"]` — re-enabling `child_process` inside the nested VM. Verified root RCE, including reading the credential-encryption key.

**6. A library function reports the wrong address family for a specific address form (CVE-2026-69257 — incomplete fix for CVE-2026-31829).** `isDeniedIP()` compares `.kind()` between a resolved IP and each deny-list entry before CIDR-matching. `::ffff:169.254.169.254` (IPv4-mapped IPv6) reports `.kind() === 'ipv6'`; a deny entry like `169.254.0.0/16` reports `'ipv4'` — the kinds never match, so EVERY IPv4 deny rule is silently skipped for this address form, across all 8+ HTTP-emitting Flowise components.

## The shared lesson

Four of these six (#1, #2, #4-as-sibling-of-#3, #6) are explicitly SECOND attempts at closing something a prior fix believed it had closed — a blocklist checked the wrong thing (name vs. behavior, ASCII vs. Unicode, ipv4-kind vs. mapped-ipv6-form). The other two (#3, #5) are the same "spread AFTER the safe value" bug shape appearing in two unrelated subsystems (database config, sandbox options) — worth a dedicated code-search for in any codebase using `{ ...defaults, ...callerInput }` patterns, since the order determines whether caller input can override security-relevant defaults. The meta-lesson: fixing a vulnerability by blocking the SPECIFIC observed exploitation shape (a flag name, an ASCII pattern, one address representation) tends to leave the general vulnerability class open — the fourth bypass in a four-item blocklist, the homoglyph after the ASCII fix, the mapped-IPv6 after the plain-IPv4 fix.

## The detection signals

- **#1 (application logsource):** MCP server config whose `env` sets `npm_config_yes` or five sibling bypass variables.
- **#2 (application logsource):** Python source to CSVAgent/AirtableAgent containing a dunder identifier with a non-ASCII character.
- **#3 (application logsource):** SQLite Record Manager config whose `additionalConfig` sets `database` to a system path (`/etc/...`).
- **#4 (application logsource):** Record Manager/Agent Memory config setting `entities`, `subscribers`, or `migrations`.
- **#5 (application logsource):** custom-function request referencing the utils module path together with `nodeVMOptions` and a `require.builtin` override.
- **#6 (network-connection logsource):** a Flowise process connection to an IPv4-mapped IPv6 destination (`::ffff:` prefix).

## Known limitations (per rule)

**#1, #3, #4, #5** require application-level logging of configuration/request-body content most infrastructure doesn't capture by default, but are otherwise fairly high-precision signals (the specific combinations required have no ordinary legitimate use).

**#2** narrows well (dunder-shape + non-ASCII together) but still needs application logging to see actual submitted code content.

**#6** needs network telemetry that logs the literal destination address form rather than a normalized/resolved equivalent — not all monitoring preserves this distinction.

**Freshness**: all six describe themselves as unpatched at authoring; live GHSA data shows all patched at 3.1.3 — verify your version before assuming no negative case exists.

## What to do right now

1. **Upgrade to Flowise 3.1.3 or later** — all six fixed in the same release.
2. **If you maintain a blocklist-based security control anywhere** (flag names, character patterns, address forms), assume it will need a second bypass fix — audit for the SPECIFIC observed-exploitation-shape trap: does the fix address the general vulnerability class, or only the one payload form that was reported?
3. **Search your own codebase for `{ ...defaults, ...callerInput }` patterns** where `callerInput` can be attacker-influenced — the spread order determines whether caller input silently overrides security-relevant defaults, and this exact bug shape appeared twice independently in this batch.
4. Deploy the six detection rules above against the log sources each requires.

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of six vendor-disclosed, now-patched vulnerabilities. References: [FlowiseAI/Flowise GHSA-xc48-889x-5qmw](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-xc48-889x-5qmw), [GHSA-52fh-8v99-63c2](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-52fh-8v99-63c2), [GHSA-x3hf-7cj6-3r4m](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-x3hf-7cj6-3r4m), [GHSA-g32j-mmxr-gfq5](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-g32j-mmxr-gfq5), [GHSA-3769-jgqc-cxm7](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-3769-jgqc-cxm7), [GHSA-c6xh-wv4j-ppv5](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-c6xh-wv4j-ppv5).*
