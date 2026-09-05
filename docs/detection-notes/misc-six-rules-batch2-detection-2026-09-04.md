<!--
Companion detection note covering SIX unrelated single-vendor Sigma rules, grouped for authoring
efficiency (each genuinely distinct, no shared vendor or mechanism):
- resources/examples/defense_evasion/observed_aws_api_mcp_server_policy_load_failure_silent_bypass_t1562_001.yml
- resources/examples/execution/observed_banks_prompt_jinja2_ssti_t1059.yml
- resources/examples/execution/observed_bedrock_agentcore_install_packages_extras_metachar_injection_t1059.yml
- resources/examples/execution/observed_fastgpt_sandbox_regex_bypass_import_t1059_007.yml
- resources/examples/initial_access/observed_kong_konnect_mcp_indirect_prompt_injection_t1190.yml
- resources/examples/initial_access/observed_microsoft_apm_symlink_dereference_deploy_t1195_002.yml
Advisory sources: GHSA-29w2-fq35-v728 (awslabs/mcp) / GHSA-gphh-9q3h-jgpp (masci/banks, CVSS 7.5) /
GHSA-j6g5-3hh3-pgw8 (aws/bedrock-agentcore-sdk-python, CVSS 7.3) / GHSA-f5mq-qxm4-5mvc (labring/FastGPT,
CVSS 6.3) / GHSA-7767-3m3w-2p44 (Kong/mcp-konnect, CVSS 7.4) / GHSA-q5pp-gvjg-h7v4 (microsoft/apm, CVSS
7.4), all fetched via `gh api repos/<owner>/<repo>/security-advisories/<id>`.
Detection/defense only, no exploit/PoC reproduced beyond what the vendor advisories already published.
-->

# Six More Vulnerabilities: Fail-Open Policy Loading, LLM-Prompt SSTI, Regex Bypasses, Indirect Prompt Injection, Symlink Dereference

Six unrelated vulnerabilities across six projects, each distinct enough to stand alone.

## What each flaw actually does

**1. A startup failure that silently disables enforcement for the process's entire life (CVE-2026-16584).** AWS API MCP Server's `SecurityPolicy._load_policy()` reads the operator's deny/gate policy file inside a try/except that, on any parse/read failure, logs an error and simply continues — the denylist stays empty, and nothing downstream checks whether the load succeeded. The per-request policy check is then silently skipped for the process's ENTIRE lifetime — a one-time startup hiccup becomes permanent unenforcement. The underlying IAM permissions still bound what the server can do; this bypasses the policy-file gate layered on top, not IAM itself.

**2. The same Jinja2 SSTI idiom this corpus already tracks, in a different library (CVE-2026-44209).** `banks`, an LLM-prompt-templating library, renders templates with a plain unsandboxed `jinja2.Environment()`. Any application passing a user-supplied string as the `template` argument is vulnerable to the same dunder-attribute object-graph traversal this corpus's RAGFlow rule documents — the advisory's own PoC achieves full command execution. Filed separately from the RAGFlow rule because the vulnerable library, code path, and downstream applications differ, but the underlying bypass idiom (`__globals__`, `__builtins__`, `__import__`, `__subclasses__`, `__mro__`) is identical — worth recognizing as a recurring signature across the whole "unsandboxed Jinja2 in an LLM-adjacent tool" pattern, not a one-off.

**3. A regex bracket class that's too permissive by one character class (CVE-2026-16796).** Bedrock AgentCore's `install_packages()` validates package specifiers, but the extras-group portion of the regex was `(\[.*\])?` — any characters at all inside brackets. `requests[$(id)]` passes validation, and because accepted specifiers are joined with plain `" ".join()` (no shell quoting) before building a `pip install` command, the bracket content reaches a shell intact.

**4. A whitespace-only regex defeated by valid JavaScript grammar the regex never anticipated (CVE-2026-44287).** FastGPT's sandbox blocks dynamic `import()` with `/\bimport\s*\(/.test(code)` — `\s` matches only ASCII whitespace. A block comment (`/* ... */`) is valid JavaScript between `import` and `(`, invisible to the regex since comment delimiters aren't whitespace. `import/**/("child_process")` parses as valid syntax the filter never sees, and because the sandbox's `require()` wrapper doesn't cover `import()`, the loaded module is fully unrestricted.

**5. Untrusted, attacker-fully-controlled data returned to an AI agent as if it were inert (CVE-2026-13341).** Kong's MCP server returns gateway-side metadata (User-Agent and other headers an attacker fully controls by sending a normal request to the gateway) to an AI agent's analytics tools without sufficient neutralization — the model can interpret attacker-supplied header content as instructions. A second, related bug: unvalidated path identifiers let a crafted ID redirect API requests to unintended Konnect endpoints, exposing internal metadata using the calling user's own token.

**6. `Path.read_text()` transparently follows a symlink a dependency chose to ship (CVE-2026-45539).** Microsoft APM's file-discovery integrators enumerate package files with bare `Path.glob()`/`read_text()`, which follows symlinks. A remote dependency commits a symlink inside its own package; on `apm install`, it's preserved verbatim, then DEREFERENCED during integration — the resolved target's content gets written into the project's own deploy directories (`.github/`, `.claude/`, `.codex/`). Three independent controls all miss this: the content-hash check runs BEFORE symlink resolution, the security scanner walks with `followlinks=False` (never inspects the target), and the auto-generated `.gitignore` doesn't cover the deploy directories the dereferenced content lands in — so the resulting files get committed by default.

## The detection signals

- **#1 (application logsource):** the literal log line `Failed to load security policy from` at MCP server startup.
- **#2 (application logsource):** the Jinja2 sandbox-escape idiom appearing together with `banks.Prompt`/`Prompt(` context.
- **#3 (application logsource):** a `pip install` command whose extras-group brackets contain a shell metacharacter (`$(`, backtick, `;`, whitespace).
- **#4 (application logsource):** the literal `import` + block-comment + `(` sequence together with `child_process` reference.
- **#5 (proxy logsource):** a gateway request whose User-Agent (or other captured header) contains instruction-shaped phrasing aimed at an AI agent.
- **#6 (file-event logsource):** a symlink created under `.apm/agents/`or `.apm/prompts/` together with a deploy-directory (`.github/`, `.claude/`, `.codex/`) target in the same command-line evidence.

## Known limitations (per rule)

**#1** is a single log line — correlate with subsequent AWS API calls executed by the same process to determine whether an operation the intended policy would have denied actually ran.

**#2, #3, #4, #6** all require application/file-event-level logging of actual content (template strings, constructed commands, submitted code, symlink targets) that most infrastructure doesn't capture by default, though each is a fairly narrow, high-precision signal once that logging exists.

**#5** flags the SHAPE of header content, not confirmed exploitation against a vulnerable instance specifically — a security researcher's own prompt-injection resilience testing produces the identical pattern. This rule also does not attempt to detect the path-manipulation half of the advisory (no example malformed identifier was quoted to key on).

**#6**'s two-step selection (symlink creation, then dereference into a deploy dir) approximates the advisory's chain, but a real filesystem event log may capture this as a single rename/copy rather than two observable steps — and cannot by itself distinguish a malicious third-party dependency's symlink from a legitimate maintainer deduplicating files within their own package.

## What to do right now

1. **Upgrade**: #1 to 1.3.47+; #2 to banks 2.4.2+; #3 to bedrock-agentcore 1.18.1+; #4 to FastGPT 4.15.0-beta1+; #5 to mcp-konnect 1.0.0+; #6 to Microsoft APM 0.13.0+.
2. **#1's general lesson**: any fail-open error handler around a startup security-configuration load is a silent, permanent unenforcement risk — verify your own equivalent code fails CLOSED (refuses to start / refuses to serve) rather than logging and continuing.
3. **#2's general lesson**: if you use Jinja2 (or similar) to render any content from an LLM-prompt pipeline, verify you're using the SANDBOXED environment class, not the plain one — this is now the third instance of this exact bug in this corpus (RAGFlow, banks, and implicitly the general pattern).
4. **#4's general lesson**: a regex-based code filter checking for a keyword needs to account for every valid syntax form that keyword can appear in, not just whitespace-separated tokens — comments, alternate quoting, and Unicode normalization (see this corpus's Flowise homoglyph rule) are all recurring bypass classes for this filter shape.
5. **#6's general lesson**: any file-reading code path that walks a dependency tree needs explicit symlink handling (check `is_symlink()` before reading) — and any security scanner walking the same tree needs `followlinks=True` or equivalent, not the reverse.
6. Deploy the six detection rules above against the log sources each requires.

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of six vendor-disclosed, now-patched vulnerabilities. References: [awslabs/mcp GHSA-29w2-fq35-v728](https://github.com/awslabs/mcp/security/advisories/GHSA-29w2-fq35-v728), [masci/banks GHSA-gphh-9q3h-jgpp](https://github.com/masci/banks/security/advisories/GHSA-gphh-9q3h-jgpp), [aws/bedrock-agentcore-sdk-python GHSA-j6g5-3hh3-pgw8](https://github.com/aws/bedrock-agentcore-sdk-python/security/advisories/GHSA-j6g5-3hh3-pgw8), [labring/FastGPT GHSA-f5mq-qxm4-5mvc](https://github.com/labring/FastGPT/security/advisories/GHSA-f5mq-qxm4-5mvc), [Kong/mcp-konnect GHSA-7767-3m3w-2p44](https://github.com/Kong/mcp-konnect/security/advisories/GHSA-7767-3m3w-2p44), [microsoft/apm GHSA-q5pp-gvjg-h7v4](https://github.com/microsoft/apm/security/advisories/GHSA-q5pp-gvjg-h7v4).*
