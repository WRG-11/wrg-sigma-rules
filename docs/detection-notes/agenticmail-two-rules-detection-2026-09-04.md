<!--
Companion detection note covering TWO sibling Sigma rules against the same product (AgenticMail),
distinct CVEs the corpus rules' own descriptions already cross-reference as "same product family":
- resources/examples/initial_access/observed_agenticmail_mcp_http_unauth_masterkey_tools_t1190.yml
- resources/examples/initial_access/observed_agenticmail_bridge_wake_unverified_sender_t1566.yml
Advisory sources: GHSA-63gr-g7jc-v8rg / GHSA-fq4x-789w-jg5h, both fetched via
`gh api repos/agenticmail/agenticmail/security-advisories/<id>`.
Detection/defense only, no exploit/PoC reproduced beyond what the vendor advisories already published.
-->

# Detecting Two AgenticMail Vulnerabilities: Auth Gaps in an AI Agent's Own Mailbox (CVSS 8.2-8.7)

AgenticMail gives AI agents real email addresses and lets them act through both an MCP tool interface and an inbound-email bridge. Two CVEs in the same product family show what happens when the AUTHENTICATION layer around an AI agent's privileged actions has gaps — one on the tool-call side, one on the email-trigger side.

## What each flaw actually does

**1. Unauthenticated MCP HTTP mode exposes master-key tools (CVE-2026-50287, CVSS 8.7).** When started with `--http` or `MCP_HTTP=1`, `@agenticmail/mcp`'s HTTP server accepts an `initialize` JSON-RPC request with no Authorization header, hands back a session id with no credential exchanged, and then executes `tools/call` requests directly. Some of those tools — `setup_email_relay`, `delete_agent`, `send_test_email` and others — are marked as requiring the operator's `AGENTICMAIL_MASTER_KEY`, but the server executes them using its OWN server-side master key regardless of caller authentication. A confused deputy: the unauthenticated caller inherits privileges it never had. This vulnerability only applies to the opt-in `--http` mode — deployments on the default `stdio` transport are unaffected.

**2. An inbound email resumes a privileged agent session with no sender check (CVE-2026-57495, CVSS 8.2).** `handleBridgeMail` acts on any inbound email routed to the bridge inbox WITHOUT verifying the sender is the operator, then embeds the attacker-controlled `from`/`subject`/`preview` fields VERBATIM into a prompt that a resumed agent session reads — an indirect prompt injection. That resumed session runs with `permissionMode: 'bypassPermissions'`, meaning a fully-privileged agent (Bash, Write, Edit, WebFetch, plus the AgenticMail MCP toolbelt) executes the attacker's embedded content under the operator's own OAuth identity. The advisory notes a SIBLING handler in the same codebase — the operator-query email-reply hook — correctly gates on `isOperatorReplySender()`; the higher-privilege bridge-wake path simply had no equivalent check. Same codebase, same available pattern, one path used it and one didn't.

## The shared lesson

Both bugs are "an authentication check exists somewhere in this system, and a specific privileged path doesn't use it" — #1 at the transport layer (HTTP mode skips it), #2 at the handler layer (one handler has the sender-verification pattern, the sibling doesn't). If you build an AI agent system with multiple entry points into the same privileged capability (a tool-call API, an email trigger, a webhook), the actionable habit is to verify EVERY entry point enforces the same authentication/authorization requirement — not just the one you built or tested first. #2 is also a directly relevant lesson for anyone running Claude Code or similar agent tooling behind an automated trigger: `bypassPermissions` plus an unauthenticated trigger source is a fully general dangerous combination, not specific to email.

## The detection signals

- **#1 (proxy logsource):** an unauthenticated (no `Authorization` header) request to the `/mcp` endpoint naming one of the master-key-protected tools (`setup_email_relay`, `setup_email_domain`, `delete_agent`, `cleanup_agents`, `send_test_email`).
- **#2 (application/agenticmail logsource):** a `resumeBridgeSession`/`bypassPermissions` log event with no corresponding `isOperatorReplySender` check having run first.

## Known limitations (per rule)

**#1** produces no traffic to flag on a deployment still using the default `stdio` transport — the vulnerability is specific to opt-in HTTP mode.

**#2's limitation is the most important one to internalize before deploying it**: on an UNPATCHED install, this condition is not attack-specific — it is the normal shape of EVERY bridge-wake event, because the vulnerability IS that no sender check runs at all. A hit answers "is this deployment still vulnerable and actively using bridge-wake," not "is this a confirmed attack." Correlate the email's `from` address against the configured operator identity out-of-band to make that distinction — the rule's own log-field inference is based on the advisory's source citations, not a captured production log sample, so verify field names against your actual logs before relying on it.

## What to do right now

1. **Upgrade**: #1 to `@agenticmail/mcp` 0.9.27+; #2 requires upgrading whichever AgenticMail package you run — `@agenticmail/claudecode` 0.2.39+, `@agenticmail/codex` 0.1.33+, `@agenticmail/core` 0.9.43+, or `@agenticmail/openclaw` 0.5.71+.
2. If you cannot upgrade #1 immediately, avoid running MCP in `--http` mode, or put it behind an authenticating reverse proxy.
3. For #2, if you cannot upgrade immediately, consider disabling the bridge-wake feature or restricting which inbound addresses can reach the bridge inbox at the mail-routing layer, since the application itself performs no sender check pre-fix.
4. **If you operate any AI agent system with `bypassPermissions`-equivalent privilege escalation triggered by an external, potentially-untrusted signal** (email, webhook, queue message), audit whether that trigger path verifies sender/origin identity the same way your other privileged entry points do — this is the generalizable lesson from #2.
5. Deploy the two detection rules above against the log source each requires.

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of two vendor-disclosed, now-patched vulnerabilities. References: [agenticmail/agenticmail GHSA-63gr-g7jc-v8rg](https://github.com/agenticmail/agenticmail/security/advisories/GHSA-63gr-g7jc-v8rg), [GHSA-fq4x-789w-jg5h](https://github.com/agenticmail/agenticmail/security/advisories/GHSA-fq4x-789w-jg5h).*
