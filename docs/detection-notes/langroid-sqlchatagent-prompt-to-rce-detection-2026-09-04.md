<!--
Companion detection note for the Langroid SQLChatAgent prompt-to-SQL-to-RCE Sigma rule.
Accuracy source: resources/examples/execution/observed_langroid_sqlchatagent_llm_rce_t1059.yml
Advisory source: https://github.com/langroid/langroid/security/advisories/GHSA-mxfr-6hcw-j9rq (fetched via
`gh api repos/langroid/langroid/security-advisories/GHSA-mxfr-6hcw-j9rq`; CVSS 9.8 confirmed live).
Detection/defense only, no exploit/PoC reproduced beyond what the vendor advisory already published.
-->

# Detecting Prompt-to-RCE in Langroid's SQLChatAgent (CVE-2026-25879, CVSS 9.8)

Langroid's `SQLChatAgent` lets an LLM write and run SQL against a real database on the application's behalf. Before 0.63.0, nothing stood between "the model decided to emit this query" and "the database executed it" — including queries the model was manipulated into emitting by content it merely read.

## What the flaw actually does

`run_query()` (`sql_chat_agent.py:474`) executed whatever SQL the LLM produced with no sanitization or validation. The attack surface here is not a direct user prompt — it is prompt injection, including indirect injection through data the agent reads back from elsewhere in the course of doing its job. Anyone who can shape content the agent later processes can steer it toward emitting a `RunQueryTool` call carrying a database-specific dangerous primitive instead of an ordinary query.

Reach depends on the database role's privileges: on Postgres, a role with `pg_execute_server_program` turns `COPY log(content) FROM PROGRAM 'id';` into arbitrary command execution on the database host — the advisory's own example. MySQL's equivalent is a `FILE`-privileged role reaching `LOAD_FILE`/`INTO OUTFILE`; MSSQL's is `xp_cmdshell`. This lands as RCE reached through a SQL interface — filed under execution (T1059) rather than credential access, since the primitive itself is command execution, not data theft.

## The detection signal

The corpus rule (`execution/observed_langroid_sqlchatagent_llm_rce_t1059.yml`) flags exactly the three dialect-specific escalation primitives in database query-log content: `COPY ... FROM PROGRAM` on Postgres, `LOAD_FILE`/`INTO OUTFILE`/`INTO DUMPFILE` on MySQL, or `xp_cmdshell` on MSSQL. None of these has a legitimate reason to originate from a normal chat-agent query workload, whichever application layer emitted them.

## Known limitation

If your database role legitimately needs one of these primitives for maintenance — a DBA running `COPY ... FROM PROGRAM` by hand, for instance — this rule cannot distinguish that from an LLM-agent-issued query by SQL content alone. Correlate with the calling application's identity if your log source captures it. Separately, a deployment that has deliberately set `allow_dangerous_operations=True` (the flag Langroid's own fix added to opt back into pre-0.63.0 behavior for workloads that accept the risk) will legitimately trigger this rule on every matching query by design; know whether your deployment has that flag set before triaging a hit as an incident.

## What to do right now

1. **Upgrade to Langroid 0.63.0 or later.** The fix adds a SELECT-only, sqlglot-parsed allowlist with a dialect-aware dangerous-pattern blocklist as the default behavior.
2. If you rely on `allow_dangerous_operations=True` for a specific, trusted workflow, scope the database role's privileges tightly — remove `pg_execute_server_program` / `FILE` / `xp_cmdshell`-equivalent grants from any role an LLM agent connects as, so even a successful prompt injection has nothing dangerous to reach.
3. Deploy the detection rule above against database query logs for any service that lets an LLM agent execute SQL on its own behalf.

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of a vendor-disclosed, now-patched vulnerability. Reference: [langroid/langroid Security Advisory GHSA-mxfr-6hcw-j9rq](https://github.com/langroid/langroid/security/advisories/GHSA-mxfr-6hcw-j9rq).*
