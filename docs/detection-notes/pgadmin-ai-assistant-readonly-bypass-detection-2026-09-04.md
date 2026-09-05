<!--
Companion detection note for the pgAdmin 4 AI Assistant read-only bypass Sigma rule.
Accuracy source: resources/examples/execution/observed_pgadmin_ai_assistant_readonly_bypass_t1059.yml
Advisory sources: https://github.com/pgadmin-org/pgadmin4/issues/10022 + fix commit bf4792444 (both
fetched directly via `gh api`; CVSS 3.1 9.0 / CVSS 4.0 9.4 confirmed from the issue itself -- the YAML's
"CVSS 9.4" is the CVSS 4.0 score, not 3.1; both are cited here for clarity).
Detection/defense only, no exploit/PoC reproduced beyond what the vendor issue already published.
-->

# Detecting the pgAdmin 4 AI Assistant Read-Only Bypass (CVE-2026-12045, CVSS 9.0 / 9.4)

pgAdmin 4's AI Assistant wraps LLM-generated SQL in a `BEGIN TRANSACTION READ ONLY` block specifically so the model cannot modify data. Versions 9.13 through 9.16 sent the query to the database as-is, which let one crafted multi-statement payload defeat that wrapper entirely.

## What the flaw actually does

`execute_sql_query` never restricted the LLM's output to a single statement, or to read-only verbs. A payload starting with a transaction-control keyword — `COMMIT`, `END`, `ROLLBACK`, or `ABORT` — closes the enclosing `READ ONLY` transaction early. Everything after it runs in ordinary autocommit mode, and the trailing `ROLLBACK` the wrapper issues at the end does nothing, because the transaction it was meant to undo is already gone.

The delivery mechanism is prompt injection: content the AI Assistant later reads back — a row value, a column, a comment — can steer the model into emitting exactly this multi-statement shape as its tool call, without a human ever typing the malicious query directly. With ordinary write privileges this reaches unauthorized data modification; with a superuser role or `pg_execute_server_program`, the fix's own commit message confirms the chain extends to remote code execution via `COPY ... TO PROGRAM` on the database host.

## The detection signal

The corpus rule (`execution/observed_pgadmin_ai_assistant_readonly_bypass_t1059.yml`) flags a query containing a transaction-control keyword (`COMMIT;`, `END;`, `ROLLBACK;`, `ABORT;`) followed by a write verb (`INSERT`, `UPDATE`, `DELETE`, `COPY `, `DROP`, `ALTER`) in the same message — the specific shape the vulnerability needs to work, distinct from either keyword appearing alone in a legitimate query.

## Known limitation

The fix (pgAdmin 9.16, commit `bf4792444`) validates that a query is exactly one statement whose leading token is one of `SELECT`/`WITH`/`EXPLAIN`/`SHOW`/`VALUES`/`TABLE` — a stricter, allowlist-based check than the rule's own keyword-pairing heuristic. A deployment on 9.16+ rejects the malicious shape before it ever reaches the database, so a match there reflects a blocked attempt, not success. Separately, this rule cannot distinguish the AI Assistant's `execute_sql_query` path from pgAdmin's ordinary Query Tool, which was never wrapped in `READ ONLY` protection to begin with and legitimately runs multi-statement admin scripts all the time — correlate with the originating pgAdmin feature if your log source captures it, or this rule will alert on routine DBA activity.

## What to do right now

1. **Upgrade to pgAdmin 4 9.16 or later.** The fix's 60-scenario regression suite (added in the same commit) covers the original PoC shapes plus comment-masked multi-statements and dollar-quoted literals containing semicolons — worth reviewing if you want to understand the exact validation logic now enforced.
2. Until upgraded, restrict which database roles the AI Assistant can connect as — remove superuser and `pg_execute_server_program` grants from any role it uses, so a successful bypass has a smaller blast radius even before the fix lands.
3. Deploy the detection rule above against pgAdmin's query logs, and layer in the Query-Tool-vs-AI-Assistant correlation described above if your log source supports it.

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of a vendor-disclosed, now-patched vulnerability. References: [pgadmin-org/pgadmin4 issue #10022](https://github.com/pgadmin-org/pgadmin4/issues/10022), [fix commit bf4792444](https://github.com/pgadmin-org/pgadmin4/commit/bf4792444446f0e7ab721d23cbd6bfe6afaa7a8b).*
