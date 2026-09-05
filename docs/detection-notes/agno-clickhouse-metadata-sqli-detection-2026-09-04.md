<!--
Companion detection note for the agno ClickHouse metadata SQL-injection Sigma rule.
Accuracy source: resources/examples/execution/observed_agno_clickhouse_metadata_sqli_t1059.yml
Fix source: https://github.com/agno-agi/agno/issues/7866 (fetched via `gh api repos/agno-agi/agno/issues/7866`),
fix PR https://github.com/agno-agi/agno/pull/7883. No GHSA exists for this one -- fixed via a direct
issue+PR, corroborated by VulnCheck.
Detection/defense only, no exploit/PoC reproduced beyond what the issue report's own code citation already
published.
-->

# Detecting the agno ClickHouse Metadata SQL Injection (CVE-2026-10105, CVSS 8.7)

agno's ClickHouse vector-store backend built a `DELETE` statement's `WHERE` clause with unescaped f-string interpolation of caller-supplied metadata — a textbook SQL injection in an AI-agent framework's data layer.

## What the flaw actually does

`delete_by_metadata()` built its query condition as `f"JSONExtractString(toString(filters), '{key}') = '{value}'"`, with neither `key` nor `value` escaped or parameterized, then executed it via `self.client.command(f"DELETE FROM ... WHERE {where_clause}")`. Since agent-ingested content can carry attacker-influenced metadata, a `value` like `1' OR '1'='1` turns the intended equality check into a tautology — `JSONExtractString(toString(filters), 'user_id') = '1' OR '1'='1'` matches every row rather than the intended one. The issue report names the resulting impact directly: mass deletion, targeted row deletion, or error-based/blind data extraction, depending on what the attacker chooses to inject.

## The detection signal

The corpus rule flags a `JSONExtractString(toString(filters)` predicate whose value operand contains a SQL boolean-tautology or comment idiom (`' OR '`, `'='`, `--`, `/*`) — this is the exact function call the vulnerable code path builds, so its presence alongside an injection idiom is a tight signal rather than a generic "SQL keyword in a query" heuristic.

## Known limitation

This rule requires database or application query-log content, which many infrastructure log sources do not capture by default. A legitimate metadata value that coincidentally contains one of the matched substrings (e.g. a document title containing `--`) is possible but narrow in practice, given the specific `JSONExtractString` function-call context also required.

## What to do right now

1. **Upgrade to the version containing the fix from PR #7883**, which switches to ClickHouse named-parameter binding (indexed `meta_key_N`/`meta_val_N` parameters handled by the driver's own escaping layer) — the same secure pattern already used elsewhere in the same file, which is itself worth noting: the insecure pattern and the secure pattern coexisted in one file until this fix.
2. If you use agno's ClickHouse vector-store backend and cannot upgrade immediately, restrict what metadata content reaches `delete_by_metadata()` from untrusted or agent-ingested sources.
3. If you maintain any similar vector-store or metadata-filtering integration, check for the same f-string-into-SQL pattern specifically — the coexistence of a safe pattern elsewhere in the same file here suggests this class of bug can hide even in a codebase that "does it right" in most places.
4. Deploy the detection rule above against database/application query logs for any agno ClickHouse deployment.

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of a vendor-disclosed, now-patched vulnerability. References: [agno-agi/agno issue #7866](https://github.com/agno-agi/agno/issues/7866), [fix PR #7883](https://github.com/agno-agi/agno/pull/7883), [VulnCheck corroborating write-up](https://www.vulncheck.com/advisories/agno-sql-injection-via-clickhouse-delete-by-metadata).*
