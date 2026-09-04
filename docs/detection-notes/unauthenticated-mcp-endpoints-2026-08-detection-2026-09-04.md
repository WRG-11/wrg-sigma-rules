<!--
Companion detection note covering THREE sibling Sigma rules the corpus's own descriptions already
cross-reference as mechanistically-distinct variants of the same failure family:
- resources/examples/initial_access/observed_mcp_pinot_unauth_confused_deputy_t1190.yml
- resources/examples/initial_access/observed_ruflo_mcp_bridge_unauth_terminal_execute_t1190.yml
- resources/examples/initial_access/observed_network_ai_empty_default_secret_t1190.yml
Advisory sources: GHSA-73cv-556c-w3g6 / GHSA-c4hm-4h84-2cf3 / GHSA-r78r-rwrf-rjwp, all fetched and CVSS
scores confirmed live via `gh api repos/<owner>/<repo>/security-advisories/<id>`.
Detection/defense only, no exploit/PoC reproduced beyond what the vendor advisories already published.
-->

# Detecting Unauthenticated MCP Endpoints: Three Distinct Failure Shapes (CVSS 9.1-10.0)

Three MCP (Model Context Protocol) servers disclosed unauthenticated-access vulnerabilities in the same window, and this corpus's own rule descriptions already flag them as mechanistically distinct from each other — worth reading together, because "unauthenticated MCP endpoint" is not one bug, it is a family with at least three different root causes.

## What each flaw actually does

**1. mcp-pinot — a working auth toggle, left off by default (CVE-2026-49257, CVSS 10.0).** Versions 3.0.1 and earlier defaulted `oauth_enabled` to `False` and bound the HTTP MCP server to `0.0.0.0:8080` — reachable from any network-adjacent caller, not just localhost. With OAuth disabled, every tool registers with no authentication check at all, and the server proxies each call using its OWN server-side Pinot credentials rather than any caller identity — a textbook confused deputy. Reachable tools include arbitrary `SELECT` queries and full schema/table-config read-write access. The server was never confused about whether auth existed; it just never required it by default.

**2. Ruflo MCP bridge — a blocklist that only covered one code path (CVE-2026-59726, CVSS 10.0).** Ruflo's default `docker-compose` deployment bound its MCP bridge to all interfaces and exposed `POST /mcp` and `POST /mcp/:group` with no authentication. The advisory states the tool blocklist meant to cover `terminal_execute` "was enforced only in the autopilot flow" — these two HTTP endpoints bypassed it entirely. An unauthenticated caller reaching either endpoint gets a shell in the bridge container as the `node` user, can read provider API keys from the container environment, and can poison the AgentDB learning store with attacker-chosen patterns.

**3. Network-AI — an auth check that is logically a no-op on default config (CVE-2026-48814, CVSS 9.1).** This is the subtlest of the three, and a "previous fix was incomplete" case. An earlier advisory (CVE-2026-46701) had restricted `Access-Control-Allow-Origin` to localhost origins — but that only stops a BROWSER from making a cross-origin request; it does nothing for curl, SSRF, or any other non-browser caller reaching a `0.0.0.0` bind directly. The deeper bug survived that fix untouched: the SSE MCP server's secret defaults to an empty string, and the authorization check itself treats an empty secret as "always authorized" (`if (!this._opts.secret) return true;`). The check is present in the code and LOOKS like it does something — it just doesn't, whenever the default configuration is used. All 22 MCP tools, including `config_set` and `agent_spawn`, remained invocable with zero credentials.

## The shared lesson

None of these three is "forgot to add auth." One is a secure default that wasn't the shipped default (mcp-pinot). One is a check that exists but has a gap next to it (Ruflo — the blocklist covers autopilot, not these two HTTP endpoints). One is a check that exists, runs, and is unconditionally true under its own default configuration (Network-AI). If you build or operate an MCP server, "there is an auth check in the code" is not evidence of anything by itself — verify what happens with the SHIPPED default configuration, not the configuration you assume operators will set.

## The detection signals

Each rule targets its vendor's specific protocol shape, since the three are not interchangeable:

- **mcp-pinot (proxy logsource):** a request to port 8080 naming a mutation tool (`create_schema`, `update_schema`, `create_table_config`, `update_table_config`) with no `Authorization` header.
- **Ruflo (proxy logsource):** a `POST` to `/mcp` or `/mcp/` whose query names `terminal_execute`, with no `Authorization` header — the MCP protocol's own `tools/call` envelope is the discriminator here, the first rule in this corpus targeting the MCP request shape itself rather than a downstream OS-level effect.
- **Network-AI (proxy logsource):** a `tools/call` request naming a privileged tool (`config_set`, `agent_spawn`, `blackboard_write`, `token_*`) whose query shows an explicitly empty `"secret":""` field — deliberately narrower than "no secret field at all," since for this specific bug, "credential absent" and "credential present but wrong" are not equivalent signals.

## Known limitations (per rule)

All three share one structural limitation: on a deployment already upgraded past the fix, a matching request reflects a rejected attempt at the network layer, not successful exploitation — none of these rules can distinguish "the flaw still exists" from "someone is still probing for it" by request content alone.

mcp-pinot and Ruflo additionally cannot distinguish legitimate loopback administrative traffic from real exposure on an *unfixed* version, since loopback access is the expected normal workflow pre-fix — correlate with source-IP scope (non-loopback origin) before treating a hit as a real risk. Ruflo specifically: if your log source captures response status codes, a fixed deployment answers 401/403 rather than 200, which is a cleaner discriminator than request content alone. Network-AI's limitation is different in kind: a genuine fresh development install that has simply not yet set `NETWORK_AI_MCP_SECRET` will also match on a loopback-only host — again, non-loopback origin is the signal that turns "normal setup state" into "real exposure."

## What to do right now

1. **Upgrade each affected server**: mcp-pinot to 3.1.0+, Ruflo to 3.16.3+, Network-AI to 5.7.2+.
2. **If you operate any MCP server**, audit it against all three failure shapes above, not just one: is the shipped default secure (not just the documented-recommended config)? Does your tool blocklist/allowlist cover every code path that can reach a sensitive tool, not just the primary one? Does your auth check behave correctly when its own configuration is left at default — including empty-string and unset cases?
3. **Do not bind an MCP server to `0.0.0.0` unless you specifically intend network-wide reachability** — all three of these vulnerabilities required a non-loopback bind to be exploitable remotely; loopback-only binding by default would have reduced each one to a local-privilege issue rather than an unauthenticated remote one.
4. Deploy the three detection rules above against proxy/access logs in front of each respective MCP server, with the source-IP correlation described above.

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of three vendor-disclosed, now-patched vulnerabilities. References: [startreedata/mcp-pinot GHSA-73cv-556c-w3g6](https://github.com/startreedata/mcp-pinot/security/advisories/GHSA-73cv-556c-w3g6), [ruvnet/ruflo GHSA-c4hm-4h84-2cf3](https://github.com/ruvnet/ruflo/security/advisories/GHSA-c4hm-4h84-2cf3), [Jovancoding/Network-AI GHSA-r78r-rwrf-rjwp](https://github.com/Jovancoding/Network-AI/security/advisories/GHSA-r78r-rwrf-rjwp).*
