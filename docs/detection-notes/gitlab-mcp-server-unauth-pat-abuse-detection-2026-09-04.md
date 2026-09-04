<!--
Companion detection note for the GitLab MCP Server unauthenticated PAT-abuse Sigma rule.
Accuracy source: resources/examples/initial_access/observed_gitlab_mcp_server_unauth_pat_abuse_t1190.yml
Advisory source: https://github.com/yoda-digital/mcp-gitlab-server/security/advisories/GHSA-8jr5-6gvj-rfpf
(fetched via `gh api repos/yoda-digital/mcp-gitlab-server/security-advisories/GHSA-8jr5-6gvj-rfpf`).
Detection/defense only, no exploit/PoC reproduced beyond what the vendor advisory already published.
-->

# Detecting Unauthenticated PAT Abuse via GitLab MCP Server (CVE-2026-44895, CVSS 9.2)

`mcp-gitlab-server` lets an AI agent operate on GitLab through the operator's own Personal Access Token. Before 0.6.0, its HTTP transport had no authentication layer at all, bound to every network interface by default, and set a wildcard CORS header on every response — three separate mistakes that combine into full, unauthenticated confused-deputy access to the operator's GitLab account.

## What the flaw actually does

`src/transport.ts`'s HTTP transport calls `httpServer.listen(port)` with no host argument (line 97). Node.js's default for a bare `listen(port)` is to bind `0.0.0.0` — every interface, not loopback — so any network caller that can reach the port at all can talk to it directly. On top of that, every response carried `Access-Control-Allow-Origin: *`, meaning even a browser tab visiting an unrelated malicious page could reach the server cross-origin from inside the operator's own network.

Neither the `/sse` nor the `/messages?sessionId=<id>` endpoint checked for any credential before executing mutation-capable GitLab operations backed by the server's configured `GITLAB_PERSONAL_ACCESS_TOKEN`. The advisory's own PoC reaches `delete_repository` and `push_files` — an unauthenticated caller directs the operator's token to delete a repository or write arbitrary files to one, with the server acting as a confused deputy between the caller and GitLab.

## The detection signal

The corpus rule (`initial_access/observed_gitlab_mcp_server_unauth_pat_abuse_t1190.yml`) requires three things together: a request to `/sse` or `/messages`, a destructive/mutating tool name in the query (`delete_repository`, `push_files`, `create_or_update_file`, `merge_merge_request`), and no `Authorization` header present. The combination — mutation-capable operation, reachable endpoint, missing credential — is what distinguishes an exploit attempt from routine authenticated agent traffic once the fix's auth requirement is active.

## Known limitation

On an unfixed deployment that has not yet been exposed beyond loopback, legitimate local agent traffic will also match this rule, since the vulnerable version accepts unauthenticated requests regardless of origin. Correlate a match with source-IP scope — a non-loopback origin is what turns "expected local development traffic" into "real exposure" — the same discrimination this corpus's other no-host-bind MCP-server rules (mcp-pinot, Network-AI) already use, so if you have those deployed the same triage habit applies here.

## What to do right now

1. **Upgrade to `mcp-gitlab-server` 0.6.0 or later.** The fix requires `MCP_GITLAB_AUTH_TOKEN` whenever `USE_SSE=true`, binds to `127.0.0.1` by default instead of every interface, restricts CORS to localhost, and validates the Authorization header.
2. Until upgraded, put the server behind a firewall rule or reverse proxy that only allows loopback/localhost access — the default bind is the root cause, and this compensates for it directly.
3. Rotate the `GITLAB_PERSONAL_ACCESS_TOKEN` if you have any reason to believe the server was reachable from outside loopback while running an unfixed version.
4. Deploy the detection rule above against proxy/access logs in front of the MCP server, correlated with source-IP scope as described above.

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of a vendor-disclosed, now-patched vulnerability. Reference: [yoda-digital/mcp-gitlab-server Security Advisory GHSA-8jr5-6gvj-rfpf](https://github.com/yoda-digital/mcp-gitlab-server/security/advisories/GHSA-8jr5-6gvj-rfpf).*
