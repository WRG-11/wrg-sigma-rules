<!--
Companion detection note for the Windows-MCP wildcard-CORS PowerShell RCE Sigma rule.
Accuracy source: resources/examples/execution/observed_windows_mcp_wildcard_cors_powershell_t1059_001.yml
Advisory source: https://github.com/CursorTouch/Windows-MCP/security/advisories/GHSA-vrxg-gm77-7q5g
(fetched via `gh api repos/CursorTouch/Windows-MCP/security-advisories/GHSA-vrxg-gm77-7q5g`).
Detection/defense only, no exploit/PoC reproduced beyond what the vendor advisory already published.
-->

# Detecting the Windows-MCP Wildcard-CORS PowerShell RCE (CVE-2026-48989, CVSS 8.9)

Windows-MCP integrates AI agents with Windows via MCP — including a `PowerShell` tool. Before 0.7.5, its HTTP transports left that tool reachable by any origin, with no authentication at all.

## What the flaw actually does

The SSE and Streamable-HTTP transport modes (the default `stdio` mode is unaffected) configured wildcard CORS — `allow_origins=["*"]`, `allow_methods=["*"]`, `allow_headers=["*"]` — and exposed the MCP control plane without authentication at `http://localhost:8000/mcp`. The server's `PowerShell` tool forwards a caller-controlled `command` argument to `PowerShellExecutor.execute_command`, which runs it via `powershell -EncodedCommand`. Combined, any origin — a browser tab, a script, anything — could reach the control plane and run arbitrary PowerShell as the Windows user running Windows-MCP. The advisory's own example call is as simple as `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"PowerShell","arguments":{"command":"calc.exe","timeout":30}}}`.

## The detection signal

The corpus rule requires two things together: a `powershell.exe`/`pwsh.exe` process invoked with `-EncodedCommand`, whose parent process is Windows-MCP itself (not an interactive shell or scheduled task). The `-EncodedCommand` flag is specific — it's the artifact of this server's own execution path (base64-encoding the caller's command before invocation), not a generic "PowerShell ran" signal.

## Known limitation

This rule cannot by itself distinguish an authorized operator using the PowerShell tool through a correctly-authenticated MCP client from an attacker exploiting the wildcard-CORS/no-auth gap — both produce the identical process signature. If your log source captures the originating HTTP request's `Origin` header and auth state, correlate that in before treating a hit as confirmed exploitation rather than routine authorized use.

## What to do right now

1. **Upgrade to Windows-MCP 0.7.5 or later**, where the control plane requires authentication and no longer accepts wildcard-origin requests.
2. Until upgraded, avoid running the SSE/Streamable-HTTP transport modes on a network-reachable interface — the default `stdio` mode is unaffected and is the safer choice if HTTP access isn't specifically needed.
3. Deploy the detection rule above against process-creation telemetry on any host running Windows-MCP.

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of a vendor-disclosed, now-patched vulnerability. Reference: [CursorTouch/Windows-MCP Security Advisory GHSA-vrxg-gm77-7q5g](https://github.com/CursorTouch/Windows-MCP/security/advisories/GHSA-vrxg-gm77-7q5g).*
