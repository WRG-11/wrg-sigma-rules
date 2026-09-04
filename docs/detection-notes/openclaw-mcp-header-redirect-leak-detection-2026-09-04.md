<!--
Companion detection note for the OpenClaw MCP cross-origin header-forwarding Sigma rule.
Accuracy source: resources/examples/exfiltration/observed_openclaw_mcp_header_redirect_leak_t1567.yml
Advisory source: https://github.com/openclaw/openclaw/security/advisories/GHSA-rjxq-qqhf-8hwh (fetched via
`gh api repos/openclaw/openclaw/security-advisories/GHSA-rjxq-qqhf-8hwh`; CVSS 7.1 confirmed live).
Detection/defense only, no exploit/PoC reproduced beyond what the vendor advisory already published.
-->

# Detecting OpenClaw's MCP Cross-Origin Header Leak (CVE-2026-53840, CVSS 7.1)

An OpenClaw MCP server configured with operator-set custom headers — the kind used to carry an API key or tenant-routing credential to a legitimate server — had those headers forwarded automatically across a redirect to a completely different origin.

## What the flaw actually does

Before 2026.5.12, an MCP server configured with `transportType: "streamable-http"` and operator-set custom headers under `mcp.servers.*.headers` had those headers forwarded whenever the client followed an HTTP redirect — including a cross-origin one. A malicious, compromised, or simply misbehaving MCP endpoint can respond to a request with a 3xx redirect to an attacker-controlled origin; the client library follows it and re-sends the SAME custom headers to the new destination, exfiltrating the operator's configured secret to a domain it was never meant to reach. The advisory is specific about the blast radius: this does not expose other, unrelated OpenClaw credentials — only the specific custom headers configured for that MCP server.

## The detection signal, and why it's phrased as a precondition

The corpus rule flags an MCP `streamable-http` connection whose response is a cross-origin redirect (a 3xx status with a `Location` pointing at a different host than the one the client connected to) — NOT a confirmed header leak. This is a deliberately narrower, more honest claim than "headers were exfiltrated": the advisory names neither a specific custom-header name nor the legitimate MCP server's host (both are per-deployment operator configuration), so a header-content-based selection isn't possible from the source material alone. The rule flags "the exact condition this bug turns dangerous" firing, not confirmed leakage — worth keeping in mind when triaging a hit.

## Known limitation

Any legitimate MCP-adjacent HTTP traffic that happens to receive a redirect for unrelated reasons (load balancing, a moved endpoint) will also match — this rule flags a NECESSARY precondition for the vulnerability, not proof that header forwarding or exfiltration actually occurred. The `mcp` substring match on the URI is also a coarse proxy for "this is an MCP-related request" and needs tightening against your deployment's actual MCP endpoint paths before use.

## What to do right now

1. **Upgrade to OpenClaw 2026.5.12 or later**, which strips custom headers before following a cross-origin redirect.
2. If you configure custom headers (API keys, tenant-routing credentials) on any MCP server integration — OpenClaw or otherwise — verify directly whether your client library forwards those headers across redirects, and specifically across cross-origin ones. This is a general HTTP-client behavior worth auditing independent of this specific CVE.
3. Rotate any credential configured as a custom header on an OpenClaw MCP server if you have reason to believe that server (or a compromised version of it) issued a cross-origin redirect while you were running a pre-2026.5.12 version.
4. Deploy the detection rule above against proxy logs, treating a match as "investigate," not "confirmed incident," per the limitation above.

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of a vendor-disclosed, now-patched vulnerability. Reference: [openclaw/openclaw Security Advisory GHSA-rjxq-qqhf-8hwh](https://github.com/openclaw/openclaw/security/advisories/GHSA-rjxq-qqhf-8hwh).*
