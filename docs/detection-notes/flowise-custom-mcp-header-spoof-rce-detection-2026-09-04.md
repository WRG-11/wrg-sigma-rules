<!--
Companion detection note for the Flowise Custom MCP header-spoof RCE Sigma rule.
Accuracy source: resources/examples/execution/observed_flowise_custom_mcp_header_spoof_rce_t1059.yml
Advisory sources: https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-6933-jpx5-q87q (fetched via
`gh api repos/FlowiseAI/Flowise/security-advisories/GHSA-6933-jpx5-q87q`) and VulnCheck's corroborating
write-up (fetched directly, PoC payload wording confirmed there).
Detection/defense only, no exploit/PoC reproduced beyond what the vendor advisory already published.
-->

# Detecting the Flowise Custom MCP Header-Spoof RCE (CVE-2025-71336, CVSS 9.3)

Flowise's Custom MCP feature exists to launch local MCP servers by running an OS command the operator configures. Before 3.0.6, that feature was reachable by anyone who could send one crafted header — no authentication needed on a default installation.

## What the flaw actually does

`POST /api/v1/node-load-method/customMCP` is meant to serve internal, trusted requests only, gated by checking for the header `x-request-from: internal`. The check trusts the header's presence, not its origin — any external caller can set that header on their own request. Flowise's default installation runs with no auth at all unless `FLOWISE_USERNAME`/`FLOWISE_PASSWORD` are explicitly configured, so the header is the only gate, and it is trivially forgeable.

Once past that check, the request body's `mcpServerConfig.command`/`args` fields are executed directly as an OS process — that is the feature working as designed, just reachable by the wrong caller. VulnCheck's corroborating write-up describes both a file-write probe and a reverse-shell payload against this exact endpoint-plus-header combination, resulting in full container/host compromise from one unauthenticated HTTP request.

## The detection signal

The corpus rule (`execution/observed_flowise_custom_mcp_header_spoof_rce_t1059.yml`) requires all three conditions in the same request: the `customMCP` node-load-method path, the `x-request-from: internal` header, and a `POST` method. Any one alone is common (internal service calls legitimately set custom headers; the endpoint path alone says nothing about intent); the combination is what an exploit attempt needs.

## Known limitation

On an unpatched deployment, the rule cannot tell a forged header from a genuine internal call that happens to carry it for unrelated reasons — the advisory's own fix removes trust in the header entirely rather than validating it more strictly, which is a signal that no header value is reliably trustworthy pre-fix. If your log source captures request bodies, correlate a match against `mcpServerConfig.command` naming anything outside a known-safe launcher allowlist before treating it as confirmed exploitation rather than routine internal traffic.

## What to do right now

1. **Upgrade to Flowise 3.0.6 or later** — the fix removes the header-based internal/external trust decision this bug depends on.
2. If you cannot upgrade immediately, **set `FLOWISE_USERNAME`/`FLOWISE_PASSWORD`** so the deployment is not running fully unauthenticated, and restrict network reachability to the Flowise API from untrusted origins.
3. Deploy the detection rule above against any log source that captures inbound headers and paths for the Flowise API.

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of a vendor-disclosed, now-patched vulnerability. References: [FlowiseAI/Flowise Security Advisory GHSA-6933-jpx5-q87q](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-6933-jpx5-q87q), [VulnCheck corroborating write-up](https://www.vulncheck.com/advisories/flowise-unsandboxed-remote-code-execution-via-custom-mcp).*
