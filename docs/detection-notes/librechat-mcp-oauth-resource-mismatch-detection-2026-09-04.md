<!--
Companion detection note for the LibreChat MCP OAuth resource-metadata-mismatch Sigma rule.
Accuracy source: resources/examples/credential_access/observed_librechat_mcp_oauth_resource_mismatch_t1528.yml
Advisory source: https://github.com/danny-avila/LibreChat/security/advisories/GHSA-gvpj-vm2f-2m23 (fetched via
`gh api repos/danny-avila/LibreChat/security-advisories/GHSA-gvpj-vm2f-2m23`; CVSS 8.0 confirmed live).
Detection/defense only, no exploit/PoC reproduced beyond what the vendor advisory already published.
-->

# Detecting the LibreChat MCP OAuth Resource-Metadata Mismatch (CVE-2026-54030, CVSS 8.0)

LibreChat's MCP OAuth flow trusted a value a malicious server could set itself — turning what looks like a consent flow for a legitimate server into a token handoff to an attacker's server instead.

## What the flaw actually does

LibreChat's MCP OAuth implementation fetches OAuth Protected Resource metadata (RFC 9728) from the configured MCP server and uses its `resource` field to build the authorization URL — without verifying that field matches the server the operator actually configured. RFC 9728 §7.3 requires exactly this check (the metadata's `resource` value must match the URL it was requested from), and §3.3 says the data must be discarded on mismatch; LibreChat implemented neither. A malicious MCP server hosted at `fake-mcp.com/mcp` can publish resource metadata claiming `resource: real-mcp.com/mcp` — a victim who configured LibreChat to point at the attacker's server completes an OAuth consent flow that LOOKS like it authorizes the legitimate server, while the resulting access token is delivered to the attacker's server instead.

This is a mechanistically distinct OAuth-trust bug from this corpus's Open WebUI token-exchange rule (that one skips audience/client validation on token exchange; this one skips resource-origin validation on metadata) — same broader class of "the OAuth trust boundary was assumed rather than checked," different specific gap.

## The detection signal

The corpus rule flags the structural mismatch the fix specifically validates against: an OAuth authorization request whose `resource` parameter's origin differs from the MCP server origin the client actually connected to fetch the metadata from.

## Known limitation

This rule's field names are an approximation of what a hardened/patched build's own logging might emit, not a quote from the advisory itself — the advisory documents the vulnerable CODE PATH, not a specific log line format. Deploying this rule requires adapting it to whatever your LibreChat deployment's actual logs capture, or adding an application-level hook specifically to record the resource-origin comparison outcome, before it can fire meaningfully.

## What to do right now

1. **Upgrade to LibreChat 0.8.5 or later**, which compares the metadata's resource origin against the configured server's origin and rejects a mismatch.
2. Until upgraded, restrict which MCP servers your LibreChat deployment is configured to connect to — this bug requires the operator to have pointed LibreChat at (or been tricked into pointing it at) an attacker-controlled server in the first place.
3. If you build any OAuth client that consumes RFC 9728 Protected Resource metadata, verify you implement §7.3's resource-origin match check and §3.3's discard-on-mismatch requirement directly — this is the precise gap LibreChat had.
4. Deploy the detection rule above once you've adapted it to your actual application logging, per the limitation above.

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of a vendor-disclosed, now-patched vulnerability. Reference: [danny-avila/LibreChat Security Advisory GHSA-gvpj-vm2f-2m23](https://github.com/danny-avila/LibreChat/security/advisories/GHSA-gvpj-vm2f-2m23).*
