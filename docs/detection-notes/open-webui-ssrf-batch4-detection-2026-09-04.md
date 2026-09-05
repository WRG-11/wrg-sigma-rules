<!--
Companion detection note covering TWO more sibling Sigma rules against open-webui/open-webui, extending
this corpus's SSRF/URL-ingest theme (see open-webui-ssrf-url-ingest-detection-2026-09-04.md for the first
three):
- resources/examples/initial_access/observed_open_webui_dns_rebind_toctou_ssrf_t1190.yml
- resources/examples/initial_access/observed_open_webui_vega_resource_loader_ssrf_t1190.yml
Advisory sources: GHSA-h6x2-583h-x99r (CVSS 6.3) / GHSA-rffm-9q57-q649 (CVSS 4.1), both fetched via
`gh api repos/open-webui/open-webui/security-advisories/<id>`.
Detection/defense only, no exploit/PoC reproduced beyond what the vendor advisories already published.
-->

# Detecting Two More Open WebUI SSRF Bugs: Server-Side and Client-Side (CVSS 4.1-6.3)

Two more Open WebUI SSRF vulnerabilities, extending this corpus's existing SSRF/URL-ingest note — one server-side (the classic pattern), one a rarer client-side variant delivered through stored chat content.

## What each flaw actually does

**1. Validate once, resolve twice (CVE-2026-54020, CVSS 6.3).** Open WebUI's URL-validation step resolves a submitted hostname and correctly rejects private/loopback/link-local addresses at that point — but the actual HTTP client resolves the SAME hostname AGAIN at connection time, a classic time-of-check/time-of-use gap. An attacker controlling authoritative DNS for a submitted hostname answers with a public address during validation and an internal one during connection (DNS rebinding) — reaching cloud metadata, loopback admin APIs, or internal services through general URL ingest, chat `image_url` fetches, image editing, and OAuth profile-picture fetches. The OAuth path is worse than the others: it forwards the victim's OAuth **access token** to whatever host the second DNS answer points at, not just returning a fetched response.

**2. SSRF that runs in the VICTIM's browser, not the server's (CVE-2026-70480, CVSS 4.1).** Open WebUI renders `vega`/`vega-lite` fenced code blocks by building a live Vega view directly in the viewer's browser, with no restricted resource loader — Vega's spec format supports data-loading directives that fetch external URLs as part of rendering. Anyone who can place such a block where another user will see it (a shared chat, a channel) makes that OTHER user's browser issue attacker-chosen outbound GET requests, with responses from same-origin or CORS-permissive targets rendered directly into the page the victim is viewing. This is a stored, victim-executed primitive — the attacker never makes the request themselves, they get a victim's browser to make it.

## The shared lesson

#1 is this corpus's now-familiar "the validation and the actual operation don't share state" gap — three other Open WebUI rules in this corpus's SSRF note are variants of the same theme (checked-the-initial-URL-not-the-redirect, checked-the-top-level-not-the-sub-resource, checked-the-literal-not-the-unwrapped-address). #2 is worth flagging as a DISTINCT class from the rest: it's not server-side SSRF at all — it's a content-injection primitive where the "attacker" plants passive content and a victim's own browser does the fetching. If you render any spec/config format (Vega, and similarly-shaped chart/diagram libraries) from user-controllable content, check specifically whether that format's own spec syntax supports external resource loading — the vulnerability is in the format's own capability, not a coding mistake in how you invoke it.

## The detection signals

- **#1 (dns logsource):** two DNS resolutions for the same hostname within a short window returning different address classes (public, then private/loopback/link-local) in an Open WebUI process context.
- **#2 (application logsource):** a stored chat message containing a `vega`/`vega-lite` fenced block whose spec references a private/loopback/link-local address in a `data`/`url` directive.

## Known limitations (per rule)

**#1** needs DNS-resolution logging correlated to the requesting application process, which most infrastructure doesn't capture by default. It also cannot fully distinguish a genuine internal service migration serving both public and private addresses for the same hostname over time from an actual rebind attempt — the short-window framing narrows this but doesn't eliminate it without precise per-request DNS-answer correlation.

**#2** needs application-level chat-content logging, and a legitimate chart spec referencing a public IP address literal that happens to contain similar digit sequences is a possible (if narrow) source of noise.

Both: on a deployment upgraded to 0.11.0+, a matching event reflects behavior the fix no longer permits.

## What to do right now

1. **Upgrade to Open WebUI 0.11.0 or later** — both fixed in the same release.
2. For #1: if you validate a URL/hostname anywhere in your own code, verify the validated address is what actually gets connected to — pin the resolved IP at validation time and reuse it, rather than re-resolving at connection time (this is the general TOCTOU-DNS lesson this corpus's SSRF note already names for a different Open WebUI bug).
3. For #2: if you render any chart/diagram/spec format from content a different user supplied, check that format's own capability for external resource loading before assuming your code is the only place SSRF could originate.
4. Deploy the two detection rules above against the log sources each requires.

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of two vendor-disclosed, now-patched vulnerabilities. References: [open-webui/open-webui GHSA-h6x2-583h-x99r](https://github.com/open-webui/open-webui/security/advisories/GHSA-h6x2-583h-x99r), [GHSA-rffm-9q57-q649](https://github.com/open-webui/open-webui/security/advisories/GHSA-rffm-9q57-q649).*
