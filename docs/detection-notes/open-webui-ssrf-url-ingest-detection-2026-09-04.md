<!--
Companion detection note covering THREE sibling Sigma rules against the same project (open-webui/open-webui),
grouped by shared mechanism (a URL-validation check that a specific request shape routes around):
- resources/examples/initial_access/observed_open_webui_playwright_redirect_ssrf_bypass_t1190.yml
- resources/examples/initial_access/observed_open_webui_playwright_subresource_ssrf_t1190.yml
- resources/examples/initial_access/observed_open_webui_nat64_ipv6_transition_ssrf_t1190.yml
This is 2 of 3 grouped notes for this corpus's 13 uncovered Open WebUI rules; the other two cover
stored-XSS-rendering and access-control/ownership-bypass rules respectively.
Advisory sources: GHSA-jrfp-m64g-pcwv / GHSA-w2rx-84hp-gg95 / GHSA-8x5v-cpv7-8jjp, all fetched via
`gh api repos/open-webui/open-webui/security-advisories/<id>`.
Detection/defense only, no exploit/PoC reproduced beyond what the vendor advisories already published.
-->

# Detecting Three Open WebUI SSRF Bypasses: Same Guard, Three Ways Around It (CVSS 7.1-7.7)

Open WebUI validates URLs before fetching them, specifically to prevent SSRF into internal services and cloud metadata. Three CVEs show three distinct ways a real, working URL-validation check gets bypassed — none of them a missing check, all of them a check that doesn't cover the full request.

## What each flaw actually does

**1. The check runs once, before the redirect (CVE-2026-54018, CVSS 7.7).** `SafePlaywrightURLLoader.validate_url` checks the IP address a submitted URL resolves to — but only the INITIAL URL. Playwright follows HTTP redirects automatically by default, so a URL that is itself safe and passes validation can redirect to localhost, a Docker container's internal network, or cloud metadata, and the loader fetches it without re-validating. This bypasses the protection even when `ENABLE_RAG_LOCAL_WEB_FETCH=False`, since that setting governs a different code path entirely.

**2. The check runs on the page, not on what the page's own script fetches (CVE-2026-70479, CVSS 7.7).** With `WEB_LOADER_ENGINE=playwright`, only the TOP-LEVEL page request was validated against the blocked-address policy. Sub-resource requests the loaded page issues via its own JavaScript passed entirely unvalidated — a page can direct its own script to reach internal addresses the top-level check would have refused, and the resulting DOM (including data read from those internal addresses) flows into web-search or RAG output the requesting user sees.

**3. The check examines the wrapper, not the address inside it (CVE-2026-70485, CVSS 7.1).** Open WebUI applied Python's `ipaddress.is_global` to a submitted IPv6 literal — without examining IPv4 addresses embedded inside IPv6 TRANSITION encodings. On a deployment with a NAT64 gateway (common in IPv6-only or dual-stack-with-NAT64 setups, including some Kubernetes clusters), an internal or cloud-metadata IPv4 address wrapped inside the NAT64 well-known prefix (`64:ff9b::/96`) passes `is_global` as an apparently-ordinary global IPv6 literal — but the gateway unwraps it back to the internal target at connection time. The corpus rule's own description notes this "checking the wrapper form instead of the unwrapped target" pattern recurs across multiple SSRF-protection implementations beyond Open WebUI — worth checking for specifically if you maintain any URL-validation logic of your own.

## The shared lesson

All three SSRF guards are real, working code — none of these is "no validation exists." #1's gap is TEMPORAL (validated once, not re-validated after the response arrives). #2's gap is SCOPE (validated the request you made, not every request your fetched content can trigger). #3's gap is REPRESENTATIONAL (validated the literal you were given, not what it decodes to at the network layer). If you validate a URL or address for SSRF protection anywhere in your own code, these three questions are the direct audit checklist: does validation survive a redirect? Does it cover every request the fetched content can itself trigger? Does it examine the address after every encoding/wrapping layer is unwound, not just the literal form submitted?

## The detection signals

- **#1 (proxy logsource):** a Playwright-loader fetch that receives a 301/302 whose `Location` header targets a private/loopback/link-local address — the redirect TARGET is the signal, not the initial URL.
- **#2 (proxy logsource):** a Playwright-loader context where a captured sub-resource request targets a private/loopback/link-local address — requires browser-context network-request logging correlated to the loader process.
- **#3 (proxy logsource):** a URL-ingestion request (`image_url` or `url=` parameter) whose value contains the NAT64 well-known prefix `64:ff9b:`.

## Known limitations (per rule)

**#1** won't fire on a deployment with a legitimate, deliberately-allowlisted internal redirect target (rare, since the point of RAG URL ingestion is external content, but possible in some internal-tooling deployments).

**#2** is specific to `WEB_LOADER_ENGINE=playwright` — deployments on the default or another loader engine are simply not affected and won't produce the vulnerable request shape at all. It also needs a log source most infrastructure doesn't provide (browser-context sub-resource requests correlated to the loader process).

**#3** requires a NAT64 gateway to actually be exploitable — a deployment without one sees the wrapped address simply fail to route, so a matching literal in your logs without a NAT64 gateway present is not a real risk even pre-patch.

All three: on a deployment upgraded past the fix (#1 and #2: relevant version per CVE, #3: 0.11.0+), a matching event reflects a rejected attempt, not successful exploitation.

## What to do right now

1. **Upgrade**: #1 to Open WebUI 0.9.6+; #2 and #3 to 0.11.0+.
2. If you maintain any URL/address validation logic of your own (in Open WebUI or elsewhere), run it through the three-question checklist above: redirect-survival, sub-request-scope, and encoding-unwrap completeness.
3. If you cannot upgrade immediately and use `WEB_LOADER_ENGINE=playwright`, consider network-layer egress restriction from the Playwright loader's host to private/metadata ranges as a compensating control for #1 and #2 — it doesn't depend on the application-level check working correctly.
4. Deploy the three detection rules above against proxy/access logs with the specific log-field requirements each rule needs.

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of three vendor-disclosed, now-patched vulnerabilities. References: [open-webui/open-webui GHSA-jrfp-m64g-pcwv](https://github.com/open-webui/open-webui/security/advisories/GHSA-jrfp-m64g-pcwv), [GHSA-w2rx-84hp-gg95](https://github.com/open-webui/open-webui/security/advisories/GHSA-w2rx-84hp-gg95), [GHSA-8x5v-cpv7-8jjp](https://github.com/open-webui/open-webui/security/advisories/GHSA-8x5v-cpv7-8jjp).*
