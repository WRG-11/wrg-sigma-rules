<!--
Companion detection note covering FOUR more sibling Sigma rules against open-webui/open-webui, distinct
mechanisms not fitting this corpus's other Open WebUI theme notes -- the final batch closing out this
corpus's Open WebUI coverage for now.
- resources/examples/initial_access/observed_open_webui_milvus_collection_name_injection_t1190.yml
- resources/examples/discovery/observed_open_webui_signin_timing_account_enumeration_t1087.yml
- resources/examples/defense_evasion/observed_open_webui_terminal_proxy_9x_encoding_traversal_bypass_t1027.yml
- resources/examples/credential_access/observed_open_webui_realtime_revoked_jwt_accepted_t1550.yml
Advisory sources: GHSA-p5cp-r7rg-qpxc / GHSA-7rw5-9f7q-xj36 / GHSA-frvj-c5qp-xj4w / GHSA-855v-hq7w-jmjw,
all fetched via `gh api repos/open-webui/open-webui/security-advisories/<id>`.
RESOLVED corrections (2026-09-04) -- sixth and seventh CVSS/status discrepancies found in this corpus:
- terminal-proxy-9x-encoding rule: description originally said CVSS 6.8 and "not yet fixed"; advisory
  says CVSS 7.7 and patched >= 0.10.0 -- corrected in the rule file.
- realtime-revoked-jwt rule: description originally said CVSS 5.9; advisory says CVSS 7.1 -- corrected
  in the rule file (this rule already correctly stated "fixed in v0.10.0").
Detection/defense only, no exploit/PoC reproduced beyond what the vendor advisories already published.
-->

# Detecting Four More Open WebUI Bugs: Incomplete Fixes and Split Enforcement (CVSS 5.3-7.7)

Four more Open WebUI vulnerabilities closing out this corpus's coverage of the project for now — no single shared mechanism, but three of the four share a specific, useful shape: a PRIOR fix or a DIFFERENT surface got a control right, and this bug is where that control didn't reach.

## A note on severity (see file header)

Two more CVSS/status discrepancies were found while sourcing this note — the sixth and seventh identified in this corpus today. The terminal-proxy-9x-encoding rule's description states CVSS 6.8 and "not yet fixed"; the advisory's live data says **CVSS 7.7** and **patched since 0.10.0**. The realtime-revoked-jwt rule states CVSS 5.9; the advisory says **CVSS 7.1**. This note uses the advisories' own numbers throughout.

## What each flaw actually does

**1. An ACL fix that doesn't cover one backend's multitenancy mode (CVE-2026-54019, CVSS 6.5).** Open WebUI added collection-level ACL checks for its vector-store backend — but the check is bypassable when Milvus multitenancy mode is specifically enabled: the ACL layer lets unknown, non-knowledge-base collection names through as legacy/ephemeral collections, and in multitenancy mode that user-controlled name becomes a `resource_id` interpolated DIRECTLY into a Milvus query expression with no escaping. This is explicitly an incomplete fix for an earlier CVE (CVE-2026-44560) — the prior patch closed one path, not this multitenancy-specific one.

**2. A performance property becomes a side channel (CVE-2026-59218, CVSS 5.3).** Signin looks up a submitted email and only runs bcrypt verification when a matching record EXISTS. Bcrypt is deliberately slow — that's the point of using it — so registered-account attempts take measurably longer than attempts against a never-registered email, letting an unauthenticated caller enumerate valid accounts purely from response latency, no password guessing needed.

**3. An 8-round decode cap against a 9-round-encoded payload, again (CVE-2026-59221, CVSS 7.7 — corrected above).** This is itself an incomplete fix for an EARLIER traversal bug (GHSA-r2wg-2mcr-66rv) in the same function. `_sanitize_proxy_path()` decodes a path parameter for up to 8 `unquote()` rounds before checking for traversal — a path encoded 9 times still carries one layer of percent-encoding after 8 rounds, so the check runs against literal `%2E%2E%2F` text and passes; the upstream terminal server then decodes it itself and reconstructs the traversal.

**4. HTTP enforces revocation, realtime doesn't (CVE-2026-59219, CVSS 7.1 — corrected above).** HTTP auth correctly rejects a JWT recorded as revoked in Redis (sign-out or OIDC back-channel logout). Socket.IO connect/join paths and the terminal WebSocket first-message auth validate the token with `decode_token()` only — signature and expiry, never the Redis revocation keys. A token revoked by the exact action meant to kill it keeps authenticating new realtime connections.

## The shared lesson (for #1, #3, #4)

Three of these four are the same meta-lesson from a different angle than this corpus's other Open WebUI batches: it's not enough to fix a vulnerability once — verify the fix covers every CONFIGURATION VARIANT (#1: multitenancy mode specifically), every ENCODING DEPTH an attacker can push to (#3: round 9 when the cap is 8), and every SURFACE that needs the same check (#4: realtime paths alongside HTTP). An incomplete fix that closes the common case looks identical to a complete fix until someone checks the uncommon one.

## The detection signals

- **#1 (proxy logsource):** a collection-referencing request whose `collection_name` parameter contains Milvus expression metacharacters (quotes, `and`/`or` adjacent to comparison syntax).
- **#2 (authentication logsource):** a burst of `/api/v1/auths/signin` requests from one source targeting many distinct emails in a short window — a coarse volume proxy, since Sigma cannot natively express a latency-comparison condition.
- **#3 (proxy logsource):** a terminal-proxy path parameter containing 9+ literal `%25` sequences (the escaped-`%` signature of a multiply-encoded payload).
- **#4 (application logsource):** a `/api/v1/auths/signout` event followed by a Socket.IO/terminal-WebSocket connect event — the coarse pairing signal, since correlating a specific revoked `jti` with a subsequent connection needs application-level logging most sources don't capture.

## Known limitations (per rule)

**#1** only applies to deployments on Milvus with multitenancy mode enabled — irrelevant otherwise, and a legitimate collection name containing "and"/"or" as an ordinary word substring (e.g. "sandbox") can add noise.

**#2** is a coarse volume-based proxy, not a direct timing measurement — Sigma has no native way to express "response B took longer than response A," so this rule flags request pattern, not the actual side channel. A credential-stuffing DEFENSE tool or bulk-validation feature can also produce this pattern.

**#3** needs infrastructure logging that preserves full request path/query WITH encoding intact — some proxy configurations normalize encoding before logging, which would make this rule blind regardless of the underlying traffic.

**#4** flags the coarser "both event classes appeared" signal rather than confirming the SAME `jti` was involved in both — application-level `jti` correlation would be a stronger signal where available. Also inapplicable to deployments with no Redis configured, since per-token revocation isn't supported there at all.

All four: on a deployment upgraded past its fix (#1: 0.9.6+, #2 and #4: 0.10.0+, #3: 0.10.0+), a matching event reflects rejected/inert behavior.

## What to do right now

1. **Upgrade**: #1 to 0.9.6+; #2, #3, #4 to 0.10.0+.
2. When you fix a security bug, explicitly test every configuration variant (#1), every parameter-depth boundary near your chosen limit (#3), and every alternate surface reaching the same protected resource (#4) — not just the originally-reported case.
3. Deploy the four detection rules above against the log sources each requires.

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of four vendor-disclosed, now-patched vulnerabilities. References: [open-webui/open-webui GHSA-p5cp-r7rg-qpxc](https://github.com/open-webui/open-webui/security/advisories/GHSA-p5cp-r7rg-qpxc), [GHSA-7rw5-9f7q-xj36](https://github.com/open-webui/open-webui/security/advisories/GHSA-7rw5-9f7q-xj36), [GHSA-frvj-c5qp-xj4w](https://github.com/open-webui/open-webui/security/advisories/GHSA-frvj-c5qp-xj4w), [GHSA-855v-hq7w-jmjw](https://github.com/open-webui/open-webui/security/advisories/GHSA-855v-hq7w-jmjw).*
