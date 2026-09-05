<!--
Companion detection note covering SEVEN sibling Sigma rules against the same project (open-webui/open-webui),
grouped by shared mechanism (a downstream code path trusts a caller's claim of ownership/identity that was
never actually checked):
- resources/examples/collection/observed_open_webui_shared_chat_file_ownership_bypass_t1005.yml
- resources/examples/execution/observed_open_webui_terminal_preview_iframe_sandbox_t1059_007.yml
- resources/examples/credential_access/observed_open_webui_oauth_token_exchange_audience_confusion_t1528.yml
- resources/examples/impact/observed_open_webui_folder_delete_ownership_bypass_t1485.yml
- resources/examples/execution/observed_open_webui_socketio_session_hijack_t1059_007.yml
- resources/examples/collection/observed_open_webui_model_metadata_knowledge_file_bypass_t1005.yml
- resources/examples/execution/observed_open_webui_cross_origin_postmessage_prompt_injection_t1059.yml
This is 3 of 3 grouped notes for this corpus's 13 uncovered Open WebUI rules; the other two cover
stored-XSS-rendering and SSRF/URL-ingest rules respectively.
Advisory sources: GHSA-vrhc-3fr6-pc3c / GHSA-3xpf-xq7r-v8c5 / GHSA-rq84-p6rr-vf89 / GHSA-3cg5-48j3-v4gv /
GHSA-74h3-cxq7-vc5q / GHSA-vjqm-6gcc-62cr / GHSA-3vv5-8xxp-4f55, all fetched via
`gh api repos/open-webui/open-webui/security-advisories/<id>`.
Detection/defense only, no exploit/PoC reproduced beyond what the vendor advisories already published.
-->

# Detecting Seven Open WebUI Trust/Ownership Bypasses (CVSS 7.1-8.3)

Seven Open WebUI vulnerabilities, each in a different feature, share the same root shape: somewhere downstream, code trusts that a caller's claim (I own this file, this session_id is mine, this token was issued to me, this message came from my own origin) was already verified upstream — and in each case, it wasn't.

## What each flaw actually does

**1. Chat sharing as a laundering step for file access (CVE-2026-54010, CVSS 8.3).** Attaching a `file_id` to your own chat message never checked whether you actually own or can read that file. An attacker attaches a victim's known/guessed `file_id` to their own message, shares that chat, and `has_access_to_file()` then treats the victim's file as accessible THROUGH the share — reachable for both read and delete, despite the attacker never having had legitimate access.

**2. An iframe sandbox combination the spec itself warns against (CVE-2026-70486, CVSS 8.2).** The terminal file-preview's `serveUrl` branch always granted BOTH `allow-same-origin` and `allow-scripts` for same-origin HTML previews — a combination that defeats origin isolation, since script with `allow-same-origin` reads/manipulates the parent origin's storage. Any authenticated user with terminal-server access previewing a self-crafted HTML file gets script execution in the Open WebUI origin itself.

**3. Validating the token, not who it was issued to (CVE-2026-70482, CVSS 8.1).** `/oauth/{provider}/token/exchange` validated a raw OAuth token by calling the provider's userinfo endpoint — without confirming which CLIENT the token was originally issued to. Any party holding a token minted for ANY client registered with the same provider, including applications the operator never authorized, could exchange it for a live Open WebUI session as the token's owner.

**4. An inherited permission mistaken for ownership (CVE-2026-70494, CVSS 8.1).** `DELETE /api/v1/folders/{id}`'s subfolder check accepted any inherited WRITE grant instead of requiring actual ownership or admin status. A collaborator with nothing more than write access can permanently delete the folder owner's entire chat subtree.

**5. A session_id the server never checks belongs to the requester (CVE-2026-59216, CVSS 7.7).** `get_event_call()` delivers `execute:python`/`execute:tool` Socket.IO events to whatever `session_id` a caller supplies, checking only that the session is CONNECTED — never that it belongs to the requester. Chained with a separate disclosure (a victim's `session_id` leaks to any read-access participant of a shared document via `ydoc:document:join`), an attacker learns the victim's session_id, then submits a chat-completion request carrying it — delivering a code-interpreter event to the VICTIM's browser, running the attacker's payload as the victim.

**6. The same ownership gap, reached through model metadata instead of chat sharing (CVE-2026-54012, CVSS 7.1).** A mechanistic sibling of #1: any user who can create/update/import a workspace model can store arbitrary `meta.knowledge` file references without an ownership check. Two downstream paths (`view_file`, and `has_access_to_file()`'s model branch) trust those references as an authorization source — a malicious model owner attaches another user's `file_id` and gets read+delete access to it.

**7. A message listener with no origin check at all (CVE-2026-54007, CVSS 7.1).** The chat listener accepted `input:prompt`/`action:submit` `postMessage` events regardless of the sending window's origin. An attacker-controlled web page a logged-in victim merely visits can auto-post these messages, triggering `submitPrompt()` inside the victim's authenticated tab — cross-site forced model/tool execution under the victim's own privileges, no click needed beyond visiting the page.

## The shared lesson

Six of these seven (all but #2, which is a sandbox-configuration bug) are the same failure at different layers: **the check that should establish "this caller is authorized for this specific resource/session/origin" either never runs, or runs against the wrong question** (is this token valid for the provider, not was it issued to me; is this session connected, not does it belong to me; do I have write access, not do I own this). #1 and #6 are close enough to be flagged as a sibling family in the corpus's own tags. The actionable audit habit: for every feature that grants access based on a caller-supplied identifier (a file_id, a session_id, a token, an origin), verify the check confirms OWNERSHIP or ISSUANCE, not merely EXISTENCE or VALIDITY of that identifier.

## The detection signals

- **#1 (application logsource):** a `file_id` attachment followed by a chat share, followed by a file-endpoint request against the same `file_id` from the sharing user.
- **#2 (proxy logsource):** a terminal file-preview `serveUrl` request targeting an `.html`/`.htm` file — on the vulnerable version, this request pattern IS the exposure.
- **#3 (proxy logsource):** a `POST` to `/oauth/<provider>/token/exchange` — every request is flagged, since proxy logs cannot inspect the token's issuing-client claim; correlate with OAuth audit logs.
- **#4 (proxy logsource):** a `DELETE` to `/api/v1/folders/<id>` — every request is flagged; correlate the caller against the folder's actual owner.
- **#5 (application logsource):** a chat-completions request whose body carries a `session_id` not matching the connection's own authenticated session.
- **#6 (application logsource):** a model create/update/import request whose `meta.knowledge` references a `file_id` not owned by the requester.
- **#7 (proxy logsource):** a `POST` to `/api/v1/chats/new` or `/api/chat/completions` with a missing or foreign `Referer`/`Origin` header.

## Known limitations (shared pattern across most of these)

**#3, #4, and #7 flag every request to their endpoint** — proxy/access logs typically cannot inspect the deeper application state (token issuer, folder ownership, request origin at the JS layer) that actually distinguishes an attack from legitimate use. All three need correlation with application-level audit logs for real confidence.

**#5 and #6** ship with illustrative log-field markers (`session_owner_match`, `file_owner_match`) that approximate what a hardened build's logging MIGHT record — the advisories document the vulnerable code path, not a captured production log line. Deploying either rule requires adapting it to your actual Open WebUI application logs first.

**#2** cannot distinguish malicious intent from a benign HTML preview by request shape alone — the vulnerability is in the sandbox configuration applying to every preview, not a payload pattern.

All seven: on a deployment upgraded past its fix, a matching event reflects rejected/inert behavior rather than successful exploitation.

## What to do right now

1. **Upgrade**: #1, #6, #7 to 0.9.6+; #5 to 0.10.0+; #2, #3, #4 to 0.11.0+.
2. **Audit any caller-supplied-identifier-grants-access pattern in your own code** against the "ownership vs. existence" distinction above — this is the single most repeated root cause in this batch.
3. For #3 specifically, if you use `ENABLE_OAUTH_TOKEN_EXCHANGE`, verify your deployment's client-id validation independent of the version number, since this is exactly the kind of check worth confirming directly rather than trusting a changelog entry.
4. Deploy the seven detection rules above against the log sources each requires, adapting #5/#6's illustrative markers to your actual logging first.

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of seven vendor-disclosed, now-patched vulnerabilities. References: [open-webui/open-webui GHSA-vrhc-3fr6-pc3c](https://github.com/open-webui/open-webui/security/advisories/GHSA-vrhc-3fr6-pc3c), [GHSA-3xpf-xq7r-v8c5](https://github.com/open-webui/open-webui/security/advisories/GHSA-3xpf-xq7r-v8c5), [GHSA-rq84-p6rr-vf89](https://github.com/open-webui/open-webui/security/advisories/GHSA-rq84-p6rr-vf89), [GHSA-3cg5-48j3-v4gv](https://github.com/open-webui/open-webui/security/advisories/GHSA-3cg5-48j3-v4gv), [GHSA-74h3-cxq7-vc5q](https://github.com/open-webui/open-webui/security/advisories/GHSA-74h3-cxq7-vc5q), [GHSA-vjqm-6gcc-62cr](https://github.com/open-webui/open-webui/security/advisories/GHSA-vjqm-6gcc-62cr), [GHSA-3vv5-8xxp-4f55](https://github.com/open-webui/open-webui/security/advisories/GHSA-3vv5-8xxp-4f55).*
