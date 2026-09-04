<!--
Companion detection note covering SIX sibling Sigma rules against open-webui/open-webui, all tagged
privilege_escalation (T1548) -- grouped by shared mechanism (one access-controlled path in a feature has a
sibling/alternate path that reaches the same privileged action without the same check):
- resources/examples/privilege_escalation/observed_open_webui_terminal_identity_spoofing_unsigned_forward_t1548.yml
- resources/examples/privilege_escalation/observed_open_webui_terminal_ws_role_gate_bypass_t1548.yml
- resources/examples/privilege_escalation/observed_open_webui_url_idx_backend_bypass_t1548.yml
- resources/examples/privilege_escalation/observed_open_webui_arena_task_endpoint_submodel_bypass_t1548.yml
- resources/examples/privilege_escalation/observed_open_webui_chat_features_image_gen_permission_bypass_t1548.yml
- resources/examples/privilege_escalation/observed_open_webui_image_edit_permission_check_missing_t1548.yml
Advisory sources: GHSA-j657-m4c4-24jq / GHSA-5gpj-vj23-vhhv / GHSA-9rpj-v7hf-vv2w / GHSA-m3qf-58wf-w979 /
GHSA-g423-grf7-98rv / GHSA-rqj7-6wrp-6g2g, all fetched via `gh api repos/open-webui/open-webui/security-advisories/<id>`.
RESOLVED correction (2026-09-04): the terminal-identity-spoofing rule's description originally stated
"CVSS 6.5 MEDIUM" and "not yet fixed at time of publication." The advisory's own live data says CVSS 8.0
(CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:C/C:H/I:H/A:H) and patched >= 0.10.0 -- corrected in the rule file the
same day. This was the fifth CVSS/status
discrepancy found in this corpus today -- see the corpus-wide re-audit recommendation in the "What to do"
section of open-webui-disclosure-batch3-detection-2026-09-04.md.
Detection/defense only, no exploit/PoC reproduced beyond what the vendor advisories already published.
-->

# Detecting Six Open WebUI Privilege-Escalation Gaps: The Alternate-Path Pattern (CVSS 4.3-8.0)

Six Open WebUI vulnerabilities, all filed under T1548, share one structural shape more precisely than any other batch in this corpus: in every single case, a properly-access-controlled feature has a SIBLING code path — a WebSocket variant, a task endpoint, an index parameter, a legacy mode — that reaches the identical privileged outcome without the same check. This is the single clearest "audit every code path, not just the one you tested" lesson in the corpus.

## A note on severity (see file header)

The terminal-identity-spoofing rule (#1 below) originally stated CVSS 6.5 and "not yet fixed" — the advisory's own live data says **CVSS 8.0** and **patched since 0.10.0**, and the rule file was corrected accordingly (2026-09-04). This was the fifth such corpus/advisory discrepancy identified in this corpus.

## What each flaw actually does

**1. An HTTP sibling sanitizes, the WebSocket path doesn't (CVE-2026-59224, CVSS 8.0 — see correction above).** The terminal proxy forwards caller identity to the upstream as an unsigned claim. On the WebSocket path, `ws_terminal()` interpolates `session_id` directly into the upstream URL before appending `?user_id=<caller>` — and unlike its HTTP sibling `proxy_terminal`, runs no sanitization or URL-encoding. An attacker-controlled `session_id` containing an encoded `?`/`&` survives Open WebUI's single decode, gets re-decoded upstream, and injects an attacker-chosen `user_id` ahead of the legitimate one.

**2. A WebSocket auth path skips the role gate its HTTP sibling applies (CVE-2026-70490, CVSS 6.3).** The terminal WebSocket route authenticates its own first-message JWT but never applies the verified-user role gate the equivalent HTTP terminal routes enforce. A `pending`-role account (unapproved signup, or deactivated) reaches an interactive terminal session over WebSocket while the HTTP routes on the same feature correctly reject it.

**3. An index parameter with no authorization check on the index itself (CVE-2026-54021, CVSS 6.3).** Several Ollama proxy routes use a caller-supplied `url_idx` as a raw index into the admin-configured backend list, checking only whether the caller may use the requested MODEL, never which BACKEND the request routes to. An admin-disabled backend's disabled state is checked only during model discovery, never re-checked at request time — any authenticated user can reach an internal or explicitly-disabled backend by appending an arbitrary index.

**4. A direct-dispatch endpoint skips the resolve-then-recheck step the normal route performs (CVE-2026-59225, CVSS 5.4).** The normal chat route resolves which underlying model an "arena" (random-routing) wrapper request landed on, then re-checks THAT model's access permission. Task endpoints call the completion generator directly — arena-fallback resolution happens AFTER the wrapper's own check, then recurses with `bypass_filter=True`, skipping the underlying model's access check entirely.

**5. A client-supplied flag treated as authorization (CVE-2026-70484, CVSS 4.3).** Direct image routes and the native function-calling path re-check the caller's image-generation permission. The legacy chat-completions path (`function_calling: legacy`) stores the client-supplied `features` object and dispatches to the image handler purely on that flag's truthiness — a user an administrator explicitly revoked image generation from can still trigger it by setting the flag themselves.

**6. "Verified" was the access model, not "permitted" (CVE-2026-59227, CVSS 4.3).** `POST /api/v1/images/edit` required only a verified account — never the deployment's global image-edit switch (which an admin may have disabled) nor the per-user permission (which an admin may have denied). Any merely-verified user reaches server-side image editing on the operator's provider credentials, regardless of either control the operator believed was gating it.

## The shared lesson (the strongest one in this corpus)

Every single one of these six is the same audit failure in a different feature: **a security check exists and works correctly on one code path, and a sibling path reaching the identical privileged outcome was never wired to the same check.** WebSocket-vs-HTTP (#1, #2), index-parameter-vs-model-permission (#3), direct-dispatch-vs-normal-route (#4), client-flag-vs-server-permission (#5), verified-vs-permitted (#6) — six different specific shapes of one general failure. If a feature can be reached two ways, the actionable audit habit is: enumerate EVERY entry point to a privileged action before considering that action "access-controlled," not just the one your test suite exercises.

## The detection signals

- **#1 (application logsource):** a terminal WebSocket connect whose `session_id` contains a percent-encoded query delimiter (`%3F`/`%26`).
- **#2 (application logsource):** a terminal WebSocket connection correlated with a `pending`-role authenticating account.
- **#3 (proxy logsource):** a request to an indexed Ollama proxy route (`/ollama/api/{chat,generate,embed,embeddings,show}/<n>`) — flags every such request.
- **#4 (proxy logsource):** a request to `/api/v1/tasks/*/completions` — flags every such request.
- **#5 (application logsource):** a chat-completions body with `"image_generation":true` together with `"function_calling":"legacy"`.
- **#6 (proxy logsource):** a `POST` to `/api/v1/images/edit` — flags every such request.

## Known limitations (shared pattern)

**#3, #4, and #6 flag every request to their endpoint** rather than confirmed unauthorized access — proxy/HTTP logs typically cannot determine the caller's actual permission grants, the arena-resolved submodel, or the target backend's admin-disabled status. Application-level access-control logs are needed to confirm an actual violation.

**#2** requires correlating a WebSocket connection event with the authenticating account's role — most infrastructure logging doesn't capture this correlation by default.

**#1** needs application-level logging of terminal WebSocket connect parameters specifically, and its impact additionally depends on the upstream terminal server actually trusting the unsigned identity it receives — a deployment using signed claims or non-`user_id`-scoped containers is unaffected regardless of the injection succeeding.

**#5** flags every legacy-mode request carrying the flag, including from users who genuinely hold the permission — correlate against the account's actual permission grant.

All six: on a deployment upgraded past its fix, a matching event reflects rejected/inert behavior.

## What to do right now

1. **Upgrade**: #1 and #4 to 0.10.0+; #2 and #6 to (#2: 0.11.0+, #6: 0.10.0+ — check both, they differ); #3 to 0.9.6+; #5 to 0.11.0+. Verify each against your specific deployed version rather than assuming a single upgrade covers all six.
2. **Run the alternate-path audit this batch demonstrates** on any feature you maintain that has more than one entry point (a WebSocket and HTTP variant, a direct-dispatch and normal-routed variant, an index/flag parameter alongside a resource permission): does every entry point apply the identical authorization check, or did only the first-built one get it?
3. Deploy the six detection rules above against the log sources each requires, layering in the application-level correlation each limitation section describes wherever your logging supports it.

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of six vendor-disclosed, now-patched vulnerabilities. References: [open-webui/open-webui GHSA-j657-m4c4-24jq](https://github.com/open-webui/open-webui/security/advisories/GHSA-j657-m4c4-24jq), [GHSA-5gpj-vj23-vhhv](https://github.com/open-webui/open-webui/security/advisories/GHSA-5gpj-vj23-vhhv), [GHSA-9rpj-v7hf-vv2w](https://github.com/open-webui/open-webui/security/advisories/GHSA-9rpj-v7hf-vv2w), [GHSA-m3qf-58wf-w979](https://github.com/open-webui/open-webui/security/advisories/GHSA-m3qf-58wf-w979), [GHSA-g423-grf7-98rv](https://github.com/open-webui/open-webui/security/advisories/GHSA-g423-grf7-98rv), [GHSA-rqj7-6wrp-6g2g](https://github.com/open-webui/open-webui/security/advisories/GHSA-rqj7-6wrp-6g2g).*
