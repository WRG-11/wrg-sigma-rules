<!--
Companion detection note covering EIGHT sibling Sigma rules against FlowiseAI/Flowise, all authorization/
tenant-isolation bugs from the same vendor disclosure round:
- resources/examples/collection/observed_flowise_upsert_history_server_wide_disclosure_t1005.yml
- resources/examples/credential_access/observed_flowise_oauth2_credential_workspace_scoping_missing_t1552.yml
- resources/examples/credential_access/observed_flowise_oauth2_refresh_whitelisted_token_leak_t1528.yml
- resources/examples/credential_access/observed_flowise_vars_injection_bypasses_permission_t1552.yml
- resources/examples/impact/observed_flowise_chatflow_delete_resource_type_confusion_t1485.yml
- resources/examples/impact/observed_flowise_files_endpoint_missing_permission_check_t1485.yml
- resources/examples/impact/observed_flowise_overrideconfig_ungated_flow_context_injection_t1565_001.yml
- resources/examples/privilege_escalation/observed_flowise_stripe_subscription_idor_t1548.yml
Advisory sources: GHSA-fr6g-7cq8-fg82 / GHSA-wch5-xp77-fxg4 / GHSA-qgvm-j2hm-6m38 / GHSA-8r8h-6vcc-xhrv /
GHSA-p5w8-m249-4r4v / GHSA-wp74-f5hh-5f3r / GHSA-6vh2-wg4h-4vwj / GHSA-gmmw-qg98-6j6p, all fetched via
`gh api repos/FlowiseAI/Flowise/security-advisories/<id>`.
RESOLVED freshness note (2026-09-04): all eight corpus rules originally stated "not yet fixed at time
of publication." Live GHSA data confirmed patched_versions "3.1.3" for all eight, and the rules'
`description:` fields were corrected accordingly the same day -- the same freshness gap found in this
corpus's NLTK rules. If deploying these rules, they now correctly state the fix version; the "no
negative case" limitation no longer applies once a deployment is confirmed at 3.1.3+.
Detection/defense only, no exploit/PoC reproduced beyond what the vendor advisories already published.
-->

# Detecting Eight Flowise Authorization/Tenant-Isolation Bugs

Eight Flowise vulnerabilities from the same disclosure round, unified by one theme: a workspace, organization, or resource-type boundary that should have scoped an operation didn't, in eight different endpoints.

**Freshness note before anything else**: all eight rules originally described these as unpatched at authoring time (2026-08-11). Live GHSA data confirmed `patched_versions: "3.1.3"` for all eight, and the rules' descriptions were corrected accordingly (2026-09-04) — a deployment confirmed at Flowise 3.1.3+ now correctly reads as fixed.

## What each flaw actually does

**1. No tenant scoping on a bulk endpoint (CVE-2026-70473).** `GET /api/v1/upsert-history` returns the entire SERVER-WIDE upsert history with no workspace/tenant scoping and no pagination. The vendor's own PoC against production produced a >100MB response containing every workspace's vector-store configuration (Qdrant URLs, collection names, dimensions).

**2. Three OAuth2 handlers query by id alone, two skip auth entirely (CVE-2026-70474).** `authorize`/`callback`/`refresh` all use `findOneBy({ id: credentialId })` with no `workspaceId` filter — unlike the standard credential service elsewhere in the same codebase. `callback` and `refresh` are additionally whitelisted from authentication. Combined: leak another workspace's OAuth client_id/scope, forge a callback to inject attacker tokens, or refresh any credential's tokens.

**3. The refresh endpoint returns a live token to anyone who knows the ID (CVE-2026-70478).** `POST /api/v1/oauth2-credential/refresh/:credentialId` is whitelisted from auth entirely — decrypts the stored credential, exchanges the refresh token, and returns the new `access_token` directly in the response body. No session, no API key needed.

**4. A gated API sits next to an ungated injection site (CVE-2026-70471).** The official Variables API correctly enforces `variables:view`. But the custom-function sandbox always injects `$vars` (every workspace variable, including `process.env`-backed runtime secrets) with no permission check at the injection site — a caller explicitly denied `variables:view` still gets full `$vars` inside their sandbox.

**5. Either permission grants delete on either resource type (CVE-2026-69262).** `DELETE /api/v1/chatflows/:id` authorizes with `checkAnyPermission('chatflows:delete,agentflows:delete')` — either permission suffices — but the delete logic never checks that the resolved resource's actual type matches the permission domain granted. An `agentflows:delete`-only key deletes a `CHATFLOW`.

**6. A feature-flag gate substituted for a permission check (CVE-2026-69252).** `/api/v1/files` is gated only by `checkFeatureByPlan('feat:files')` — no `checkPermission()` on GET or DELETE. Neither the caller's permissions nor their `activeWorkspaceId` restricts what they can see or remove; a `tools:view`-only key lists and deletes another workspace's files.

**7. Two spread operations a prior fix didn't cover (CVE-2026-69258).** An earlier advisory gated `overrideConfig`'s ability to modify node parameters. Two SEPARATE spreads (`buildChatflow.ts`'s `flowConfig`, `utils/index.ts`'s `flowData`) were never covered — unauthenticated `overrideConfig: {"chatId": "<victim>"}` redirects an attacker's messages into a victim's conversation memory; `chatHistory` injection is unauthenticated prompt injection with no UI interaction.

**8. A client-supplied billing identifier trusted without ownership check (CVE-2026-70476).** `updateSubscriptionPlan`/`updateAdditionalSeats` take `subscriptionId` from the request body and forward it to Stripe with no check it belongs to the caller's organization. Any authenticated user of any organization can downgrade or reduce seats on another tenant's subscription.

## The shared lesson

Every one of these eight is "an identifier or resource reference crossed a tenant/workspace/organization/resource-type boundary that nothing checked" — the specific mechanism varies (missing `workspaceId` filter, whitelisted route, ungated injection site, permission-domain-not-bound-to-type, feature-flag-as-authorization, uncovered spread, client-trusted billing ID) but the audit question is identical across all eight: for every multi-tenant resource, does EVERY code path that reaches it verify caller-to-resource ownership, not just the primary/first-built one?

## The detection signals

- **#1 (webserver logsource):** `GET /api/v1/upsert-history` — flags every call.
- **#2 (webserver logsource):** any request to `/api/v1/oauth2-credential/{authorize,callback,refresh}/`.
- **#3 (webserver logsource):** `POST` to `/api/v1/oauth2-credential/refresh/`.
- **#4 (application logsource):** `/api/v1/node-custom-function` request whose body references `$vars`.
- **#5 (webserver logsource):** `DELETE /api/v1/chatflows/:id`.
- **#6 (webserver logsource):** `GET`/`DELETE` to `/api/v1/files`.
- **#7 (application logsource):** `/api/v1/prediction/:id` request whose `overrideConfig` sets `chatId`, `sessionId`, or `chatHistory`.
- **#8 (webserver logsource):** `POST` to either billing endpoint.

## Known limitations (shared pattern)

**All eight flag every request to their endpoint** rather than confirmed cross-tenant access — web server/application logs typically cannot see the caller's granted permissions, workspace/organization assignment, or the target resource's actual owner. Every one needs application-level authorization logs correlated against the request to distinguish a real violation from routine, legitimately-scoped use.

## What to do right now

1. **Upgrade to Flowise 3.1.3 or later** — all eight fixed in the same release.
2. **Audit any multi-tenant resource your own systems expose** for the eight specific mechanisms above — a missing scoping filter, a whitelisted route, an ungated injection site next to a gated API, a permission domain not bound to resource type, a feature flag standing in for a permission check, a partial fix that missed a sibling code path, and a client-supplied identifier trusted without ownership verification.
3. Deploy the eight detection rules above, layering in application-level authorization correlation wherever your logging supports it.

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of eight vendor-disclosed, now-patched vulnerabilities. References: [FlowiseAI/Flowise GHSA-fr6g-7cq8-fg82](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-fr6g-7cq8-fg82), [GHSA-wch5-xp77-fxg4](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-wch5-xp77-fxg4), [GHSA-qgvm-j2hm-6m38](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-qgvm-j2hm-6m38), [GHSA-8r8h-6vcc-xhrv](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-8r8h-6vcc-xhrv), [GHSA-p5w8-m249-4r4v](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-p5w8-m249-4r4v), [GHSA-wp74-f5hh-5f3r](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-wp74-f5hh-5f3r), [GHSA-6vh2-wg4h-4vwj](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-6vh2-wg4h-4vwj), [GHSA-gmmw-qg98-6j6p](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-gmmw-qg98-6j6p).*
