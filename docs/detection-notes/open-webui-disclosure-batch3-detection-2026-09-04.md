<!--
Companion detection note covering FOUR more sibling Sigma rules against open-webui/open-webui, same
ownership/authorization-gap family as the other two Open WebUI disclosure notes in this corpus.
- resources/examples/impact/observed_open_webui_channel_message_cross_channel_overwrite_t1565_001.yml
- resources/examples/collection/observed_open_webui_upload_knowledge_id_writeaccess_bypass_t1005.yml
- resources/examples/impact/observed_open_webui_calendar_event_destination_bypass_t1565_001.yml
- resources/examples/impact/observed_open_webui_sync_cleanup_cross_kb_delete_t1485.yml
Advisory sources: GHSA-x2ff-v5v8-m75m / GHSA-7r7x-gjvr-448g / GHSA-f3g7-59qc-pqg6 / GHSA-jxc9-xmc4-gr23,
all fetched via `gh api repos/open-webui/open-webui/security-advisories/<id>`.
IMPORTANT correction: the channel-overwrite rule's description states "CVSS 6.5 MEDIUM" -- the advisory's
own live CVSS score, checked directly, is 7.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:L). This is the
fourth such description/advisory CVSS discrepancy found across this corpus today (after mem0, the
flyto2 image.download rule, and this one) -- worth a corpus-wide CVSS re-audit against live GHSA data.
Detection/defense only, no exploit/PoC reproduced beyond what the vendor advisories already published.
-->

# Detecting Four More Open WebUI Authorization-Boundary Gaps (CVSS 4.3-7.1)

Four more Open WebUI bugs continuing this corpus's largest single-project theme: a write or move operation validates the SOURCE object's authorization but not the DESTINATION, or validates one endpoint's access path but not an equally-reachable sibling.

## What each flaw actually does

**1. A code path written to skip the ownership check entirely (CVE-2026-59714, CVSS 7.1 — corrected from the rule's own "6.5," see note above).** Submitting a chat completion with a `channel:`-prefixed `chat_id` skipped the ENTIRE ownership/membership verification block — not a bypassed check, a code path that was never written to include one. The caller-supplied `message_id` (or `message_ids` map for multimodel requests) flows unchecked into a direct primary-key message update. Any authenticated user can overwrite a message in a channel they don't belong to, with the original author attribution preserved — impersonation via message-integrity destruction. A v0.9.6 partial fix validated only the FIRST entry of the multimodel map, leaving the fan-out variant exploitable until v0.10.0 — worth noting as a "the first fix attempt covered the common case, not every case" lesson.

**2. The general path skips a check the dedicated path enforces (CVE-2026-59217, CVSS 4.3).** File upload accepts a `metadata.knowledge_id` field and auto-links the file to that knowledge base — without the write-access check the dedicated `/api/v1/knowledge/{id}/file/add` endpoint correctly enforces. A read-only user reaches the same effective outcome as the write-gated endpoint by going through the general upload path instead.

**3. Source validated, destination not (CVE-2026-54006, CVSS 4.3).** Calendar event update validates the caller has write access to the CURRENT calendar — never the destination `calendar_id` supplied in the request body. A user moves their own event into any other user's calendar whose id they know, bypassing the check the sibling `create_event` endpoint correctly performs.

**4. URL-authorized scope, body-supplied objects never checked against it (CVE-2026-70488, CVSS 4.3).** The sync-cleanup endpoint authorizes write access to the knowledge base named in the URL, then acts on directory/file ids from the REQUEST BODY without confirming those objects belong to that same knowledge base. Write access to KB-A lets a caller delete content from KB-B.

## The shared lesson

Every one of these four is a variant of "one side of an operation was checked, the other side wasn't" — #1 and #3 are source-vs-destination gaps, #2 is a general-path-vs-dedicated-path gap, #4 is a URL-scope-vs-body-object gap. None of them is "no authorization exists" — each sits next to a sibling endpoint or the SAME endpoint's other half that gets it right. The audit habit this batch reinforces: for any operation moving, updating, or acting on an object referenced from TWO places (a URL param and a body field, a source and a destination, a general path and a specific one), verify BOTH sides are checked, not just the one that was implemented first.

## The detection signals

- **#1 (application logsource):** a chat-completions request with a `channel:`-prefixed `chat_id` together with a caller-supplied `message_id`/`message_ids`.
- **#2 (proxy logsource):** a file-upload request whose body carries `knowledge_id` — flags every such request since proxy logs can't determine the caller's actual permission level.
- **#3 (proxy logsource):** an event-update request carrying a `calendar_id` field — flags every request to the endpoint for the same reason.
- **#4 (proxy logsource):** a `POST`/`DELETE` to a knowledge sync-cleanup endpoint — flags every request to the endpoint for the same reason.

## Known limitations (shared across #2, #3, #4)

All three flag every request to their respective endpoint rather than confirmed cross-object access, since proxy/HTTP logs typically cannot determine the caller's actual permission level, calendar ownership, or knowledge-base membership. Application-level access-control logs are needed to confirm an actual violation rather than routine, legitimately-scoped use. **#1** is narrower — it requires both the channel prefix AND a caller-supplied message id together, but still can't confirm actual channel non-membership from application logs alone.

All four: on a deployment upgraded past its fix, a matching event reflects rejected/inert behavior.

## What to do right now

1. **Upgrade**: #1 and #2 to 0.10.0+; #3 to 0.9.6+; #4 to 0.11.0+.
2. **Audit any two-sided operation in your own systems** (source/destination, URL-scope/body-object, general-path/dedicated-path) for the specific asymmetry this batch demonstrates four times over — check that both sides of the reference are authorized, not just the one your first implementation happened to validate.
3. Given four independent CVSS discrepancies found in this corpus today (mem0, flyto2 image.download, and this channel-overwrite rule), a corpus-wide pass re-verifying every rule's stated CVSS against live GHSA/NVD data is worth scheduling as its own follow-up — not urgent, but the pattern is now established rather than a one-off.
4. Deploy the four detection rules above against the log sources each requires.

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of four vendor-disclosed, now-patched vulnerabilities. References: [open-webui/open-webui GHSA-x2ff-v5v8-m75m](https://github.com/open-webui/open-webui/security/advisories/GHSA-x2ff-v5v8-m75m), [GHSA-7r7x-gjvr-448g](https://github.com/open-webui/open-webui/security/advisories/GHSA-7r7x-gjvr-448g), [GHSA-f3g7-59qc-pqg6](https://github.com/open-webui/open-webui/security/advisories/GHSA-f3g7-59qc-pqg6), [GHSA-jxc9-xmc4-gr23](https://github.com/open-webui/open-webui/security/advisories/GHSA-jxc9-xmc4-gr23).*
