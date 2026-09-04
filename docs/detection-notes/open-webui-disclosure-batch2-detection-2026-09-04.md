<!--
Companion detection note covering FOUR sibling Sigma rules against the same project (open-webui/open-webui),
continuing the ownership/authorization theme from open-webui-access-control-detection-2026-09-04.md at a
lower CVSS band -- grouped by shared mechanism (a caller-supplied identifier or response field skips the
ownership/scope check other similar paths already enforce):
- resources/examples/collection/observed_open_webui_image_url_file_id_ocr_exfil_t1005.yml
- resources/examples/credential_access/observed_open_webui_tool_source_field_readmission_t1552.yml
- resources/examples/collection/observed_open_webui_knowledge_file_id_cross_user_read_t1005.yml
- resources/examples/collection/observed_open_webui_cache_serve_prefix_traversal_t1005.yml
Advisory sources: GHSA-wch8-mhj5-9frg / GHSA-3r7g-q6cg-q2vx / GHSA-6xhv-rxhv-pwm4 / GHSA-j2c8-v969-8r5c,
all fetched via `gh api repos/open-webui/open-webui/security-advisories/<id>`.
Detection/defense only, no exploit/PoC reproduced beyond what the vendor advisories already published.
-->

# Detecting Four More Open WebUI Disclosure Bugs (CVSS 4.3-6.5)

Four more Open WebUI vulnerabilities in the same "a caller-supplied value reaches something it wasn't authorized to touch" family already covered in this corpus's other Open WebUI access-control note, at a lower severity band — each still a real confidentiality loss.

## What each flaw actually does

**1. Ambiguous URL parsing turns a file id into an OCR-exfiltration channel (CVE-2026-54009, CVSS 6.5).** `POST /api/chat/completions`'s `image_url.url` field, when it does NOT start with `http://`, `https://`, or `data:image/`, is interpreted as a raw file id and resolved with NO ownership check. An attacker sets it to another user's file id; the server reads that file, base64-encodes it, and injects it into the LLM request as if it were a legitimate image. The attacker then simply prompts the model to describe or OCR the "image" — an indirect, LLM-mediated exfiltration channel for a file they never had access to.

**2. A response model designed to omit a field, undone by a sibling model that permits extras (CVE-2026-70491, CVSS 6.5).** `GET /api/v1/tools/*` endpoints returned full Python tool source to authenticated non-admin, read-only users. `ToolResponse` deliberately omits `source`/`specs` — but the route handlers spread a full tool-model dump into the response, and a sibling model (`ToolUserResponse`) permits extra fields, re-admitting exactly what `ToolResponse` was built to omit. Tool source commonly embeds hard-coded API keys and internal service URLs directly.

**3. An inline attachment path that bypasses the per-file read check everything else enforces (CVE-2026-70487, CVSS 5.3).** Inline direct model metadata accepted client-supplied knowledge attachments without filtering against the caller's actual read access. Knowledge-base-level permissions and saved-workspace model validation were unaffected — the gap was specifically in this one inline-attachment path skipping the check the rest of the system already does correctly.

**4. `startswith` without a trailing separator (CVE-2026-54014, CVSS 4.3).** `serve_cache_file()` validates a path with `file_path.startswith(os.path.abspath(CACHE_DIR))` — no `os.sep` appended to the comparison. A resolved path in a SIBLING directory whose name merely begins with the same characters (the advisory's own examples: `cache_sibling`, `cache_backup`, `cached_models`) passes the check despite not actually being inside `CACHE_DIR`. This is a well-known bug shape — "prefix containment without a trailing separator" — worth pattern-matching for in any codebase doing path containment checks this way.

## The shared lesson

All four repeat a lesson this corpus's earlier Open WebUI access-control note already named: a check existing SOMEWHERE in the system (file ownership validation, a response model's deliberate field omission, per-file read filtering, path containment) does not mean every code path that touches the same resource actually goes through it. #4 adds a specific, mechanical variant worth its own checklist entry: `str.startswith(prefix)` is not a safe containment check unless the prefix itself ends with (or the comparison appends) the path separator — this exact bug shape recurs across many codebases independently of Open WebUI.

## The detection signals

- **#1 (application logsource):** a chat-completions request whose `image_url.url` value matches a bare-identifier shape (not `http(s)://` or `data:image/`) — the specific ambiguity the vulnerable parsing exploited.
- **#2 (proxy logsource):** a request to `/api/v1/tools/*` — flags the REQUEST side since proxy logs typically can't inspect response body content; correlate with actual response content for confirmation.
- **#3 (application logsource):** an inline knowledge attachment reference lacking an `authorized: true` marker in application logs (illustrative field name, see limitation).
- **#4 (proxy logsource):** a `/cache/` request whose path targets a same-prefix sibling directory name or contains a traversal sequence.

## Known limitations (per rule)

**#1** cannot distinguish a legitimate use of `image_url.url` pointing to the caller's OWN file from a foreign-file attempt by request shape alone — both submit a bare file-id-shaped string; correlate the referenced file's actual owner against the requesting user.

**#2** flags every request to the affected endpoints, since these same endpoints also serve legitimate, authorized tool listing — a hit is not itself malicious; response-body correlation is required to confirm actual source-code disclosure.

**#3**'s log-field marker is illustrative (approximating what a hardened build's access-check logging might record), not a quote from the advisory — adapt to your actual application logs before relying on it.

**#4**'s matched sibling-directory names are the advisory's own illustrative examples, not exhaustive — adjust to whatever directories actually exist alongside your deployment's `CACHE_DIR`.

All four: on a deployment upgraded past its fix, a matching event reflects rejected/inert behavior rather than confirmed exploitation.

## What to do right now

1. **Upgrade**: #1 and #4 to 0.9.6+; #2 and #3 to 0.11.0+.
2. If you build any response model meant to omit a sensitive field, verify a sibling/derived model doesn't silently re-admit it — #2's exact bug shape.
3. If you use `str.startswith()` for any path-containment check anywhere in your own code, verify the comparison prefix includes the trailing separator — #4's exact bug shape, and a common one worth a dedicated code-search.
4. Deploy the four detection rules above against the log source each requires.

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of four vendor-disclosed, now-patched vulnerabilities. References: [open-webui/open-webui GHSA-wch8-mhj5-9frg](https://github.com/open-webui/open-webui/security/advisories/GHSA-wch8-mhj5-9frg), [GHSA-3r7g-q6cg-q2vx](https://github.com/open-webui/open-webui/security/advisories/GHSA-3r7g-q6cg-q2vx), [GHSA-6xhv-rxhv-pwm4](https://github.com/open-webui/open-webui/security/advisories/GHSA-6xhv-rxhv-pwm4), [GHSA-j2c8-v969-8r5c](https://github.com/open-webui/open-webui/security/advisories/GHSA-j2c8-v969-8r5c).*
