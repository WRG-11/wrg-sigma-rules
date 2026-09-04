<!--
Companion detection note covering THREE sibling Sigma rules against the same project (open-webui/open-webui),
grouped by shared mechanism (an error-fallback or a permissive render mode turns content into executed HTML):
- resources/examples/execution/observed_open_webui_katex_stack_overflow_xss_t1059_007.yml
- resources/examples/execution/observed_open_webui_mermaid_loose_security_xss_t1059_007.yml
- resources/examples/execution/observed_open_webui_model_profile_svg_xss_takeover_t1059_007.yml
This is 1 of 3 grouped notes for this corpus's 13 uncovered Open WebUI rules (split by mechanism theme
rather than one 13-rule note, for readability); the other two cover SSRF/URL-ingest and access-control/
ownership-bypass rules respectively.
Advisory sources: GHSA-pwxh-7358-jq2x / GHSA-v8qj-hxv7-mgvv / GHSA-v2qm-5wxj-qhj7, all fetched via
`gh api repos/open-webui/open-webui/security-advisories/<id>`.
Detection/defense only, no exploit/PoC reproduced beyond what the vendor advisories already published.
-->

# Detecting Three Open WebUI Stored-XSS Vulnerabilities (CVSS 7.6-8.7)

Three Open WebUI XSS bugs, each a different rendering surface, share one shape: a fallback path, a permissive rendering mode, or a validator that was fixed in one place but not a sibling — each turns attacker content into executed HTML rather than displayed text.

## What each flaw actually does

**1. A parse-error fallback that renders raw HTML (CVE-2026-70492, CVSS 8.7).** `KatexRenderer.svelte`'s catch branch, written for the ordinary parse-error case, falls back to inserting the original math source into the page via Svelte's `{@html}` directive — as raw HTML, not escaped text. A math block crafted to trigger a STACK OVERFLOW in KaTeX (rather than an ordinary parse error) reaches this fallback, and a script tag embedded in the "math" executes in the browser of anyone who views the message — including in shared chats and channels. The viewer's session token is reachable; if the viewer is an administrator, their account is fully compromised.

**2. A permissive diagram-rendering mode meets `innerHTML` (CVE-2026-54011, CVSS 8.7).** Open WebUI renders Mermaid diagrams from Markdown files in the file-preview panel and inserts the generated SVG via `innerHTML`. Mermaid is configured with `securityLevel: 'loose'` — the setting that permits diagram syntax to include raw clickable links and script-capable constructs. The advisory specifically validated the working payload through the Markdown FILE PREVIEW path, not chat rendering: an attacker who gets a victim to preview a malicious Markdown file gets full script execution under the victim's session.

**3. A fix applied to two profile-image types, and not the third (CVE-2026-54013, CVSS 7.6).** Open WebUI had already patched SVG-based XSS in user profile images and webhook profile images. The identical fix was never applied to MODEL profile images: `ModelMeta` has no `validate_profile_image_url` field validator, and the serving endpoint sets no `X-Content-Type-Options: nosniff` header. Any authenticated user with the default-enabled `workspace.models` permission can store a `data:image/svg+xml;base64,...` payload as a model's profile image — and anyone who merely NAVIGATES to that image URL, no click needed, executes the embedded script under the application origin. Full account takeover, including of an administrator who simply views the model.

## The shared lesson

#1 and #2 are both "the error/fallback path doesn't get the same escaping discipline as the happy path" — a pattern worth auditing for specifically: does every catch branch, every fallback renderer, apply the same output-encoding rules as normal rendering? #3 is a different but related lesson: a security fix applied to one of several structurally-similar fields (user images, webhook images) needs to be checked against EVERY sibling field of the same shape (model images) — "we fixed the XSS in profile images" was true and incomplete at the same time.

## The detection signals

- **#1 (application/open_webui logsource):** a stored chat message containing both a math-block delimiter (`$$` or `\(`) and script-injection markup (`<img`, `<script`, `<svg`, `onerror=`, `onload=`) in the same content.
- **#2 (application/open_webui logsource):** a Markdown file preview request whose content contains a ` ```mermaid ` fenced block with embedded `<script`, `onerror=`, `onload=`, or `javascript:` markup.
- **#3 (application/open_webui logsource):** a model-update request whose `profile_image_url` value is a `data:image/svg+xml` URI — legitimate model profile images are raster formats or hosted URLs, not inline base64 SVG.

## Known limitations (per rule)

All three require **application-level logging** of stored/submitted content (chat message text, Markdown file content, or the submitted `profile_image_url` value) that most infrastructure log sources do not capture by default.

**#1 and #2** cannot fully rule out a legitimate documentation/tutorial message that genuinely discusses the relevant syntax (LaTeX+HTML, or Mermaid+script examples) together — narrow in practice given the specific delimiter-plus-markup combination each rule requires, but not impossible.

**#3** cannot rule out a deliberate, operator-reviewed exception if one exists in your deployment — narrow in practice since inline SVG model images are not a supported pattern, but worth confirming against your own operational policy before treating every hit as an incident.

All three: on a deployment already upgraded past the fix (#1: 0.11.0+, #2 and #3: 0.9.6+), a matching event reflects content that would render inert or be rejected outright, not successful exploitation.

## What to do right now

1. **Upgrade**: #1 to Open WebUI 0.11.0+; #2 and #3 to 0.9.6+.
2. If you audit your own fork or a similar chat/rendering application, check every error-fallback and permissive-render-mode path for the same escaping discipline the happy path uses — #1 and #2 are exactly this class of bug, and it tends to recur across a codebase once found in one place.
3. When a security fix targets one of several structurally-similar fields (image URLs, profile fields, template fields), grep for every sibling field of the same shape before considering the class of bug closed — #3 is the direct lesson.
4. Deploy the three detection rules above against application-level content logging for chat messages, Markdown file previews, and model-update requests respectively.

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of three vendor-disclosed, now-patched vulnerabilities. References: [open-webui/open-webui GHSA-pwxh-7358-jq2x](https://github.com/open-webui/open-webui/security/advisories/GHSA-pwxh-7358-jq2x), [GHSA-v8qj-hxv7-mgvv](https://github.com/open-webui/open-webui/security/advisories/GHSA-v8qj-hxv7-mgvv), [GHSA-v2qm-5wxj-qhj7](https://github.com/open-webui/open-webui/security/advisories/GHSA-v2qm-5wxj-qhj7).*
