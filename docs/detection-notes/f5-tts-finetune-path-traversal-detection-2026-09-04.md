<!--
Companion detection note for the F5-TTS finetune project_name path-traversal Sigma rule.
Accuracy source: resources/examples/collection/observed_f5_tts_finetune_project_name_traversal_t1005.yml
Fix source: https://github.com/SWivid/F5-TTS/pull/1294 (fetched via `gh api repos/SWivid/F5-TTS/pulls/1294`;
no CVSS score or GHSA exists for this one -- fixed via a direct PR, not a formal advisory).
Detection/defense only, no exploit/PoC reproduced beyond what the merged fix's own PoC already published.
-->

# Detecting the F5-TTS Finetune Path-Traversal Directory Write (CVE-2026-43624, CVSS 8.8)

F5-TTS's finetune Gradio handlers passed a caller-supplied `project_name` straight into a path join with no containment check — a well-known Python footgun that let an unauthenticated caller write attacker-controlled directories anywhere the server process could reach.

## What the flaw actually does

Roughly ten call sites (`save_settings`, `load_settings`, `create_data_project`, and others) called `os.path.join(base, project_name)` with `project_name` taken directly from caller input. `os.path.join`'s documented behavior: when the second argument is an absolute path, the first argument is discarded entirely — so `project_name="/tmp/EVIL"` resolves the join to `/tmp/EVIL`, completely outside `base`. The fix's own before/after test makes this concrete: submitting `project_name="/tmp/F5TTS_PWND_pinyin"` created that exact directory with attacker-controlled JSON content before the patch, and raises `ValueError: invalid project_name: '/tmp/F5TTS_PWND_pinyin'` after it.

## The detection signal

The corpus rule flags a finetune-handler request whose `project_name` value is an absolute path (starts with `/`, `%2F`, or a Windows drive letter) or contains a `..` traversal segment — the two shapes the fix's own `_safe_project_path()` helper specifically rejects.

## Known limitation

This rule matches on the URL-encoded query parameter shape; it cannot verify from proxy logs alone that a coincidentally path-like `project_name` was actually malicious rather than an unusual-but-legitimate value — narrow in practice given the specific patterns matched, but application-level correlation (did the request actually create a directory outside the intended base?) would be a stronger signal if your log source captures it.

## What to do right now

1. **Upgrade to the version containing PR #1294's fix** (the PR doesn't state a specific release version — verify against the commit `2f53ded68e5f69e248ceb200a51ef4d1dc647936` directly if you need to confirm your installed version).
2. If you cannot upgrade immediately, restrict who can reach the finetune Gradio interface at all — this endpoint accepts unauthenticated requests by default, and the vulnerability requires no special privilege beyond reaching it.
3. Deploy the detection rule above against proxy/access logs in front of the F5-TTS finetune interface.

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of a vendor-disclosed, now-patched vulnerability. References: [SWivid/F5-TTS PR #1294](https://github.com/SWivid/F5-TTS/pull/1294), [VulnCheck corroborating write-up](https://www.vulncheck.com/advisories/f5-tts-path-traversal-via-finetune-gradio-py-create-data-project).*
