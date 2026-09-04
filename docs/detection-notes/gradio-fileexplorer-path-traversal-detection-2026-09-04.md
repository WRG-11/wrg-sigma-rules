<!--
Companion detection note for the Gradio FileExplorer path-traversal Sigma rule.
Accuracy source: resources/examples/collection/observed_gradio_fileexplorer_path_traversal_t1005.yml
Fix source: https://github.com/gradio-app/gradio/pull/13437 (fetched via
`gh api repos/gradio-app/gradio/pulls/13437`). The PR body references GHSA-qqr5-x4m8-g4gq by name --
that advisory returns 404 on both the repo-scoped and global GitHub advisories API as of this writing
(not yet publicly queryable), so this note relies on the PR's own detailed body plus VulnCheck's
corroborating write-up rather than the advisory itself.
Detection/defense only, no exploit/PoC reproduced beyond what the merged fix's own PoC description
already published.
-->

# Detecting the Gradio FileExplorer Path-Traversal Arbitrary File Read (CVE-2026-49119, CVSS 8.7)

Gradio's `FileExplorer` component had two separate code paths for reading files — one safe, one not — and the unsafe one was reachable, unauthenticated, from any app that used the component without `auth=`.

## What the flaw actually does

`FileExplorer.preprocess()` joined the configured `root_dir` with caller-supplied path segments using `os.path.join(self.root_dir, *segments)` followed only by `os.path.normpath()`. The PR's own description calls out the asymmetry directly: the component's `ls()` endpoint already used a safe `_safe_join()` helper — `preprocess()` simply didn't. Two ways this fails: an ABSOLUTE path segment (e.g. `/etc/passwd`) makes `os.path.join` discard the `root_dir` prefix entirely (the same Python footgun behind this corpus's F5-TTS finetune rule), and a `..`-laden segment list resolves outside root through ordinary traversal. The out-of-root path is then handed to the developer's own callback, whose documented contract is "selections from `root_dir`" — so any app that reads or serves the returned path leaks arbitrary files. Reachable unauthenticated via `/queue/join` on any Gradio app without `auth=` configured.

## The detection signal

The corpus rule flags a request to a FileExplorer-backed endpoint whose path-segment parameter is either an absolute path or contains a `..` traversal component — the exact two shapes the fix's `_safe_join()` routing specifically targets (both `single` and `multiple` selection branches).

## Known limitation

The exact query-parameter shape a given FileExplorer-backed Gradio app uses may differ from this rule's generic assumptions — Gradio apps expose components through app-specific routing, so verify the actual parameter naming against your deployment before relying on this rule as written. A legitimate file-browsing path segment coincidentally containing `..` as part of a real filename is rare but possible on some filesystems.

## What to do right now

1. **Upgrade to Gradio 6.16.0 or later**, where `FileExplorer.preprocess()` routes through the same `_safe_join()` helper `ls()` already used, rejecting out-of-root paths with `InvalidPathError`.
2. If you cannot upgrade immediately and use `FileExplorer` in any app without `auth=` configured, add authentication in front of the app or audit whether the component's callback needs to be reachable at all without it.
3. Deploy the detection rule above against proxy/access logs in front of any Gradio app using `FileExplorer`.

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of a vendor-disclosed, now-patched vulnerability. References: [gradio-app/gradio PR #13437](https://github.com/gradio-app/gradio/pull/13437), [VulnCheck corroborating write-up](https://www.vulncheck.com/advisories/gradio-path-traversal-via-fileexplorer-preprocess).*
