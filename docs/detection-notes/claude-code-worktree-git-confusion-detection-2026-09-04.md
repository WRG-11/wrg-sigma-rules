<!--
Companion detection note for the Claude Code worktree ".git" directory-confusion sandbox-escape Sigma rule.
Accuracy source: resources/examples/persistence/observed_claude_code_worktree_git_confusion_t1546_004.yml
Advisory source: https://github.com/anthropics/claude-code/security/advisories/GHSA-7835-87q9-rgvv (fetched
via `gh api repos/anthropics/claude-code/security-advisories/GHSA-7835-87q9-rgvv`).
Detection/defense only, no exploit/PoC reproduced beyond what the vendor advisory already published.
-->

# Detecting the Claude Code Git-Worktree Sandbox Escape (CVE-2026-55607, CVSS 7.7)

A vendor-disclosed vulnerability in Claude Code itself (Anthropic's own advisory) — included in this corpus because the same detection discipline that applies to any AI-tooling vulnerability applies to the tooling this corpus's own maintainers use.

## What the flaw actually does

Claude Code's worktree handling (versions `>= 2.1.38, < 2.1.163`) allowed creating a git worktree literally named `.git`, and navigating to worktrees outside the sandbox context — "git directory confusion." Combined with symlink manipulation and git fsmonitor execution during worktree operations, this let an attacker overwrite files in the user's home directory (the advisory names `.zshenv` as the example), achieving code execution outside the macOS seatbelt sandbox's restrictions the next time a shell starts.

This is a **chained** attack, not a network-reachable exploit on its own: the advisory is explicit that reliable exploitation required the user to clone a malicious repository containing prompt-injection content and run Claude Code against it. The chain is prompt injection → sandbox-scoped tool misuse → host-level persistence. The takeaway for anyone running Claude Code (or a similar sandboxed agentic coding tool) against untrusted repositories: sandbox escapes in this class of tooling don't need a separate initial-access vector — the untrusted repository content itself, processed through prompt injection, IS the initial access.

## The detection signal

The corpus rule flags a `git worktree add` invocation whose target name is literally `.git` — ordinary worktree usage never names a worktree this way, since it collides with git's own internal directory name. This is a high-precision signal on the specific artifact, not a heuristic on worktree usage in general.

## Known limitation

This rule has not been validated against a live macOS process-monitoring log source — it was authored directly against the advisory's own text, with no such log source available at authoring time. Verify the field names and process-creation event shape against your actual EDR/monitoring tool's output before relying on it as written.

## What to do right now

1. **Upgrade Claude Code to 2.1.163 or later.**
2. If you run Claude Code (or any sandboxed agentic coding tool) against repositories you don't fully trust, treat that as an active-risk operation regardless of version — the underlying chain (prompt injection via untrusted repo content → sandbox-scoped tool misuse) is a general class this specific CVE happens to be one instance of, and future instances in this or similar tools are plausible.
3. Deploy the detection rule above against macOS process-creation telemetry on any host running Claude Code against untrusted repositories.

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of a vendor-disclosed, now-patched vulnerability in Claude Code itself. Reference: [anthropics/claude-code Security Advisory GHSA-7835-87q9-rgvv](https://github.com/anthropics/claude-code/security/advisories/GHSA-7835-87q9-rgvv).*
