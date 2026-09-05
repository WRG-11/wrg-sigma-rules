<!--
Companion detection note for the PraisonAI Claude GitHub Action branch-injection Sigma rule.
Accuracy source: resources/examples/execution/observed_praisonai_claude_gha_branch_injection_t1059_004.yml
Advisory source: https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-xp85-6wwf-r67c (fetched
via `gh api repos/MervinPraison/PraisonAI/security-advisories/GHSA-xp85-6wwf-r67c`; CVSS 10.0 confirmed live).
Detection/defense only, no exploit/PoC reproduced beyond what the vendor advisory already published.
-->

# Detecting the PraisonAI Claude GitHub Action Branch-Name Injection (CVE-2026-48168, CVSS 10.0)

PraisonAI's bundled Claude-response GitHub Action ran an unquoted shell command built from a pull request's branch name — and triggered on any `@claude` comment, from anyone, with no check on who was commenting.

## What the flaw actually does

The workflow's `claude-response` job ran `git fetch origin pull/${{ github.event.issue.number }}/head:${{ steps.check_fork.outputs.pr_branch }}` inside an unquoted Bash `run:` block, with no validation that the branch name was a plausible git ref. Separately, the workflow's trigger condition never checked `github.event.comment.author_association` — so a fork contributor with no special privileges could open a PR whose branch name contained shell metacharacters, comment `@claude` on it, and the malicious branch name would be interpreted as shell commands the moment the job ran.

The advisory's own proof-of-concept branch name uses `${IFS}` (the shell's internal field separator variable) to smuggle spaces past naive filtering, and writes an attacker-controlled entry into `$GITHUB_PATH` — poisoning which binaries later steps in the same job resolve when they run. That job held `contents: write`, `pull-requests: write`, `issues: write`, and `id-token: write` — a fork PR's branch name alone was enough to reach all four.

This is the same root shape as three other GitHub-Actions-supply-chain rules already in this corpus (attacker PR content reaching a privileged CI execution context) — the distinguishing detail here is that the injection vector is the branch **name** itself, not a file the PR ships, which is why it is filed under execution (T1059.004) rather than initial_access.

## The detection signal

The corpus rule (`execution/observed_praisonai_claude_gha_branch_injection_t1059_004.yml`) requires both a `git fetch origin pull/` command line and a shell-metacharacter marker (`;`, `${IFS}`, `$GITHUB_PATH`, `$(GITHUB_PATH)`) in the same command line — the specific combination the exploit needs, distinct from either condition appearing alone in ordinary CI activity.

## Known limitation

On a repository already upgraded to PraisonAI 4.6.40+ (where the fix quotes the branch name and/or gates the trigger on `author_association`), a matching command line reflects a rejected or inert attempt rather than successful exploitation. Separately, a legitimate branch name containing a semicolon or `$` sequence for unrelated reasons is rare given normal git ref naming conventions, but a log source that cannot distinguish a PR-sourced branch name from a maintainer-created one will still flag it as a coincidental match.

## What to do right now

1. **Upgrade to PraisonAI 4.6.40 or later.** The fix both quotes the branch-name interpolation and gates the `@claude` trigger on commenter authorization.
2. If you maintain any similar custom CI workflow that interpolates a PR-controlled branch name (or any other attacker-influenceable git ref) into a shell command without quoting, treat this as a template for the same bug class — check for it directly rather than assuming it's PraisonAI-specific.
3. Audit which permissions your `@claude`-triggered (or similarly comment-triggered) CI jobs actually need; `id-token: write` alongside three other write scopes is a large blast radius for a job reachable by an unvetted commenter.
4. Deploy the detection rule above against process-creation telemetry on GitHub Actions runners.

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of a vendor-disclosed, now-patched vulnerability. Reference: [MervinPraison/PraisonAI Security Advisory GHSA-xp85-6wwf-r67c](https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-xp85-6wwf-r67c).*
