<!--
Companion detection note covering TWO sibling Sigma rules against Anthropic's own Claude Code products
(different repos, same vendor):
- resources/examples/initial_access/observed_claude_code_action_mcp_json_pr_rce_t1195_002.yml
- resources/examples/collection/observed_claude_code_copy_tmp_symlink_t1552.yml
Advisory sources: GHSA-8q5r-mmjf-575q (repos/anthropics/claude-code-action) / GHSA-4vp2-6q8c-pvq2
(repos/anthropics/claude-code), both fetched via `gh api repos/<owner>/<repo>/security-advisories/<id>`.
Detection/defense only, no exploit/PoC reproduced beyond what the vendor advisories already published.
-->

# Detecting Two Claude Code Vulnerabilities (CVSS 4.4-5.3)

Two more vendor-disclosed vulnerabilities in Anthropic's own tooling (alongside this corpus's earlier worktree-confusion note) — different products, different bugs, same discipline applied: this corpus tracks vulnerabilities in the tools its own maintainers use, not only in third-party AI infrastructure.

## What each flaw actually does

**1. Trusting the PR's own configuration to run the PR (CVE-2026-47751, CVSS 5.3).** `claude-code-action` — the GitHub Action that runs Claude Code on pull requests — checked out the attacker-controlled PR HEAD branch, read `.mcp.json` from that checkout, and unconditionally enabled every project MCP server via `enableAllProjectMcpServers`. An attacker opens a PR containing a malicious `.mcp.json`; whenever a privileged user or automatic trigger invokes the Claude action on that PR, the attacker's MCP server configuration runs with the workflow's own privileges — arbitrary code execution on the runner, secrets exfiltration. The fix restores `.claude/` and `.mcp.json` from the PR's BASE branch (the trusted, pre-PR state) rather than the attacker-supplied HEAD.

**2. A predictable path with no isolation, in either direction (CVE-2026-46406, CVSS 4.4).** Claude Code's `/copy` command wrote its response to a hardcoded path, `/tmp/claude/response.md`, world-readable (`0644`) inside a world-traversable directory (`0755`), with no UID isolation, no randomness, no symlink protection. This is exploitable two ways by any unprivileged user on the same host: read the file after a privileged user runs `/copy` (disclosure), or pre-plant a symlink at the expected path BEFORE they run it (the privileged process follows the symlink and overwrites an attacker-chosen file with the response text).

## The detection signals

- **#1 (file-event/PR-content logsource):** a `.mcp.json` file (in a checked-out PR) whose content contains a `"command"` field naming a shell interpreter (`bash`, `sh`, `powershell`).
- **#2 (process-creation logsource):** an `ln -s` symlink-creation syscall targeting `/claude/response.md`.

## Known limitations (per rule)

**#1** flags the presence of a shell-interpreter command in `.mcp.json` — a legitimate MCP server configuration can also invoke a shell for benign reasons; this rule is a precursor signal (the specific shape the exploit needs), not confirmation of malicious intent. On a fixed deployment (1.0.74+), the base-branch restoration means this file content, even if present in the PR HEAD, never actually gets read by the action.

**#2** is a high-precision signal (symlink creation at this exact predictable path has no benign explanation) but requires process-creation telemetry that captures the full target path.

Both: on an upgraded deployment (#1: 1.0.74+, #2: 2.1.128+), the underlying vulnerable behavior no longer occurs even if the precursor signal is observed.

## What to do right now

1. **Upgrade**: `claude-code-action` to 1.0.74+; Claude Code itself to 2.1.128+.
2. If you run any CI action that processes a PR's own configuration files (not just Claude-specific tooling), verify it reads trusted-source configuration (the base branch, a pinned ref) rather than the PR head's potentially-attacker-controlled version — #1's exact lesson generalizes to any "run config from the PR" CI pattern.
3. If you write any tool that creates a shared, predictable-path temp file, verify it uses per-user isolation (a UID- or randomness-derived path) and `O_NOFOLLOW`/equivalent symlink protection — #2's exact lesson.
4. Deploy the two detection rules above against the log sources each requires.

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of two vendor-disclosed, now-patched vulnerabilities. References: [anthropics/claude-code-action GHSA-8q5r-mmjf-575q](https://github.com/anthropics/claude-code-action/security/advisories/GHSA-8q5r-mmjf-575q), [anthropics/claude-code GHSA-4vp2-6q8c-pvq2](https://github.com/anthropics/claude-code/security/advisories/GHSA-4vp2-6q8c-pvq2).*
