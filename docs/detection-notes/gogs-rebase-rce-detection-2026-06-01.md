<!--
Companion detection note for R89-149d (Gogs rebase-RCE Sigma rule, PR #8 MERGED 2026-06-01T20:14Z).
Accuracy source: resources/examples/execution/observed_gogs_rebase_rce_t1059.yml (merged, V-152v T1 GREEN).
V-152v finding incorporated: shell-intermediary evasion-FN documented in "Known limitation" section.
Status: operator-ready draft. Operator posts (Detection Frontier / dev.to); D drafts only.
De-AI pass: no em-dashes, no symmetric-triplet padding, plain ASCII.
Brand: WRG-11 byline. Detection/defense only, no exploit/PoC.
-->

# Detecting the Gogs Rebase RCE Before a Patch Exists

A critical authenticated remote-code-execution flaw in Gogs (the self-hosted Git service) is public, has a working Metasploit module, and as of this writing has no patch. If you run a Gogs instance you cannot wait for a fix to defend it. The good news: the attack leaves a clean, specific signal in process telemetry, and you can detect it today with one rule.

## What the flaw actually does

Gogs offers a "Rebase before merging" option on pull requests. Behind the scenes it runs `git rebase <base_branch> <head_branch>` in a temporary directory. The base branch name is passed to `git rebase` without a `--` separator, so git is free to interpret a branch name that starts with a dash as a command-line flag.

`git rebase` happens to support an `--exec` flag, which runs a shell command after each replayed commit. An attacker who can open a pull request (any authenticated user, and on instances with open registration that means anyone) can name a branch so that the name itself becomes an `--exec=<command>` flag. When Gogs runs the rebase, git runs the attacker's command as the Gogs server user.

The impact is full server compromise: read every repository on the instance including other users' private code, dump stored credentials and tokens, and pivot into the network. Rapid7 scored it CVSSv4 9.4.

## The detection signal

The artifact is a process: the Gogs server spawns `git rebase` with an `--exec` (or `-x`) flag on the command line. That is the whole signal, and it is specific.

The one trap to avoid is false positives. `git rebase --exec` is a legitimate developer feature. Plenty of engineers run `git rebase --exec "make test"` by hand, and CI systems do it too. A rule that alerts on `git rebase --exec` alone will bury your analysts in benign developer activity.

The discrimination that makes the rule precise is the parent process. In the exploit, the rebase is launched by the Gogs server process. A developer or CI runner launching the same command has a shell, an IDE, or a runner as the parent instead. Scope the rule to the Gogs server as the parent and the legitimate uses fall away on their own, with no fragile allowlist to maintain.

## The rule

A Sigma rule for this is published in the WRG-11 `wrg-sigma-rules` corpus as `execution/observed_gogs_rebase_rce_t1059.yml`. Its three-part condition, in plain terms:

- the process image is `git`,
- the command line contains `rebase` and `--exec` (or `-x`),
- and the parent process is the Gogs server (`ParentImage` ends with `/gogs`).

All three must be true simultaneously. A legitimate `git rebase --exec` from a shell or CI runner never satisfies the parent condition, and a normal Gogs rebase-merge never carries `--exec`. Only the exploit matches all three. The rule targets `process_creation` on Linux, where most Gogs servers run.

## Known limitation: shell-intermediary deployments

Depending on how Gogs is installed, the server may spawn git indirectly via a shell wrapper: `gogs -> sh -c "git rebase --exec=<cmd>"`. In that case the git process has `/sh` as its parent, not `/gogs`, and the rule will not fire. This is a coverage gap, not a false positive: the rule is silent rather than wrong.

If your Gogs deployment uses a shell intermediary, add a supplementary rule that looks for `sh -c "git rebase.*--exec"` patterns where the parent is the Gogs process, or instrument at a higher level (process tree rather than direct parent). The direct-spawn path (gogs -> git) is the primary case and is caught cleanly; the shell-wrapper path is a documented follow-up.

## A second, cheaper signal

If you keep Gogs application or web-server logs, watch for pull requests whose base or head branch name begins with `--`. A legitimate branch name has no reason to start with a dash. This catches the malicious branch at creation time rather than at merge time, and works even if your process telemetry has the shell-intermediary gap described above.

## What to do right now

1. Deploy the process-creation rule above, or the branch-name audit, or both.
2. Close open registration on any internet-facing Gogs instance. The flaw needs an authenticated account, so removing self-service signup shrinks the attacker pool sharply.
3. Restrict who can use the rebase-merge option if your workflow allows it.
4. Audit existing API tokens and credentials on the instance, since a successful exploit can read them.

A patch will come eventually. Detection does not have to wait for it.

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of an already-public technique. References: [Rapid7 disclosure](https://www.rapid7.com/blog/post/ve-authenticated-rce-via-argument-injection-gogs-unfixed/) and [The Hacker News coverage](https://thehackernews.com/2026/05/critical-gogs-rce-vulnerability-lets.html).*
