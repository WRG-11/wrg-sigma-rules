<!--
Companion detection note covering TWO sibling Sigma rules against 1Panel-dev/MaxKB's code sandbox, both
disclosed together, both defeating a different half of the sandbox's security model:
- resources/examples/defense_evasion/observed_maxkb_frame_introspection_result_spoofing_t1036.yml
- resources/examples/defense_evasion/observed_maxkb_sendto_fastopen_sandbox_bypass_t1562_001.yml
Advisory sources: GHSA-f3c8-p474-xwfv (CVSS 3.1) / GHSA-w9g4-q3gm-6q6w (CVSS 5.0), both fetched via
`gh api repos/1Panel-dev/MaxKB/security-advisories/<id>`.
Detection/defense only, no exploit/PoC reproduced beyond what the vendor advisories already published.
-->

# Detecting Two MaxKB Code-Sandbox Escapes: Trusting the Wrong Channel (CVSS 3.1-5.0)

MaxKB's code sandbox enforces two different security properties — result integrity and network isolation — and both disclosed bugs work by finding a channel the enforcement mechanism didn't know to watch.

## What each flaw actually does

**1. A "secret" that's readable from inside the sandbox by design (CVE-2026-39419, CVSS 3.1).** The sandbox wrapper embeds a per-execution UUID as a bytecode constant, prefixed to its legitimate result line so the host can identify the real output line in mixed stdout. `sys._getframe(1).f_code.co_consts` — ordinary Python frame introspection — reads the wrapper's own compiled bytecode from inside the sandboxed code, recovering a value that was never meant to be visible there. The attacker writes a forged result line carrying the recovered UUID directly to file descriptor 1 via `os.write` (bypassing stdout redirection) and calls `sys.exit(0)` before the wrapper emits its own output — the host trusts the last UUID-prefixed line and acts on the forged one.

**2. A network hook that only watches one syscall (CVE-2026-39418, CVSS 5.0).** The sandbox's banned-hosts policy uses `LD_PRELOAD` to intercept `connect()`. Linux's `sendto()` with `MSG_FASTOPEN` establishes a TCP connection entirely at the kernel level without userspace calling `connect()` at all — and because glibc's `sendto()` invokes the kernel via an inline syscall instruction rather than the hooked `syscall()` wrapper, the interception never fires. An authenticated user with tool-editing permissions reaches internal services the IP-blocklist was supposed to make unreachable.

## The shared lesson

Both bugs are "the enforcement mechanism assumed one specific API surface was the only path to the effect it wanted to control" — #1 assumed stdout (fd 1 write via a specific pattern) was the only result channel; #2 assumed `connect()` was the only way to establish a TCP connection. Both assumptions were wrong because the underlying platform (Python's introspection API, Linux's socket syscalls) offers alternate paths to the same effect. If you build a sandbox that hooks or wraps a SPECIFIC function/syscall to enforce a security property, audit for every OTHER way to reach the same underlying effect the platform provides — a userspace hook only covers what calls through it.

## The detection signals

- **#1 (application logsource):** sandboxed output showing the frame-introspection idiom (`_getframe`, `f_code.co_consts`) together with a raw `os.write(1` followed by `sys.exit(0)`.
- **#2 (process-creation logsource):** a `sendto()` call carrying `MSG_FASTOPEN` from a process in the sandbox's execution context — **requires syscall-level tracing (auditd, eBPF)**; ordinary process-creation/command-line logging does not capture socket flags at all, so most infrastructure cannot populate this selection without dedicated syscall auditing.

## Known limitations (per rule)

**#1** needs application-level logging of the actual code string submitted to the sandbox, and cannot fully rule out unrelated legitimate use of `sys._getframe` combined with separate `os.write`/`sys.exit` calls in the same submission (narrow but not impossible in advanced debugging workloads).

**#2** is effectively undeployable without syscall-level tracing already in place — treat the rule as a template for whatever syscall-audit tooling your environment actually runs, not something Sysmon-equivalent logging can populate as written.

Both: on a deployment upgraded to 2.8.0+, the underlying bypass no longer works even if the observable pattern appears.

## What to do right now

1. **Upgrade to MaxKB 2.8.0 or later** — both fixed in the same release.
2. If you build any sandbox that identifies its own output via an embedded token, verify the token cannot be recovered via language-level introspection APIs available inside the sandboxed execution context — #1's exact lesson.
3. If you build any sandbox that enforces network policy via a hooked function, verify your hook covers every platform-level path to the same effect (all relevant syscalls, not just the common one) — #2's exact lesson, and worth checking against `sendmsg()` as well per the advisory's own stated fix direction.
4. Deploy #1's detection rule against application logging; #2's only if you already run syscall-level tracing.

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of two vendor-disclosed, now-patched vulnerabilities. References: [1Panel-dev/MaxKB GHSA-f3c8-p474-xwfv](https://github.com/1Panel-dev/MaxKB/security/advisories/GHSA-f3c8-p474-xwfv), [GHSA-w9g4-q3gm-6q6w](https://github.com/1Panel-dev/MaxKB/security/advisories/GHSA-w9g4-q3gm-6q6w).*
