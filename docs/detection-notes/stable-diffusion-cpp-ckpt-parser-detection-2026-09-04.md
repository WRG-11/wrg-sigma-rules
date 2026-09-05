<!--
Companion detection note covering TWO sibling Sigma rules against the same project (leejet/stable-diffusion.cpp),
sharing the wrg.observed.cluster.stable_diffusion_cpp_ckpt_parser_bugs tag:
- resources/examples/execution/observed_stable_diffusion_cpp_ckpt_global_opcode_heap_overflow_t1059.yml
- resources/examples/execution/observed_stable_diffusion_cpp_ckpt_sign_confusion_heap_overflow_t1059.yml
Advisory sources: GHSA-v37x-jwp7-mcvc / GHSA-2c29-5hxg-fv9g, both fetched via
`gh api repos/leejet/stable-diffusion.cpp/security-advisories/<id>`.
Detection/defense only, no exploit/PoC reproduced beyond what the vendor advisories already published.
-->

# Detecting Two stable-diffusion.cpp .ckpt Parser Heap Overflows (CVSS 7.8)

Two memory-corruption bugs in the same pickle `.ckpt` parser, disclosed in the same advisory round, fixed in the same commit. Both corpus rules use IDENTICAL detection logic on purpose — this note explains why, so a reader doesn't mistake that for an authoring shortcut.

## What each flaw actually does

**1. GLOBAL opcode: a missing newline becomes a length of -1 (CVE-2026-47750, CVSS 7.8).** The parser searches for newline-delimited fields when processing the `GLOBAL` opcode, with no validation that the expected newline is actually present. A crafted `.ckpt` file that omits it causes the field-length computation to produce `-1` — used directly as a `memcpy` copy length, immediate heap corruption.

**2. SHORT_BINUNICODE: an unsigned read of signed storage (CVE-2026-47749, CVSS 7.8).** The `SHORT_BINUNICODE` opcode's length field is read as if unsigned, but the underlying storage permits a negative signed value, which a crafted file supplies. The negative value, interpreted as a huge unsigned length, reaches `memcpy` directly — same heap-corruption outcome as #1, different opcode, different byte pattern.

Both live in `src/model.cpp`'s pickle parser and were disclosed together, fixed together, in commit `0a7ae07f948eff4611968a65a22bd7c7031ad74f` (`master-584-0a7ae07`).

## Why the detection signal is identical for both (not an oversight)

Both corpus rules flag the same thing: a `.ckpt` file being loaded by a stable-diffusion.cpp process. This is deliberate, not a missed differentiation opportunity — host-level file-event logging cannot see WHICH opcode handler a given `.ckpt` load reaches internally; that distinction lives inside file content the log source doesn't capture. The two rules exist as separate entries because they're separate CVEs worth naming individually (for tracking, patching, and reporting purposes), not because the detection logic differs. If your log source can inspect file content, a sharper signal is possible: for #1, a `GLOBAL` opcode field with no newline; for #2, a `SHORT_BINUNICODE` opcode (`0x8c`) immediately followed by a length byte with its high bit set. Neither of the current corpus rules attempts this, since most infrastructure doesn't capture binary file content at this granularity.

## The detection signal

**Both rules (file_event logsource):** a `.ckpt` file loaded by a process whose image contains `sd` or `stable-diffusion`.

## Known limitations (apply to both)

Neither rule can distinguish a malicious crafted `.ckpt` file from an ordinary legitimate one by filename/extension alone — the malicious byte pattern lives inside file content, invisible to a file-event-only signal. The advisory's own recommended mitigation — prefer `.safetensors` over `.ckpt`, since `.safetensors` has no pickle-based parsing path to exploit — is a stronger control than either detection rule can verify the absence of. Treat these rules as a coarse "a .ckpt file was loaded at all" tripwire, not a precise exploitation signal.

## What to do right now

1. **Upgrade past `master-584-0a7ae07`** — both bugs are fixed in the same commit.
2. **Prefer `.safetensors` over `.ckpt`** wherever your workflow allows it — this is the advisory's own recommended workaround and eliminates the entire pickle-parsing attack surface these two bugs (and any future ones in the same parser) share, rather than patching one opcode handler at a time.
3. If you must load untrusted `.ckpt` files pre-upgrade, do so in an isolated/sandboxed process — the advisory notes code-execution potential depending on heap layout, not merely a crash.
4. Deploy the shared detection rule above (either corpus entry; they're identical) against file-event telemetry on any host running stable-diffusion.cpp.

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of two vendor-disclosed, now-patched vulnerabilities. References: [leejet/stable-diffusion.cpp GHSA-v37x-jwp7-mcvc](https://github.com/leejet/stable-diffusion.cpp/security/advisories/GHSA-v37x-jwp7-mcvc), [GHSA-2c29-5hxg-fv9g](https://github.com/leejet/stable-diffusion.cpp/security/advisories/GHSA-2c29-5hxg-fv9g).*
