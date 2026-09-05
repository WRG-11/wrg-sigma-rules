<!--
Companion detection note covering FIVE sibling Sigma rules against the same project (vllm-project/vllm),
each a distinct CVE:
- resources/examples/initial_access/observed_vllm_hardcoded_trust_remote_code_bypass_t1195_002.yml
- resources/examples/impact/observed_vllm_sparse_tensor_multimodal_dos_t1499.yml
- resources/examples/impact/observed_vllm_structured_outputs_regex_redos_t1499.yml
- resources/examples/initial_access/observed_vllm_assert_security_check_optimized_mode_rce_t1195_002.yml
- resources/examples/impact/observed_vllm_mrope_prompt_embeds_assertion_crash_t1499.yml
Advisory sources: GHSA-mcmc-2m55-j8jj / GHSA-rwxx-mrjm-wc2m / GHSA-q8gq-377p-jq3r / GHSA-33cg-gxv8-3p8g
(all fetched via `gh api repos/vllm-project/vllm/security-advisories/<id>`) + huntr.com bounty reports for
the two CVEs sourced there. One CVSS discrepancy noted below (GHSA-mcmc-2m55-j8jj: corpus rule's
description says 8.7, the advisory's own API response says 8.8 -- this note uses the advisory's own
number).
Detection/defense only, no exploit/PoC reproduced beyond what the vendor advisories already published.
-->

# Detecting Five vLLM Vulnerabilities: When the Protection You Assumed Isn't There (CVSS 7.1-8.8)

Five distinct vLLM CVEs, disclosed close together, share one shape worth naming: each is a case where an operator (or a prior fix) reasonably believed a specific protection was in place, and it silently wasn't. Read together because the lesson generalizes past vLLM.

## What each flaw actually does

**1. Hardcoded `trust_remote_code=True` overrides the operator's own flag (CVE-2026-4944, CVSS 8.8, huntr.com bounty).** Two model implementation files (`nemotron_vl.py`, `kimi_k25.py`) hardcode `trust_remote_code=True` internally, silently overriding an operator's explicit `--trust-remote-code=False` startup flag. An operator who believes they've disabled arbitrary-code-execution-on-load is still exposed the moment either model architecture loads — and this is itself an *incomplete fix* for two prior CVEs that closed other code paths but missed these two files.

**2. Multimodal embedding validation gap, second time around (CVE-2026-56340, CVSS 8.8 per the advisory itself — the corpus rule's description states 8.7, a minor discrepancy this note corrects to the advisory's own number).** vLLM's `prompt-embeds` feature is missing sparse tensor index validation, and PyTorch disables sparse tensor invariant checks by default — a crafted request with malformed (negative or out-of-bounds) indices reaches unchecked tensor operations, causing crashes or resource exhaustion, with the advisory noting potential for memory corruption beyond DoS. This is a continuation of an *earlier* bug (CVE-2025-62164) whose prior fix only disabled `prompt-embeds` by default rather than fixing the validation — any deployment that re-enables the feature (a documented, supported configuration) is exposed again.

**3. A structural check that isn't a complexity check (CVE-2026-55574, CVSS 8.7).** The `structured_outputs.regex` parameter passes a user-supplied regex directly to grammar-compiler backends with no compilation timeout. The `outlines` backend's validation blocks structurally-unsafe constructs (lookarounds, backreferences) but performs no complexity analysis — a nested-quantifier pattern (`(a+)+` shape) passes every structural check while still exploding combinatorially, hanging the compiling worker indefinitely.

**4. A security check that Python's own optimization flag deletes (CVE-2026-41523, CVSS 7.5, GHSA + huntr.com).** The activation-function loading path uses a plain Python `assert` as its only guard against malicious HuggingFace model content. `python -O` or `PYTHONOPTIMIZE=1` — a common, documented production-performance practice — strips every assert statement from the running interpreter, silently removing this specific check along with every other one in the process. No error, no warning. A deployment run in optimized mode has unauthenticated RCE the moment a malicious model loads, purely because a performance flag also happened to disable the one line standing in the way.

**5. A single authorized request that crashes the whole server (CVE-2026-55514, CVSS 7.1).** Sending a pure prompt-embeds payload (no accompanying text prompt) to `/v1/completions` against a model configured for M-RoPE fails an internal `EngineCore` assertion — fatally, taking down the entire server process, not just the offending request. No special privilege beyond ordinary API access is needed; any authorized user can do this.

## The shared lesson

Three different mechanisms of the same underlying failure: a fix that covered some code paths but not all (#1, #2), a check whose scope was narrower than it looked (#3), and a check whose EXISTENCE depended on a runtime condition (`assert`, stripped by `-O`) nobody thought to verify (#4). #5 is the odd one out mechanically (an unguarded internal assertion, not a security check at all) but shares the same "one input shape nobody validated" root. If you operate any LLM-serving stack, the actionable habit here is: don't trust that a documented protection is active — verify it against your ACTUAL running configuration (interpreter flags, feature-enablement state, which code path a specific model class actually traverses).

## The detection signals

Each rule targets its specific trigger, since the five are not interchangeable:

- **#1 (application/vllm logsource):** a model-load event naming `NemotronVL` or `KimiK25`.
- **#2 (application/vllm logsource):** a `prompt_embeds` request whose `indices` field contains a negative value.
- **#3 (application/vllm logsource):** a `structured_outputs.regex` request containing a nested-quantifier pattern shape.
- **#4 (process-creation logsource):** a vLLM process command line containing `-O` or `PYTHONOPTIMIZE=1` — this flags the PRECONDITION, not a specific exploitation attempt.
- **#5 (webserver logsource):** a `/v1/completions` request with a `prompt_embeds` field and no accompanying `"prompt":"` field.

## Known limitations (per rule)

**#1, #2, #3** all require **application-level payload logging** (which model class loaded, the actual embedding indices, the actual regex parameter) that most infrastructure log sources do not capture by default — deploying these rules without that logging in place means they will never fire, silently.

**#4** flags configuration state, not an attack — a deployment running in optimized mode for legitimate performance reasons that never loads untrusted models will also match. Treat a hit as "review whether this deployment loads untrusted HuggingFace models," not as an attack alert by itself.

**#5** cannot distinguish the vulnerable M-RoPE-model case from the safe, supported non-M-RoPE prompt-embeds-only use case by request content alone — correlate with which model the request actually targets.

All five: on a deployment already upgraded past its respective fix, a matching event reflects safe, handled behavior rather than a real risk — check your version against each rule's specific fix version before treating a hit as urgent.

## What to do right now

1. **Upgrade**: #1 has no stated fixed version in the sources checked for this note (verify current vllm-project guidance); #2 is fixed at 0.13.0; #3 and #5 at 0.24.0; #4 at 0.22.0.
2. **Audit your actual runtime configuration against each assumption a fix depends on**: are you running with `-O`/`PYTHONOPTIMIZE=1`? Is `prompt-embeds` re-enabled after being disabled-by-default? Do you load NemotronVL or KimiK25 architectures?
3. If you cannot upgrade immediately, the compensating controls differ per bug: disable `prompt-embeds` if not required (#2), avoid `-O`/`PYTHONOPTIMIZE=1` on vLLM processes specifically even if used elsewhere (#4), restrict which model architectures your deployment will load from untrusted repositories (#1).
4. Deploy the five detection rules above against the log source each requires, with the application-level logging caveat from "Known limitations" addressed first for #1-#3.

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of five vendor-disclosed vulnerabilities, four now patched. References: [vllm-project/vllm GHSA-mcmc-2m55-j8jj](https://github.com/vllm-project/vllm/security/advisories/GHSA-mcmc-2m55-j8jj), [GHSA-rwxx-mrjm-wc2m](https://github.com/vllm-project/vllm/security/advisories/GHSA-rwxx-mrjm-wc2m), [GHSA-q8gq-377p-jq3r](https://github.com/vllm-project/vllm/security/advisories/GHSA-q8gq-377p-jq3r), [GHSA-33cg-gxv8-3p8g](https://github.com/vllm-project/vllm/security/advisories/GHSA-33cg-gxv8-3p8g), [huntr.com bounty 97f706f7](https://huntr.com/bounties/97f706f7-a852-49b2-a4eb-76811e611daf), [huntr.com bounty dcb05b04](https://huntr.com/bounties/dcb05b04-e625-41e7-adbc-bbae0cc2d64c).*
