<!--
Companion detection note covering THREE Sigma rules for hosted-LLM abuse:
- resources/examples/command_and_control/observed_promptflux_honestcue_gemini_api_dns_scripting_host_t1102_002.yml
- resources/examples/defense_evasion/observed_promptflux_llm_self_regenerating_vbscript_t1027.yml
- resources/examples/defense_evasion/observed_pliny_dataset_card_pretext_jailbreak_t1027.yml
Sources: GTIG AI Threat Tracker, 2025-11-06 and 2026-05-12 (fetched 2026-09-23);
the X post linked in the third rule (search-indexed; the post body itself sits behind a login wall).
Detection/defense only, no malware code or jailbreak payload reproduced.
-->

# Detecting Hosted-LLM Abuse: Malware That Calls Gemini at Runtime, and a Dataset-Card Jailbreak Frame

Two of these rules cover malware that uses a hosted LLM as a runtime capability instead of shipping its evasion logic statically. The third covers a prompt-side jailbreak framing seen in an LLM gateway log.

## What the sources actually say

**PROMPTFLUX** (GTIG, November 2025) is a VBScript dropper. It sends a POST request to the Gemini API with a hard-coded API key and specifies the `gemini-1.5-flash-latest` model. It prompts the model to rewrite its own source code and saves the new, obfuscated version to the Startup folder for persistence. Its "Thinking Robot" module periodically queries Gemini for new evasion code and logs the model responses to `%TEMP%\thinking_robot_log.txt`. GTIG describes it as experimental and **unattributed**; the filenames suggest financially motivated operators.

**HONESTCUE** (GTIG, May 2026) asks the Gemini API for specific VBScript obfuscation and evasion techniques, to support just-in-time self-modification that evades static signatures. GTIG does not attribute it to a named actor either.

**PROMPTSPY** (GTIG, May 2026) is an Android backdoor that posts to `generativelanguage.googleapis.com` with the `gemini-2.5-flash-lite` model. These Windows rules do not cover it. It is listed here only because the same report discusses it next to HONESTCUE.

**The dataset-card frame** comes from a public autonomous jailbreaking run against Gemini 3.5 Flash by Pliny the Liberator in May 2026. The restricted request was framed as filling in example records for an open-source HuggingFace dataset card, and the run went on to produce content beyond the initial request.

None of the three rules names a nation-state actor, because none of the sources does.

## The detection signals

- **Gemini API resolved by a scripting host** (`dns_query`): `wscript`, `cscript`, `mshta`, PowerShell or a LOLBin resolving `generativelanguage.googleapis.com`. This is the network surface of both PROMPTFLUX and HONESTCUE.
- **PROMPTFLUX self-regeneration artefacts** (`file_event`): the `thinking_robot_log.txt` response log, or a Windows Script Host process writing a `.vbs`/`.vbe`/`.js` file into a Startup folder.
- **Dataset-card pretext** (`llm_gateway` prompt log): a dataset-card or model-card structure combined with reviewer or placeholder pretext markers.

## Known limitations

- The DNS rule's main false-positive surface is PowerShell automation that legitimately calls Gemini. Allowlist by script path or signed account; the `wscript`/`cscript`/`mshta` hits are the high-signal subset.
- The log file name is an author-controlled indicator. The Startup-folder write is the part that survives renaming.
- LLM gateway prompt logging is not standard telemetry. Bind the `prompt` field to your AI-proxy schema before deploying the third rule, and pair it with a session-level breadth metric: the escalation seen in the run is behavioural, and a single prompt does not show it.
- Every sidecar sample is synthetic and is shaped from the published description, not captured telemetry.

## What to do right now

1. If you allow scripting hosts to reach the internet directly, deploy the DNS rule first. It is cheap and high-signal for `wscript`/`cscript`.
2. Block or alert on outbound LLM API access from hosts that have no business reason to reach it. The domain is a small, stable allowlist decision.
3. If you run an LLM gateway, turn on prompt logging before you need it. The third rule has nothing to read without it.

---

*Detection content from WinstonRedGuard (WRG-11). References: [GTIG AI Threat Tracker, November 2025](https://cloud.google.com/blog/topics/threat-intelligence/threat-actor-usage-of-ai-tools), [GTIG AI Threat Tracker, May 2026](https://cloud.google.com/blog/topics/threat-intelligence/ai-vulnerability-exploitation-initial-access), [the dataset-card jailbreak run](https://x.com/elder_plinius/status/2056853157162999903).*
