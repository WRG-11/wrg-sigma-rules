<!--
Companion detection note covering TWO sibling Sigma rules against vllm-project/vllm's audio endpoints,
both CVSS 6.5, both memory-exhaustion DoS bugs reached through different mechanisms on the same routes:
- resources/examples/impact/observed_vllm_audio_decompression_bomb_t1499.yml
- resources/examples/impact/observed_vllm_audio_upload_pre_limit_memory_exhaustion_t1499.yml
Advisory sources: GHSA-6pr9-rp53-2pmc / GHSA-v82g-2437-67m2, both fetched via
`gh api repos/vllm-project/vllm/security-advisories/<id>` (CVSS 6.5 confirmed live for both).
Detection/defense only, no exploit/PoC reproduced beyond what the vendor advisories already published.
-->

# Detecting Two vLLM Audio-Endpoint Memory-Exhaustion Bugs (CVSS 6.5 each)

Two vLLM DoS vulnerabilities on the same audio-transcription routes, both reaching memory exhaustion but through mechanistically distinct paths — worth reading together because the two failure shapes are opposite ends of "the size check didn't work."

## What each flaw actually does

**1. The check happens too late (CVE-2026-55646).** `/v1/audio/transcriptions` and `/v1/audio/translations` call `request.file.read()` to fully materialize an uploaded file into memory BEFORE the documented `VLLM_MAX_AUDIO_CLIP_FILESIZE_MB` limit (default 25MB) is checked — the check happens later, in the speech-to-text preprocessing step. A caller submits a multipart upload far larger than the limit; vLLM allocates memory proportional to the FULL uploaded size before the request is ever rejected as too large. The size check exists and works, it's just positioned after the expensive operation instead of before it.

**2. The check measures the wrong quantity (CVE-2026-54233).** The compressed-upload size limit is enforced correctly and BEFORE decoding — but it only bounds the COMPRESSED size, never the DECODED PCM output size, a classic decompression-bomb shape. The advisory's own measured ratio: a 25MB OPUS file (comfortably within the compressed limit) expands to approximately 14.9GB of float32 PCM at decode time. A caller submitting an ordinary, size-compliant compressed file still exhausts server memory.

## The shared lesson

Read together, these are the two ways a size limit can fail even when someone clearly intended to enforce one: check it at the wrong TIME (#1 — after the expensive read, not before) or check the wrong THING (#2 — compressed size, not decoded size). Any upload-handling path that decodes/decompresses/transforms user input needs both properties verified explicitly: the size check must run before the expensive operation, AND it must bound the post-transform size, not just the pre-transform one.

## The detection signals

- **#1 (proxy logsource):** a request to `/v1/audio/transcriptions` or `/v1/audio/translations` whose body exceeds the documented limit (`cs-bytes > 26214400`, i.e. >25MB) — this rule catches the oversized-request shape directly.
- **#2 (proxy logsource):** a request to `/v1/audio/transcriptions` using an OPUS codec (the high-compression-ratio format the advisory measured) at a size approaching but not exceeding the 25MB limit — the specific shape that passes the compressed-size check while still expanding to a memory-exhausting decoded size.

## Known limitations (per rule)

**#1** is a fairly direct signal (an oversized request to these endpoints IS the vulnerability manifesting on an unpatched deployment) — the main caveat is that a fixed deployment (0.24.0+) rejects the same oversized request cleanly before allocating, so a match there reflects normal, safe rejection.

**#2** is a proxy heuristic, not a certainty — not every near-limit OPUS upload is a decompression bomb (a legitimate long-form audio file compresses similarly), and the rule cannot measure the actual decode-time expansion from request metadata alone. Treat a match as "worth checking resource usage during processing," not confirmed abuse.

Both: on a deployment upgraded to 0.24.0+, a matching request is rejected/bounded rather than causing the described exhaustion.

## What to do right now

1. **Upgrade to vLLM 0.24.0 or later** — both fixed in the same version.
2. If you build any upload-handling endpoint that decodes or decompresses input, verify explicitly: (a) the size check runs before the expensive read/decode, and (b) it bounds the POST-transform size, not just the pre-transform one — this pair of bugs is a concrete, sourced checklist for exactly that audit.
3. Deploy the two detection rules above against proxy/access logs in front of vLLM's audio endpoints.

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of two vendor-disclosed, now-patched vulnerabilities. References: [vllm-project/vllm GHSA-6pr9-rp53-2pmc](https://github.com/vllm-project/vllm/security/advisories/GHSA-6pr9-rp53-2pmc), [GHSA-v82g-2437-67m2](https://github.com/vllm-project/vllm/security/advisories/GHSA-v82g-2437-67m2).*
