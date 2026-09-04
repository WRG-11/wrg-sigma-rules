<!--
Companion detection note for the AutoGPT Platform Redis cache pickle-deserialization RCE Sigma rule.
Accuracy source: resources/examples/execution/observed_autogpt_redis_pickle_cache_poisoning_rce_t1059.yml
Advisory source: https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-rfg2-37xq-w4m9
(fetched via `gh api repos/Significant-Gravitas/AutoGPT/security-advisories/GHSA-rfg2-37xq-w4m9`; CVSS 7.6
confirmed live).
Detection/defense only, no exploit/PoC reproduced beyond what the vendor advisory already published.
-->

# Detecting AutoGPT's Redis Cache Pickle-Deserialization RCE (CVE-2026-33233, CVSS 7.6)

AutoGPT Platform's cache layer trusted its own Redis-stored bytes to be safe to deserialize with `pickle` — a design that turns any way of writing to that Redis key into remote code execution.

## What the flaw actually does

The backend's cache layer writes values to Redis with `pickle.dumps(...)` and reads them back with a bare `pickle.loads(cached_bytes)` — no HMAC/signature check, no strict schema validation gating the deserialization. Python's `pickle` protocol executes arbitrary code during unpickling via an object's `__reduce__` method; the advisory's own PoC uses a crafted class that, when deserialized, creates a proof file (`/tmp/autogpt_pickle_rce_official`) as evidence of command execution. Any attacker able to write to the shared Redis cache key — through a separate Redis-access vulnerability, a misconfigured or exposed Redis instance, or another service sharing the same cache — can trigger arbitrary command execution in the backend container simply by having their poisoned bytes read back through the normal cache-read path. This is not itself a network-reachable exploit — it requires SOME way to write the poisoned bytes to Redis first — but it turns "attacker can write to Redis" (a bug class treated as lower-severity in many threat models) into full RCE.

## The detection signal

The corpus rule flags the resulting host-level artifact: a Python process attributed to the AutoGPT backend spawning a child process as a direct consequence of a cache read — legitimate cache reads never spawn subprocesses, so any subprocess creation immediately following a `cache.py` read call in the same process is the anomaly this bug makes possible.

## Known limitation

This rule cannot distinguish a legitimate backend-initiated subprocess (block execution, external tool invocation — both normal AutoGPT behaviors) from a pickle-triggered one by process lineage alone. Correlate with a preceding Redis read in application logs, or check for the specific proof-of-concept artifact name (`/tmp/autogpt_pickle_rce_official`) the advisory's own PoC creates, for higher confidence before treating a hit as confirmed exploitation.

## What to do right now

1. **Upgrade to AutoGPT Platform 0.6.52 or later**, which moves to a non-code-executing serialization format with schema validation.
2. The advisory's own additional recommendations are worth applying regardless of upgrade timing: HMAC-sign cached values, and harden the Redis deployment itself (authentication, TLS, network isolation) — this closes the "how does an attacker write to Redis in the first place" question the detection rule alone doesn't address.
3. If you maintain any application that caches pickled Python objects in Redis (or any shared store another service can potentially write to), treat this as the general lesson: `pickle.loads()` on data from a store you don't fully control is a code-execution primitive, not a caching implementation detail.
4. Deploy the detection rule above against process-creation telemetry on the AutoGPT backend host, correlated with Redis access logs where available.

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of a vendor-disclosed, now-patched vulnerability. Reference: [Significant-Gravitas/AutoGPT Security Advisory GHSA-rfg2-37xq-w4m9](https://github.com/Significant-Gravitas/AutoGPT/security/advisories/GHSA-rfg2-37xq-w4m9).*
