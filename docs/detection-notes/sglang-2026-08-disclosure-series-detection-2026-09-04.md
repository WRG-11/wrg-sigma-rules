<!--
Companion detection note covering SIX sibling Sigma rules from the same coordinated SGLang disclosure
series (the rules themselves cross-reference each other as siblings, sharing the
wrg.observed.cluster.sglang_2026_08_disclosure_series tag):
- resources/examples/execution/observed_sglang_lora_adapter_safeunpickler_bypass_rce_t1059.yml
- resources/examples/execution/observed_sglang_dumper_subsystem_sandbox_escape_t1059.yml
- resources/examples/execution/observed_sglang_weights_from_disk_pickle_rce_t1059.yml
- resources/examples/initial_access/observed_sglang_expert_backup_zeromq_pull_rce_t1190.yml
- resources/examples/credential_access/observed_sglang_server_info_credential_leak_t1552.yml
- resources/examples/exfiltration/observed_sglang_nccl_weight_broadcast_exfil_t1041.yml
Advisory sources: GHSA-2wvm-gjg7-5jfm / GHSA-h6rf-77vv-9mvj / GHSA-wf98-gv64-5wrf / GHSA-jx7q-p32r-7wx8 /
GHSA-cpqq-22v3-2wfm all return 404 on the GitHub security-advisories API as of this writing (not yet
published to the queryable advisory database) -- corroborated instead via
https://thoughts.apoorvdayal.com/posts/sglang-disclosures/ (fetched directly, confirmed to cover all five
of these plus the /server_info and NCCL-broadcast flaws specifically) and
https://www.kb.cert.org/vuls/id/326070 (fetched directly, confirms CVE-2026-14890) plus direct source
verification for the expert-backup rule.
Detection/defense only, no exploit/PoC reproduced beyond what the published sources already contain.
-->

# Detecting the SGLang 2026-08 Disclosure Series: Six Vulnerabilities (CVSS 7.5-9.8)

SGLang, a high-performance LLM/VLM serving engine, shipped six distinct vulnerabilities disclosed in the same coordinated research window. Four are unauthenticated RCE paths sharing one root cause class: trusting Python's `pickle` module — or a denylist meant to restrict it — on network-reachable input, instead of avoiding `pickle` for that input entirely. The other two are credential-leak and exfiltration bugs from the SAME series, sharing the corpus's own cluster tag with the first four. This note covers all six together because the corpus rules themselves are written as siblings.

## What each flaw actually does

**1. LoRA adapter loader — SafeUnpickler denylist bypass (CVE-2026-15969, CVSS 9.8).** `/load_lora_adapter_from_tensors` accepts a caller-supplied, base64-encoded pickle payload with no authentication. The endpoint's `SafeUnpickler` is meant to restrict which classes a pickle stream can reconstruct, but the independent researcher write-up corroborating this disclosure notes the allowlist includes the `builtins` namespace — which enables dynamic import and attribute lookup without ever naming a denied function directly. A crafted payload using that path reaches arbitrary code execution during deserialization.

**2. Dumper subsystem — opt-in debug port sandbox escape (CVE-2026-15971, CVSS 9.8).** Setting the `DUMPER_SERVER_PORT` environment variable enables a debug/introspection subsystem reachable through ordinary inference requests once active. The corroborating write-up's finding here is conceptual and worth internalizing beyond this one bug: "removing `__builtins__` does not create a Python sandbox," because objects still expose their classes and the subclass graph — the same object-graph-traversal idea behind the RAGFlow Jinja2 SSTI covered in a separate note in this corpus. This one requires the feature to be explicitly enabled; it is not on by default.

**3. `update_weights_from_disk` — unsafe `torch.load` fallback (CVE-2026-15976, CVSS 9.8).** SGLang loads model weight files a caller can direct it to fetch from a HuggingFace repository. The corroborating write-up specifies the unsafe fallback is deliberate for **legacy tar-format weight files** — SGLang disables PyTorch's safe `weights_only=True` mode specifically for that path, falling back to full pickle deserialization, which PyTorch's own documentation calls unsafe for untrusted input. A `.bin` file crafted as a malicious pickle stream, disguised as model weights, executes the moment SGLang loads it. Note: this path is source-analyzed in the corroborating write-up, not demonstrated end-to-end with a working PoC — treat it as verified-by-code-reading rather than verified-by-exploitation.

**4. Expert-backup ZeroMQ PULL socket — no-auth deserialization on a routable interface (CVE-2026-14890, CVSS 9.1).** `python/sglang/srt/elastic_ep/expert_backup_manager.py` binds a ZeroMQ PULL socket to a **routable** network interface (not loopback) — CERT/CC's own vulnerability note confirms this directly: "binding to an external IP address with no authentication." The only gate before the socket processes incoming data is a plain count of connected clients against `server_args.tp_size`; there is no authentication and no deserialization safeguard on what it receives. This one is mechanistically distinct from the other three: it is reached over a raw ZeroMQ TCP socket, not an HTTP endpoint.

**5. `/server_info` returns secrets it was never gated to protect (CVE-2026-15977, CVSS 7.5).** When a deployment sets ONLY `--admin-api-key` (a common configuration for admin-gated deployments that otherwise expect the regular inference API to remain open or separately secured), the `/server_info` diagnostic endpoint returns API keys and SSL keyfile paths in its response — the corroborating write-up confirms the endpoint "returned a dictionary built from the complete server configuration." The information disclosure was not gated on the same admin credential it was meant to protect: a caller who can merely REACH `/server_info` gets secrets, not one who holds the admin key.

**6. NCCL weight broadcast — internal-cluster trust extended to any caller (CVE-2026-15978, CVSS 7.5).** When no API key is configured, two endpoints called in sequence trigger distributed weight broadcasting over NCCL (the GPU-to-GPU library normally used internally for multi-GPU inference) and then a data transfer — exfiltrating the entire served model's weights. The corroborating write-up's framing is the useful part: "a caller-selected peer was treated as a cluster member without an independent identity or membership check." No deserialization bug is needed here, unlike #1/#2/#3 — only the absence of the API-key gate that was meant to protect these two endpoints from callers outside the trusted cluster.

## The detection signals

Each rule targets its own trigger surface rather than a shared signature, because the six vulnerabilities are reached through different protocols:

- **LoRA adapter (proxy logsource):** a `POST` to `/load_lora_adapter_from_tensors`.
- **Dumper subsystem (process-creation logsource):** an SGLang process whose command line sets `DUMPER_SERVER_PORT` — this flags the precondition (feature enabled), not a specific exploitation payload, since none is quoted in any source checked for this note.
- **Weight loading (proxy logsource):** a `POST` to `/update_weights_from_disk` or `/update_weights_from_huggingface`.
- **Expert-backup socket (network-connection logsource):** an inbound connection to a computed port in the 30000-40000 range (a coarse placeholder — see limitation below) to an SGLang process.
- **`/server_info` (proxy logsource):** a `GET` to `/server_info` — every request is flagged, since proxy logs typically cannot inspect the response body or the deployment's configured auth mode.
- **NCCL weight broadcast (proxy logsource):** a request to the weight-broadcast-trigger endpoint (route names inferred from the mechanism description, not quoted verbatim by any source checked for this note).

## Known limitations (apply across all six)

**No confirmed patched version exists for any of the six** as of the sources checked for this note — none of the rules has a reliable "already fixed, safe to dismiss" case. Every match deserves review.

The dumper-subsystem rule specifically flags configuration state, not an attack — a deliberate, network-isolated debugging session on a loopback-only host will also match; correlate with actual network exposure of the configured port before treating a hit as a real risk.

The expert-backup rule's port range is an explicit placeholder — the CERT/CC note does not state `SGLANG_BACKUP_PORT_BASE`'s default value, so deploying this rule requires substituting your actual configured base port and excluding known cluster-node source addresses, or you will alert on your own nodes' normal expert-parallel weight synchronization traffic.

The two RCE proxy-logsource rules (LoRA adapter, weight loading) flag every request to their respective endpoints regardless of payload content, since proxy logs typically cannot inspect decoded pickle opcodes or the source repository's trust status — correlate with network-exposure scope (these endpoints should not be internet-reachable at all) and, for weight loading, an allowlist of approved HuggingFace repositories.

**`/server_info`** cannot distinguish the specific vulnerable configuration (admin-api-key-only) from any other auth setup by request pattern alone — every request is flagged. **NCCL weight broadcast** cannot distinguish legitimate internal multi-node weight synchronization from an external attacker by endpoint name alone — correlate the caller's source address against known internal cluster nodes, and note the endpoint path names in this rule are inferred from the mechanism description rather than quoted verbatim from any source, since no source checked for this note states the exact route strings.

## What to do right now

CERT/CC's note states the SGLang maintainers did not respond during the coordination window for the expert-backup issue, and no fix is confirmed for any of the six. The available mitigations are operational, not "upgrade":

1. **Disable pickle-based IPC where you can.** CERT/CC's note names a specific knob for the expert-backup path: set `SGLANG_USE_PICKLE_IPC` to `false` in `environ.py`. The maintainers are reportedly working toward a `msgpack`-based refactor, but pickle IPC remains enabled by default today.
2. **Do not set `DUMPER_SERVER_PORT` in production.** The dumper subsystem is opt-in; the simplest mitigation for that one path is to leave it disabled outside active debugging.
3. **Always configure an API key**, even on deployments believed to be internal-only — this closes both #5 (`/server_info`) and #6 (NCCL weight exfil) directly, and neither depends on any code fix shipping.
4. **Network-isolate every SGLang deployment.** None of these six endpoints/sockets should be reachable from outside a trusted cluster network — restrict access at the network layer (firewall rules, security groups) rather than relying on any authentication these code paths currently lack.
5. **Curate the HuggingFace repositories SGLang is allowed to fetch weights from**, and reject `.bin` files from anything outside that allowlist for the `update_weights_from_disk`/`update_weights_from_huggingface` paths.
6. Deploy the six detection rules above against the appropriate log source for each (proxy, process-creation, network-connection) — and revisit this note once a patched SGLang version exists, since several of the "no negative case" limitations above will change.

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of a coordinated, currently unpatched multi-CVE disclosure series. References: [SGLang GHSA-2wvm-gjg7-5jfm](https://github.com/sgl-project/sglang/security/advisories/GHSA-2wvm-gjg7-5jfm), [GHSA-h6rf-77vv-9mvj](https://github.com/sgl-project/sglang/security/advisories/GHSA-h6rf-77vv-9mvj), [GHSA-wf98-gv64-5wrf](https://github.com/sgl-project/sglang/security/advisories/GHSA-wf98-gv64-5wrf), [GHSA-jx7q-p32r-7wx8](https://github.com/sgl-project/sglang/security/advisories/GHSA-jx7q-p32r-7wx8), [GHSA-cpqq-22v3-2wfm](https://github.com/sgl-project/sglang/security/advisories/GHSA-cpqq-22v3-2wfm) (all five returned 404 on the GitHub advisories API at time of writing -- corroborated via the independent write-up below instead), [independent disclosure write-up](https://thoughts.apoorvdayal.com/posts/sglang-disclosures/), [CERT/CC VU#326070](https://www.kb.cert.org/vuls/id/326070) (CVE-2026-14890).*
