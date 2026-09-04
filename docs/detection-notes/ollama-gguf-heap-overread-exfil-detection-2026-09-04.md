<!--
Companion detection note for the Ollama GGUF quantization heap-overread exfiltration Sigma rule.
Accuracy source: resources/examples/collection/observed_ollama_gguf_heap_overread_exfil_t1005.yml
Fix source: https://github.com/ollama/ollama/pull/14406 (fetched via `gh api repos/ollama/ollama/pulls/14406`;
no GHSA/CVSS breakdown available in the sources checked, CVSS 8.8 per the corpus rule's own citation of NVD).
Detection/defense only, no exploit/PoC reproduced beyond what the merged fix's own summary already published.
-->

# Detecting the Ollama GGUF Heap-Overread Memory Exfiltration Chain (CVE-2026-7482, CVSS 8.8)

Ollama's model-creation endpoint trusted a GGUF file's own declared tensor metadata without checking it against the file's actual size — turning an untrusted model upload into a way to read, and then exfiltrate, other processes' memory.

## What the flaw actually does

`/api/create` accepts an attacker-supplied GGUF model file. During quantization, the server trusted the file's declared tensor offset and size fields without validating them against the file's actual length. A GGUF file whose declared offset/size exceeds the real file causes the quantization path to read past the allocated heap buffer — and the leaked memory can contain environment variables, API keys, system prompts, and OTHER CONCURRENT USERS' conversation data, not just data belonging to the uploading attacker. Because `/api/create` and `/api/push` both ship with no authentication in the upstream distribution, the exfiltration chain is: upload a malicious GGUF to `/api/create` to trigger the overread, then push the resulting model artifact — now carrying the leaked heap bytes baked into it — via `/api/push` to an attacker-controlled registry. The leaked memory leaves the server disguised as an ordinary model file. Default deployments bind to loopback, but the documented `OLLAMA_HOST=0.0.0.0` configuration (needed for any multi-user or networked deployment) is widely used in practice.

## The detection signal

The corpus rule flags the two-endpoint sequence the exfiltration chain depends on: a `/api/create` call carrying a GGUF payload, or a `/api/push` call to a registry host — either endpoint alone. A real investigation should correlate a `/api/create` GGUF upload followed shortly by a `/api/push` to an UNFAMILIAR registry from the same source, since a legitimate model-authoring workflow rarely pushes to an unfamiliar registry immediately after a fresh create call.

## Known limitation

The rule flags either endpoint independently because a single HTTP log line rarely carries enough context to confirm the two-step chain by itself. On an `OLLAMA_HOST=0.0.0.0` deployment, routine model management traffic to both endpoints is otherwise normal and expected — without the create-then-push-to-unfamiliar-registry correlation, this rule alone will be noisy on any actively-used multi-user Ollama deployment.

## What to do right now

1. **Upgrade to Ollama 0.17.1 or later**, which validates tensor sizes against GGUF shape metadata before quantization.
2. If you run `OLLAMA_HOST=0.0.0.0` (network-exposed) pre-upgrade, restrict which registries `/api/push` can target, or require authentication in front of both `/api/create` and `/api/push` at the network layer — neither endpoint authenticates natively in the affected versions.
3. Deploy the detection rule above with the create-then-push-to-unfamiliar-registry correlation described above, rather than treating either endpoint's traffic as inherently suspicious.

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of a vendor-disclosed, now-patched vulnerability. Reference: [ollama/ollama PR #14406](https://github.com/ollama/ollama/pull/14406).*
