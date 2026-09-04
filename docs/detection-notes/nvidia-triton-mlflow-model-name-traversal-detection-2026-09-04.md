<!--
Companion detection note for the NVIDIA Triton MLflow plugin model-name traversal Sigma rule.
Accuracy source: resources/examples/collection/observed_nvidia_triton_mlflow_model_name_traversal_t1005.yml
Source: NVIDIA's own security bulletin, fetched directly via
`gh api repos/NVIDIA/product-security/contents/2026/5860/5860.md`.
Minor correction: the corpus rule's falsepositives note states "NVIDIA's advisory does not specify the
exact fixed version" -- the bulletin does specify it (Triton Server r26.03), quoted below.
Detection/defense only, no exploit/PoC reproduced beyond what the vendor bulletin already published.
-->

# Detecting the NVIDIA Triton MLflow Plugin Path Traversal (CVE-2026-47487, CVSS 4.4)

NVIDIA Triton Inference Server's MLflow plugin let a caller-supplied model name reach outside the model repository — a straightforward path-traversal bug in a plugin that manages model artifacts.

## What the flaw actually does

The Triton MLflow plugin accepts a caller-supplied model name that's used to build a filesystem path under the configured model repository, with no confinement check on the result. NVIDIA's own bulletin: "a user could cause files outside the model repository to be read, written to, or modified by providing a path in the model name to the Triton MLflow plugin," leading to denial of service and information disclosure. This is a standard CWE-22 (path traversal) shape, reached specifically through the MLflow plugin's model-management interface — not the core inference API.

## The detection signal

The corpus rule flags an MLflow-plugin model endpoint request whose model-name parameter contains a `../` (or URL-encoded equivalent) traversal sequence — the specific artifact that turns an ordinary model-name string into a filesystem escape.

## Known limitation

A legitimate model name containing a literal `..` sequence for an unrelated reason is uncommon given typical model-naming conventions, but not impossible — narrow in practice. On a deployment already upgraded past the fix, a matching request would be rejected rather than reaching the filesystem.

## What to do right now

1. **Upgrade to Triton Server r26.03 or later.** NVIDIA's bulletin states this explicitly (affected: 0.0–26.02, fixed: 26.03) — the corpus rule's own note that the fixed version isn't specified is a minor inaccuracy; it is.
2. If you cannot upgrade immediately, restrict which callers can reach the MLflow plugin's model-management interface — this is a separate surface from the core inference API and can often be access-controlled independently.
3. Deploy the detection rule above against proxy/access logs in front of the Triton MLflow plugin.

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of a vendor-disclosed, now-patched vulnerability. Reference: [NVIDIA Security Bulletin 5860](https://github.com/NVIDIA/product-security/tree/main/2026/5860).*
