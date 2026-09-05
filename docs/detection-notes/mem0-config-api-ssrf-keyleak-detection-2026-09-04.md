<!--
Companion detection note for the mem0 config-API SSRF + plaintext key-leak Sigma rule.
Accuracy source: resources/examples/credential_access/observed_mem0_unauth_config_apikey_ssrf_t1552.yml
Advisory sources: VulnCheck write-up + https://github.com/mem0ai/mem0/issues/6081 (fetched directly via
`gh api repos/mem0ai/mem0/issues/6081`, timeline, and comments, 2026-09-04).
RESOLVED provenance caveat (2026-09-04, was previously "could not be confirmed"): the corpus rule's
description originally cited a specific commit hash as "the fix" -- live verification shows that
commit's own message is "fix(docs): fix broken metadata filtering examples (#5317)," an unrelated
documentation change. The actual status, confirmed via the issue's own comment thread: the maintainers
closed #6081 with "we have sunsetted openmemory, so we won't be taking issue or pr" -- WONTFIX-by-
deprecation, not a patch. The corpus rule's description and falsepositives were corrected accordingly.
Detection/defense only, no exploit/PoC reproduced beyond what the vendor advisory already published.
-->

# Detecting the mem0 Config-API SSRF and Plaintext Key Leak (CVE-2026-59706, CVSS 9.2)

mem0's OpenMemory configuration API ships two unauthenticated endpoints that, together, let a network caller both steal LLM provider credentials and pivot into internal infrastructure.

## What the flaw actually does

`GET /api/v1/config/` returns the stored LLM provider configuration — including API keys — in plaintext, to anyone who can reach the endpoint. The issue report's own PoC: set an API key via the config endpoint, then read it straight back with a bare `GET`, no credential required.

Separately, `PUT /api/v1/config/mem0/llm` accepts a caller-supplied `ollama_base_url` with no scheme allowlist and no IP-range validation. The reporter's validated PoC points it at `http://169.254.169.254/latest/meta-data/` — the cloud instance-metadata address — and the server issues the outbound request on the next memory operation, no attacker-controlled response needed, just a live SSRF primitive that can reach the metadata service, internal-only APIs, or anything else on the host's network.

## The detection signal

The corpus rule (`credential_access/observed_mem0_unauth_config_apikey_ssrf_t1552.yml`) covers both halves as independent selections: a `GET /api/v1/config/` with no `Authorization` header (the key-disclosure path), or a `PUT /api/v1/config/mem0/llm` whose body sets `ollama_base_url` to a private/link-local/metadata address range (the SSRF path). Either alone is exploitable and worth investigating — the rule does not require both together.

## The fix status is now resolved: WONTFIX-by-deprecation, not patched

The corpus rule's description and VulnCheck's advisory both originally referred to commit `a3154d59e5...` as a fix. The primary source — the reporter's own GitHub issue — describes that same short hash (`a3154d5`) differently: "Affected component: openmemory/api, commit a3154d5 (**current HEAD as of 2026-06-01**)." That is a description of the vulnerable state at report time, not a statement that the commit fixes anything — and live verification (2026-09-04) confirms that exact commit's actual message is "fix(docs): fix broken metadata filtering examples (#5317)," entirely unrelated to this vulnerability. Pulling the issue's own comment thread resolves what could not be confirmed at authoring time: the maintainers closed #6081 (2026-07-06) with **"we have sunsetted openmemory, so we won't be taking issue or pr."** This is not a patched vulnerability — the affected OpenMemory component has been DISCONTINUED rather than fixed, so there is no version number to check a deployment against, and no fix will ever ship. **Treat every match as needing manual review, permanently** — there is no "already fixed, safe to ignore" case for this rule the way most CVE-sourced rules in this corpus have.

## What to do right now

1. Require authentication on every `/api/v1/config/` endpoint — this is the reporter's own recommended fix, and the vendor has explicitly declined to implement it (WONTFIX-by-deprecation). If you run OpenMemory, this is now entirely your own responsibility to patch or compensate for.
2. If you cannot patch or gate the API immediately, block network egress from the mem0/OpenMemory host to link-local and cloud-metadata address ranges (`169.254.169.254` and equivalents) as a compensating control for the SSRF path.
3. Stop storing LLM API keys in the configuration database if you can avoid it — prefer environment-variable references the config API never echoes back.
4. If you can migrate off OpenMemory entirely, that is now the vendor's own implicit recommendation — the component is sunset, not just unpatched.
5. Deploy the detection rule above against proxy/access logs in front of the OpenMemory API.

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of a publicly reported, WONTFIX-by-deprecation vulnerability. References: [VulnCheck advisory](https://www.vulncheck.com/advisories/mem0-server-side-request-forgery-and-plaintext-api-key-exposure-via-unauthenticated-config-endpoints), [mem0ai/mem0 issue #6081](https://github.com/mem0ai/mem0/issues/6081).*
