<!--
Companion detection note for the Flowise CSVAgent Pyodide-bridge RCE Sigma rule.
Accuracy source: resources/examples/execution/observed_flowise_csvagent_datauri_pyodide_bridge_rce_t1059.yml
Advisory source: https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-4j8x-x6v7-w9rq (fetched and
quoted directly via `gh api repos/FlowiseAI/Flowise/security-advisories/GHSA-4j8x-x6v7-w9rq`).
Known limitation (application-log dependency) is documented in the "Known limitation" section.
Detection/defense only, no exploit/PoC reproduced beyond what the vendor advisory already published.
-->

# Detecting the Flowise CSVAgent Sandbox-Escape RCE (CVE-2026-69264, CVSS 9.9)

Flowise's `CSVAgent` node interpolates an attacker-controlled fragment of a data URI directly into a Python source template, and that template runs inside Pyodide with the default `js` bridge enabled. The bridge is the whole problem: an attacker who can escape the Python string literal gets a `js.eval` call that reaches Node's `globalThis`, and from there dynamic `import('child_process')` is one line away from a shell on the Flowise host. The vendor's own advisory rates it CVSS 9.9 Critical, and at time of writing it is unpatched.

## What the flaw actually does

`CSVAgent.run()` takes the `csvFile` field's data URI, splits it on `,`, and pops the third segment straight into a Python bootstrap string:

```ts
base64_string = "${base64String}"
```

Neither of the two validators that guard this code path (`validatePythonCodeForDataFrame`, `validateCustomReadCSVFunction`) is ever applied to that bootstrap template — they check other things. So a segment shaped like `";\nimport js\nawait js.eval("...")\n#` closes the string literal early, imports the bridge module, and calls into Node's `fs` or `child_process` modules through Pyodide's WASM boundary. The vendor's advisory includes a full working PoC (verified end-to-end against `flowise@3.1.2` on Node 20.20.2) that writes a proof file to the host filesystem this way.

The part that makes this reachable by anyone, not just an insider: the trigger route `POST /api/v1/prediction/:id` is whitelisted from authentication whenever the chatflow has no `apikeyid` set — which is the default for a newly created chatflow. So the attack is two steps: one authenticated user plants the malicious `csvFile` once (any account with `chatflows:create`, which in most OSS deployments is every registered user), and every subsequent prediction request against that chatflow — from anyone, unauthenticated — re-triggers the RCE.

## The detection signal

The corpus rule (`execution/observed_flowise_csvagent_datauri_pyodide_bridge_rce_t1059.yml`) looks for the exact string shape the exploit needs to survive Flowise's own Python string interpolation: a chatflow-prediction log message containing `csvFile`, together with both `";` (the string-literal terminator) and `import js` (the bridge import). All three conditions must be true in the same message.

That specificity is deliberate. `";` alone is common in ordinary text; `import js` alone could appear in unrelated Python snippets a user pastes. The pairing — a string terminator immediately followed by the exact bridge-import statement the exploit needs — is what the rule's own `falsepositives:` block calls out as narrow "well outside any valid base64 payload." A legitimate CSV upload's base64 content has no reason to contain either token, let alone both in sequence.

## Known limitation: this needs a log source most environments do not have

This is the rule's most important caveat, and it is not hidden: **it requires application-level logging of chatflow prediction request bodies** (a `Message` field carrying the request payload). Most infrastructure logging — access logs, reverse-proxy logs, standard Node/Express logs — captures the route and status code, not the JSON body of a `POST /api/v1/prediction/:id` call. Without body-level logging at the Flowise application layer (or a WAF/API-gateway configured to log request bodies for this specific route), this rule has nothing to match against and will not fire, silently.

If you run Flowise and want this detection live, the actionable step is upstream of the Sigma rule: turn on application-level request-body logging for the prediction endpoint before you rely on this signal to catch an exploit attempt.

## What to do right now

The vendor advisory is unpatched as of this writing, so the working mitigations are:

1. **Set `apikeyid` on every chatflow that uses a `CSVAgent` node.** This is the single highest-leverage step — it forces `validateFlowAPIKey` to require auth on `/api/v1/prediction/:id`, which closes the unauthenticated re-trigger path even though the underlying template-injection bug remains.
2. **Restrict `chatflows:create` / `agentflows:create` permissions** to trusted users — the plant step needs one of these.
3. **Strip `csvFile` from any `nodeOverrides` allow-list** on affected chatflows so the malicious value cannot be supplied at prediction time.
4. **Turn on application-level request-body logging** for the prediction endpoint if you want the Sigma rule above to have anything to match (see "Known limitation").
5. Watch for the vendor's fix — the advisory recommends replacing the string-interpolation bootstrap with Pyodide's `globals.set()` API, which keeps the value out of the Python source text entirely.

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of a vendor-disclosed, unpatched vulnerability. Reference: [FlowiseAI/Flowise Security Advisory GHSA-4j8x-x6v7-w9rq](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-4j8x-x6v7-w9rq).*
