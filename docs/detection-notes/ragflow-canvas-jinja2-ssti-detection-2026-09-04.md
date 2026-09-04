<!--
Companion detection note for the RAGFlow Canvas Jinja2 SSTI Sigma rule.
Accuracy source: resources/examples/execution/observed_ragflow_canvas_jinja2_ssti_t1059.yml
Advisory source: https://github.com/infiniflow/ragflow/security/advisories/GHSA-wpg4-h5g2-jxm6 (fetched
via `gh api repos/infiniflow/ragflow/security-advisories/GHSA-wpg4-h5g2-jxm6`; CVSS 9.9 and "no patched
version" confirmed live -- the advisory's own vulnerabilities[].patched_versions field is empty).
Detection/defense only, no exploit/PoC reproduced beyond what the vendor advisory already published.
-->

# Detecting the RAGFlow Canvas Jinja2 SSTI RCE (CVE-2026-45312, CVSS 9.9, UNPATCHED)

RAGFlow's citation-prompt generator renders a user-controlled field through an unsandboxed Jinja2 environment. Any authenticated user — including a brand-new, self-registered account on a default installation — can reach full remote code execution through it, and no fix exists as of this writing.

## What the flaw actually does

`rag/prompts/generator.py:185` builds `PROMPT_JINJA_ENV = jinja2.Environment(autoescape=False, ...)` with no sandboxing. `citation_prompt()` (line 189) renders a `user_defined_prompts` value populated from an LLM component's `sys_prompt` `<CITATION_GUIDELINES>` field through that environment. The path to trigger it: create a Canvas workflow chaining a DuckDuckGo search component (no API key required) into an LLM component with `cite=true` (the default), save it via `POST /v1/canvas/set`, then execute it via `POST /v1/canvas/completion`. RAGFlow's own self-registration is open by default, so this whole chain is available to anyone who can sign up.

The advisory's own PoC payload, placed inside `<CITATION_GUIDELINES>` tags in the `sys_prompt` field, walks Jinja2's object graph to escape the template sandbox entirely:

```
{% set g = cycler.__init__.__globals__ %}{% set bl = g.__builtins__ %}
{% set os = bl.__import__('os') %}{{ os.popen('id > /tmp/pwned').read() }}
```

## The detection signal

The corpus rule (`execution/observed_ragflow_canvas_jinja2_ssti_t1059.yml`) requires two things together: a request to `/v1/canvas/set` or `/v1/canvas/completion`, and a body containing one of Jinja2/Python's sandbox-escape idioms — `__globals__`, `__builtins__`, `__import__`, `__subclasses__`, `__mro__`. These dunder-attribute names are what any working Jinja2 SSTI payload needs to reach `os.popen` or equivalent, independent of the exact payload wording; they have no legitimate reason to appear inside a citation-guidelines prompt field.

## Known limitation

This is one of the rarer cases in this corpus where there is **no patched-deployment negative case to lean on** — the advisory states "Patched versions: None" as of authoring. Every match on any RAGFlow version currently deserves manual review; do not assume a specific version range is safe. Separately, this rule needs a log source that captures POST body content, since the payload lives in the request body, not the URL — and a security researcher's own authorized testing against a lab instance is indistinguishable from real exploitation by log content alone.

## What to do right now

Because there is no fix to apply yet, the mitigations are operational:

1. **Disable self-registration**, or restrict Canvas creation to trusted, vetted users — the entire attack chain starts with "any registered user can build a workflow."
2. If you cannot restrict registration, **audit or disable the LLM component's `cite=true` default** on Canvas workflows accessible to untrusted users, since the citation-prompt path is the specific trigger.
3. Deploy the detection rule above against any log source that captures RAGFlow's Canvas API request bodies.
4. Watch for infiniflow's fix and upgrade as soon as one ships — this note should be revisited once a patched version exists, since the "no negative case" limitation above will change.

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of a vendor-disclosed, currently unpatched vulnerability. Reference: [infiniflow/ragflow Security Advisory GHSA-wpg4-h5g2-jxm6](https://github.com/infiniflow/ragflow/security/advisories/GHSA-wpg4-h5g2-jxm6).*
