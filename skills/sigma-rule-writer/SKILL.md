---
name: sigma-rule-writer
description: Guided sigma detection rule writing from a natural language threat description. Use when the user asks to write a sigma rule, SIEM detection rule, EDR alert logic, or any "detect when X happens" question. Asks clarifying questions (logsource, MITRE ATT&CK TTP, severity), drafts YAML via mcp__plugin_wrg-sigma-rules_wrg-sigma-rules__draft_rule, validates via mcp__plugin_wrg-sigma-rules_wrg-sigma-rules__validate_rule, and offers backend conversion.
user-invocable: true
allowed-tools:
  - Read
  - Write
  - Bash(ls *)
  - mcp__plugin_wrg-sigma-rules_wrg-sigma-rules__draft_rule
  - mcp__plugin_wrg-sigma-rules_wrg-sigma-rules__validate_rule
  - mcp__plugin_wrg-sigma-rules_wrg-sigma-rules__convert_rule
---

# Sigma Rule Writer

Guides a SOC analyst, threat-intel responder, or bug-bounty hunter through
writing a production-grade sigma detection rule from a plain-English threat
description.

Trigger when the user says any of:

- "write a sigma rule for X"
- "I need a detection for X"
- "how do I detect X in my SIEM"
- "draft an EDR alert for X"
- "convert this CVE / blog post into a rule"

## Workflow

### Step 1 -- Clarify intent (only ask what is missing)

Collect these inputs before drafting. Ask in plain language; do not dump a
form on the user.

- **Threat behavior** -- what action triggers? (process exec, file write,
  registry mutation, network conn, auth event, cloud API call)
- **Logsource** -- what telemetry sees this? (Windows event log + channel,
  Sysmon EventID, EDR provider, Linux auditd, cloud audit log, network IDS)
- **Platform** -- Windows / Linux / macOS / network / cloud (AWS / Azure /
  GCP / SaaS)
- **MITRE ATT&CK TTP** -- technique ID if known (e.g. T1059.001 PowerShell);
  ask only if the user has not already cited one
- **Severity** -- low / medium / high / critical (default: medium if absent)
- **References** -- CVE ID, blog post URL, incident report, prior rule (if
  any). Used in the rule's `references:` block.

Skip questions the user already answered. Inferring from context is fine;
asking the same thing twice is not.

### Step 2 -- Draft via `mcp__plugin_wrg-sigma-rules_wrg-sigma-rules__draft_rule`

Pass the collected inputs as a structured payload. The tool returns a YAML
scaffold conforming to the sigma spec (https://github.com/SigmaHQ/sigma-specification).

Show the YAML to the user. Highlight the `detection:` block specifically and
explain the selection / filter / condition logic in 1-2 sentences.

### Step 3 -- Validate via `mcp__plugin_wrg-sigma-rules_wrg-sigma-rules__validate_rule`

Run validation immediately on the drafted YAML. Surface ALL warnings to the
user, not just errors:

- pySigma parser errors (hard fail)
- best-practices linter warnings, including:
  - `falsepositives_empty` / `falsepositives_placeholder` -- the block is
    missing, or filled only with placeholder text. The drafter deliberately
    emits a `TODO --` placeholder here; replacing it is Step 3 work, not
    something to defer
  - `draft_scaffold_left_in` -- a `REPLACE_ME` value survived from the
    scaffold, so the rule matches the literal placeholder string
  - `condition_default` -- the bare `condition: selection` the scaffold
    produced, which usually means no filter has been thought through yet
  - `references_empty`, `mitre_tag_missing`, `deprecated_pipe_condition`

If validation fails, offer to revise. Do not silently accept warnings.

For a base-rule + correlation-rule pair, the linter judges the correlation
document (the one that alerts), so put `falsepositives:` and `references:`
there rather than on the informational base rule.

### Step 4 -- Offer conversion (opt-in)

Ask whether the user wants the rule converted to their SIEM query language.
Pass the target as `target=`:

- `splunk` -- Splunk SPL
- `elastic` / `elasticsearch` / `kibana` -- Lucene query syntax
- `opensearch` -- OpenSearch Lucene; `opensearch-ppl` -- Piped Processing
  Language (a different language, not an alias)
- `wazuh` -- routed through the Lucene backend, with a caveat in `warnings`

**Apply a processing pipeline for windows/sysmon rules.** Sigma logsource is
abstract taxonomy; without a pipeline the emitted query keeps the field names
but drops the event selection, so a `process_creation` rule matches events of
every type that carries those fields. Pass
`config={"pipeline": "sysmon"}` (also accepts `windows`, `windows-audit`, or
a list). The difference is visible: only the piped Splunk query carries
`EventID=1`.

**Correlation rules do not convert on every target.** The Lucene-family
backends (elastic, kibana, wazuh, opensearch) cannot express them and return
`kind: backend_capability_gap`. That is a backend limit, not a defect in the
rule -- do not "fix" the rule in response. Use `splunk` or `opensearch-ppl`,
which the envelope's `hint` names.

Show converted output side-by-side with source sigma YAML.

### Step 5 -- Save the rule (opt-in)

If the user wants the rule saved, ask for a target path. Default suggestion:

```
detections/sigma/<platform>/<ttp-id>_<short-slug>.yml
```

Use `Write` tool with the validated YAML content.

## Output discipline

- **Sigma spec compliant** YAML -- pySigma parses without error
- **MITRE ATT&CK tagging mandatory** -- `tags:` block with at least one
  `attack.txxxx` entry; multi-TTP rules tag each
- **References included** -- CVE / blog / incident URL in `references:` block;
  empty `references:` is a smell
- **Falsepositives populated with a real scenario** -- name the benign thing
  that produces this same telemetry (which backup agent, which deployment
  tool, which admin workflow). "Unknown", "N/A" and the drafter's `TODO --`
  placeholder are NOT acceptable: they read as a completed field, so the rule
  ships looking finished while giving the analyst triaging the alert nothing
  to tune on. `validate_rule` reports these as `falsepositives_placeholder`.
  If the rule genuinely has a narrow false-positive surface, one honest entry
  beats three invented ones
- **LLM-safe redaction** -- never leak operator-internal infra: no internal
  hostnames, no internal IP ranges, no employee identifiers; placeholders
  like `<internal-domain>` if the user pastes context that includes them

## Anti-patterns (do not do)

- Drafting without validating (skip Step 3)
- Inventing TTP IDs (always cite a real `Txxxx` or omit the tag)
- Wrapping in code comments instead of producing a parseable YAML document
- Adding closure cues ("Hope this helps!", "Let me know if...") -- operator
  drives next step
