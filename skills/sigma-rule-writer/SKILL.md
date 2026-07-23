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
- best-practices linter warnings (e.g. missing `falsepositives:` block,
  overly broad selection, `condition` ambiguity)
- published-corpus deviations (e.g. logsource format drift vs canonical 50+ rule
  reference set)

If validation fails, offer to revise. Do not silently accept warnings.

### Step 4 -- Offer conversion (opt-in)

Ask whether the user wants the rule converted to their SIEM query language:

- Splunk SPL (`mcp__plugin_wrg-sigma-rules_wrg-sigma-rules__convert_rule` backend=splunk)
- Elastic ESQL / KQL (backend=elastic / kibana)
- Wazuh XML (backend=wazuh)

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
- **Falsepositives populated** -- at least one realistic FP scenario; "Unknown"
  is acceptable but flag for review
- **LLM-safe redaction** -- never leak operator-internal infra: no internal
  hostnames, no internal IP ranges, no employee identifiers; placeholders
  like `<internal-domain>` if the user pastes context that includes them

## Anti-patterns (do not do)

- Drafting without validating (skip Step 3)
- Inventing TTP IDs (always cite a real `Txxxx` or omit the tag)
- Wrapping in code comments instead of producing a parseable YAML document
- Adding closure cues ("Hope this helps!", "Let me know if...") -- operator
  drives next step
