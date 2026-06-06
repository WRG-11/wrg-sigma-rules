---
name: threat-coverage-gap-analyzer
description: Analyze a sigma rule corpus against the MITRE ATT&CK matrix and produce a coverage gap report. Use when the user asks "what TTPs am I missing", asks for a coverage report, wants to compare their detections against a threat actor profile (e.g. APT29, Scattered Spider), or wants a prioritized list of detection rules to write next. Reads a directory of sigma rules, cross-references against the ATT&CK matrix resource, and outputs gap analysis with priority ranking.
user-invocable: true
allowed-tools:
  - Read
  - Bash(ls *)
  - Bash(find *)
  - mcp__wrg-sigma__validate_rule
---

# Threat Coverage Gap Analyzer

Maps an existing sigma rule corpus to the MITRE ATT&CK matrix and surfaces
coverage gaps with priority ranking. Sister skill to `sigma-rule-writer`
(which drafts new rules) and `sigma-rule-reviewer` (which reviews existing
rules); this skill answers the strategic question "what should I detect
next".

Trigger when the user says any of:

- "what coverage do I have"
- "what TTPs am I missing"
- "show me my detection gaps"
- "how well do I detect APT29 / Scattered Spider / FIN7 / <actor>"
- "what should I write a rule for next"
- "MITRE coverage report"

## Workflow

### Step 1 -- Discover the rule corpus

Ask the user where their sigma rules live. Accept:

- A directory path (recursively enumerate `*.yml` and `*.yaml` via
  `Bash(find *)`)
- A list of file paths
- "Use the WRG canonical corpus" (default to the plugin's
  `resources/examples/` directory)

For each discovered rule, use `Read` to load the YAML and `mcp__wrg-sigma__validate_rule`
to extract the `tags:` block (specifically `attack.txxxx` entries).

### Step 2 -- Build the coverage map

For each rule, extract:

- File path
- Rule title
- Logsource (product + category + service)
- ATT&CK technique IDs (from `tags:`)
- Sub-technique granularity (e.g. T1059 vs T1059.001 vs T1059.003)

Output a compact matrix: rows = ATT&CK tactics (TA0001 Initial Access ...
TA0040 Impact), columns = covered / partial / not covered, cell = count of
rules.

### Step 3 -- Identify gaps

Compare the corpus coverage against:

- **Full ATT&CK matrix** (Enterprise) -- what is theoretically detectable but
  has no rule
- **Actor-specific TTP profile** -- if the user named an actor, narrow to
  that actor's known TTPs (use ATT&CK Groups data, e.g. G0016 APT29 TTPs)
- **Threat-intel priority** -- if the user has a recent incident or breach
  brief, rank gaps by relevance to that incident

### Step 4 -- Produce the gap report

Output format (markdown):

```markdown
## Coverage Gap Report: <corpus-name> [vs <actor> if specified]

### Summary
- Rules in corpus: N
- ATT&CK techniques covered: M / ~600 enterprise techniques (X%)
- Tactics with zero coverage: <list TA0xxx tactics>
- Highest-priority gaps: <top 5>

### Coverage by tactic
| Tactic | Covered | Partial | Missing | Rule count |
|---|---|---|---|---|
| TA0001 Initial Access | 3 | 2 | 8 | 5 |
...

### Top priority gaps (recommended next rules to write)
1. **T1078.004 Cloud Accounts** -- 0 rules. Rationale: <why this matters
   for the user's environment>. Suggested logsource: <e.g. AWS CloudTrail>.
   Suggested next step: invoke `sigma-rule-writer` skill with T1078.004
   context.
2. ...
```

### Step 5 -- Hand off to rule writer (opt-in)

For each top-priority gap, offer to launch the `sigma-rule-writer` skill
with the TTP ID pre-filled. The user can accept one, several, or none.

Do not auto-launch -- operator drives.

## Output discipline

- **Quantify, do not handwave** -- "you cover 47 of 600 techniques (8%)" not
  "you have some gaps"
- **Cite ATT&CK technique IDs** -- never refer to a gap without the `Txxxx`
  identifier
- **Prioritize honestly** -- top-5 gaps should be defensible (matches actor
  in scope OR matches user's stated business priority OR matches recent
  incident); do not pad with low-relevance suggestions
- **LLM-safe redaction** -- if the user shares an internal incident brief,
  do not transmit incident-specific identifiers in the report unless the
  user explicitly opts in

## Anti-patterns (do not do)

- Claiming coverage based on rule existence without validating that the rule
  actually loads and tags ATT&CK techniques (use `mcp__wrg-sigma__validate_rule`
  to extract `tags:` cleanly)
- Recommending detection for techniques the user's environment cannot
  generate telemetry for (e.g. recommending Linux audit rules for a
  Windows-only shop)
- Padding the gap list with every uncovered technique (top 5-10 with
  rationale is more actionable than 553 with none)
- Adding closure cues ("Now you have a clear path!") -- operator drives next
  step
