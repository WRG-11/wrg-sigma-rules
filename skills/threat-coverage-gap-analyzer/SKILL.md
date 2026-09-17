---
name: threat-coverage-gap-analyzer
description: Analyze a Sigma rule corpus and produce an evidence-bounded coverage report. Use when the user asks "what TTPs am I missing", asks for a coverage report, wants to compare detections against a supplied ATT&CK matrix or actor profile, or wants defensible candidates for further research. Reads a directory of Sigma rules (or, for this plugin's own corpus, the precomputed wrg-sigma://coverage/mitre-attack-matrix resource), then compares only against user-supplied, versioned scope data.
user-invocable: true
allowed-tools:
  - Read
  - Bash(ls *)
  - Bash(find *)
  - mcp__plugin_wrg-sigma-rules_wrg-sigma-rules__validate_rule
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
- "Use the WRG canonical corpus" (this plugin's `resources/examples/`)

For the WRG canonical corpus, read the
`wrg-sigma://coverage/mitre-attack-matrix` resource instead of walking the
directory. It already reports the technique-by-tactic rollup, per-technique
rule counts, the observed/template split, and any rule contributing no
coverage -- computed from the corpus at read time, so it cannot be stale.
Steps 1 and 2 are then already done and you start at Step 3.

For any other corpus, use `Read` on each discovered rule and
`mcp__plugin_wrg-sigma-rules_wrg-sigma-rules__validate_rule` to extract the
`tags:` block (specifically `attack.txxxx` entries).

Note what that resource is and is not: it is the "what we have" half only.
The ATT&CK Enterprise matrix is deliberately not vendored in this repo (a
copied-in matrix goes stale against ATT&CK releases with nothing here able
to notice), so the "what is missing" half is yours to bring in Step 3.

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

Only compare the corpus coverage against evidence the user supplies for this
run, recording its version, scope, and source:

- **Versioned ATT&CK matrix** (for example, a specified Enterprise release) --
  candidate techniques outside the corpus, not a claim that they are
  operationally detectable
- **Actor-specific TTP profile** -- if the user supplies a cited actor profile,
  narrow to its documented TTPs
- **Threat-intel priority** -- if the user has a recent incident or breach
  brief, rank gaps by relevance to that incident

If no versioned comparison data is supplied, report only what the corpus
contains. Do not claim missing tactics or techniques, use an approximate total
such as "~600", or infer an actor's TTPs from its name.

### Step 4 -- Produce the gap report

Output format (markdown):

```markdown
## Coverage Gap Report: <corpus-name> [vs <actor> if specified]

### Summary
- Rules in corpus: N
- ATT&CK techniques covered in corpus: M
- Comparison scope: <source, version, and scope — or "not supplied">
- Candidate gaps within supplied scope: <top 5, or "not assessed">

### Coverage by tactic
| Tactic | Covered | Partial | Candidate missing (supplied scope only) | Rule count |
|---|---|---|---|---|
| TA0001 Initial Access | 3 | 2 | 8 | 5 |
...

When comparison scope is not supplied, write `not assessed` in the candidate
column rather than deriving an ATT&CK total or an absence claim.

### Priority research candidates (not rules)
1. **T1078.004 Cloud Accounts** -- absent from this corpus and present in
   <supplied scope>. Rationale: <why this matters for the user's environment>.
   Next step: establish a source, platform, and telemetry manifestation before
   considering a rule.
2. ...
```

### Step 5 -- Hand off to rule writer (opt-in)

For each evidence-backed research candidate, offer to launch the
`sigma-rule-writer` skill with the TTP ID pre-filled. A generated scaffold is
not source evidence. For a public `observed_*` contribution, require the
attribution, platform, and telemetry-manifestation proof in
`CONTRIBUTING.md`; otherwise keep it a user-local or generic template
candidate. The user can accept one, several, or none.

Do not auto-launch -- operator drives.

## Output discipline

- **Quantify only against named scope** -- report corpus counts directly; add a
  denominator or percentage only when its versioned comparison scope is named
- **Cite ATT&CK technique IDs** -- never refer to a gap without the `Txxxx`
  identifier
- **Prioritize honestly** -- candidates should be defensible (matches supplied
  actor evidence OR matches user's stated business priority OR matches recent
  incident); do not pad with low-relevance suggestions
- **LLM-safe redaction** -- if the user shares an internal incident brief,
  do not transmit incident-specific identifiers in the report unless the
  user explicitly opts in

## Anti-patterns (do not do)

- Claiming coverage based on rule existence without validating that the rule
  actually loads and tags ATT&CK techniques (use `mcp__plugin_wrg-sigma-rules_wrg-sigma-rules__validate_rule`
  to extract `tags:` cleanly)
- Calling an unversioned external ATT&CK total, a named actor, or a generic
  technique description evidence of a missing coverage requirement
- Recommending detection for techniques the user's environment cannot
  generate telemetry for (e.g. recommending Linux audit rules for a
  Windows-only shop)
- Padding the gap list with every uncovered technique (top 5-10 with
  rationale is more actionable than 553 with none)
- Adding closure cues ("Now you have a clear path!") -- operator drives next
  step

## Live example

See [`DEMO.md`](../../DEMO.md) (Demo 6) for the real
`wrg-sigma://coverage/mitre-attack-matrix` resource output this skill reads
when analyzing this plugin's own corpus.
