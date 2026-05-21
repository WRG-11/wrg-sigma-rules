---
name: sigma-rule-reviewer
description: Review an existing sigma rule for spec compliance, detection quality, and improvement opportunities. Use when the user pastes a sigma YAML rule, asks "is this rule any good", asks for a code review on a detection, or wants to harden a rule against false positives. Runs pySigma validation, best-practices linter, and produces a structured findings report with concrete fix suggestions.
user-invocable: true
allowed-tools:
  - Read
  - Bash(ls *)
  - mcp__wrg-sigma__validate_rule
  - mcp__wrg-sigma__convert_rule
---

# Sigma Rule Reviewer

Reviews a sigma rule the user already has, produces a structured findings
report, and offers concrete revisions. Sister skill to `sigma-rule-writer`
(which drafts new rules from scratch).

Trigger when the user does any of:

- Pastes a YAML sigma rule and asks for feedback
- Says "review this detection"
- Says "audit this sigma rule"
- Asks "why is this rule noisy" or "how do I cut false positives"
- Asks to convert an existing rule to another backend (delegate to
  `sigma-rule-writer` Step 4 if user only wants conversion)

## Workflow

### Step 1 -- Accept input

Accept the rule via any of:

- Pasted YAML in the conversation
- File path (use `Read` tool to load)
- Directory path (use `Bash(ls *)` to enumerate + ask which rule)

Echo the rule back to the user verbatim before review. This confirms what
will be reviewed and surfaces any paste-mangling issues (e.g. tab vs space
indentation drift).

### Step 2 -- Validate via `mcp__wrg-sigma__validate_rule`

Run validation and capture the full output. Categorize findings into three
buckets:

- **Errors (hard fail)** -- rule will not parse or load in pySigma
- **Warnings** -- best-practices linter findings; rule loads but has quality
  issues
- **Notes** -- informational observations (e.g. "consider adding falsepositives
  entry")

### Step 3 -- Produce structured findings report

Output format (markdown):

```markdown
## Sigma Rule Review: <rule-title>

### Summary
- Status: [PASS / WARN / FAIL]
- Errors: N
- Warnings: M
- Notes: K

### Errors (must fix to ship)
1. [Line X] <description> -- Fix: <concrete suggestion>
...

### Warnings (recommended to fix)
1. [Line X] <description> -- Fix: <concrete suggestion>
...

### Notes
- <observation 1>
...

### Detection logic walkthrough
<1-3 sentence plain-English explanation of what this rule actually detects,
what telemetry it relies on, and one realistic false positive scenario>

### Improvement opportunities
1. <concrete improvement with before/after YAML snippet if useful>
...
```

Do not skip the **Detection logic walkthrough** -- many sigma rules are
shipped without anyone being able to articulate what they detect in plain
language. This is the highest-value section of the review.

### Step 4 -- Offer revisions (opt-in)

If errors or actionable warnings exist, offer to produce a revised version:

- Show side-by-side diff (or unified diff for long rules)
- Annotate each change with the warning it addresses
- Re-run `mcp__wrg-sigma__validate_rule` on the revised version to confirm
  the issue is closed

### Step 5 -- Optional backend conversion

If the user asks for SIEM-specific output, use `mcp__wrg-sigma__convert_rule`
to convert to Splunk / Elastic / Wazuh. Mention any conversion-specific
caveats (e.g. "Wazuh does not support `re|contains` modifiers; this clause
was rewritten to `like`").

## Output discipline

- **Honest severity** -- do not soften "FAIL" to "WARN" to make the user feel
  better; rule quality is a security control
- **Cite line numbers** -- every finding references a specific line in the
  source rule
- **Concrete fixes** -- never say "consider improving X" without showing
  what "improved X" looks like
- **Pattern 34 LLM-safe** -- if the rule contains internal-looking identifiers
  (hostnames, user names, internal CIDRs), flag as a Note (potential leakage)
  but do not transmit them outside the review output

## Anti-patterns (do not do)

- Rewriting the entire rule without showing the original (loss of operator
  decision authority)
- Marking a rule PASS when warnings exist (warnings matter)
- Ignoring `falsepositives:` block emptiness (top-3 cause of SOC alert
  fatigue per WRG corpus observation)
- Adding closure cues ("Hope this is helpful!") -- operator drives next step
