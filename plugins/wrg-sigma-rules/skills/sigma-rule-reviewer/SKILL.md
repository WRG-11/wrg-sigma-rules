---
name: sigma-rule-reviewer
description: Review an existing Sigma rule for parseability, detection quality, false positives, and backend conversion constraints.
---

# Sigma Rule Reviewer

Read the supplied YAML or requested file, then call the `wrg-sigma-rules`
MCP server's `validate_rule`. Report parse errors separately from quality
warnings. Explain what the detection actually selects, its required telemetry,
and one realistic benign trigger. Do not silently rewrite the rule; show a
small diff and revalidate only if the user requests changes.

Treat `falsepositives` placeholders and leftover `REPLACE_ME` markers as
actionable findings. A correlation rule failing for a Lucene-family backend
is a backend capability limitation, not proof that the Sigma rule is invalid.
