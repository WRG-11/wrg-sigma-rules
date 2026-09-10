---
name: threat-coverage-gap-analyzer
description: Analyze Sigma rules against MITRE ATT&CK and prioritize defensible detection coverage gaps.
---

# Threat Coverage Gap Analyzer

For WRG's own corpus, read the `wrg-sigma://coverage/mitre-attack-matrix`
MCP resource. For a user-supplied corpus, inspect only the named rules and
validate their ATT&CK tags with `validate_rule`. Report rule count, technique
coverage, missing tactics, and at most ten prioritized gaps with a logsource
rationale.

Do not claim a technique is covered solely because a file exists: the rule
must parse and carry a relevant ATT&CK tag. Do not generate a new rule unless
the user explicitly selects a gap to address.
