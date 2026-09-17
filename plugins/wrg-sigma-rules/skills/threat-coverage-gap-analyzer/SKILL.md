---
name: threat-coverage-gap-analyzer
description: Analyze Sigma rules against MITRE ATT&CK and prioritize defensible detection coverage gaps.
---

# Threat Coverage Gap Analyzer

For WRG's own corpus, read the `wrg-sigma://coverage/mitre-attack-matrix`
MCP resource. For a user-supplied corpus, inspect only the named rules and
validate their ATT&CK tags with `validate_rule`. Report rule count, technique
coverage, and at most ten evidence-gated review candidates with a logsource
rationale. The resource establishes what the corpus contains; it does not ship
an ATT&CK universe. Do not claim missing tactics or techniques unless the user
supplies a versioned ATT&CK matrix or other cited comparison scope.

Do not claim a technique is covered solely because a file exists: the rule
must parse and carry a relevant ATT&CK tag. Do not generate a new rule unless
the user explicitly selects a candidate to address. For a WRG public-corpus
contribution, never invent an `observed_*` rule from a coverage count: require
a cited incident with attribution, platform, and telemetry-manifestation
evidence as specified by `CONTRIBUTING.md`.
