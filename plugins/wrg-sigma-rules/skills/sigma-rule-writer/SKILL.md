---
name: sigma-rule-writer
description: Draft a Sigma detection rule from a threat description, then validate it before suggesting any backend conversion.
---

# Sigma Rule Writer

Use the `wrg-sigma-rules` MCP server's `draft_rule` tool for a scaffold and
immediately call `validate_rule` on the emitted YAML. Ask only for missing
behaviour, telemetry/logsource, target platform, MITRE technique, severity,
or source reference.

Do not present a scaffold as deployable. Surface every validator warning,
especially placeholder false-positive text, `REPLACE_ME` markers, missing
references, and missing ATT&CK tags. If a SIEM conversion is requested, use
`convert_rule`; for Windows/Sysmon rules pass the `sysmon` pipeline. Save a
rule only when the user names a destination path.

For a WRG public-corpus contribution, a generated scaffold is not source
evidence. Do not invent or label an `observed_*` rule without the cited
incident, attribution, platform, and telemetry-manifestation evidence required
by `CONTRIBUTING.md`; otherwise keep it a user-local draft or an explicitly
generic template candidate.
