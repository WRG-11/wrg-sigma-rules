# WRG Sigma Rules — Anthropic Claude Code Plugin

> **Status**: Production-ready. Pending submission to Anthropic community marketplace (target 2026-05-25).

Production-grade sigma detection rule writing, validation, and conversion for SOC analysts, threat-intel teams, and detection engineers using Claude Code.

## TL;DR

- **3 MCP tools**: `draft_rule` (NL → sigma YAML) + `validate_rule` (pySigma + best-practice linter) + `convert_rule` (sigma → Splunk/Elastic/Wazuh/Kibana query)
- **3 Claude Code skills**: sigma-rule-writer + sigma-rule-reviewer + threat-coverage-gap-analyzer
- **56 production sigma rule corpus**: 11 ATT&CK tactic categories
- **Multi-backend conversion**: Splunk, Elastic, Wazuh, Kibana verified
- **WRG ecosystem anchor**: 6+ months threat-intel discipline + 100+ actor TTP corpus + observed_* rules (Mini Shai-Hulud, Lazarus, LockBit, LAPSUS, AI-fingerprint)

## Why this plugin exists

The sigma-rule niche in the Anthropic Claude Code plugin marketplace is **empty** (verified 2026-05-23: 200+ plugins, 0 sigma-focused, 1 generic security plugin). SOC + threat-intel community has latent demand for fast, quality-aware rule writing tools integrated with LLM workflows.

WRG (WinstonRedGuard) has accumulated 6+ months of threat-intel infrastructure: 52 canonical sigma rules + actor catalog + pySigma integration + Pattern-driven detection-engineering discipline. This plugin packages that capability for the broader Anthropic ecosystem.

## What's included

### MCP tools (3)

- `wrg__sigma__draft_rule` — NL description → sigma YAML scaffold
- `wrg__sigma__validate_rule` — YAML schema + pySigma compat + best-practice linter
- `wrg__sigma__convert_rule` — sigma → Splunk/Elastic/Wazuh/Kibana query

### Claude Code skills (3)

- `sigma-rule-writer` — guided rule writing workflow
- `sigma-rule-reviewer` — paste rule for quality review + improvement suggestions
- `threat-coverage-gap-analyzer` — MITRE ATT&CK coverage analysis vs your existing corpus

### Sigma rule corpus (52 production rules across 11 ATT&CK tactic categories)

| Tactic | Coverage |
|---|---|
| `credential_access` | templates + observed (LAPSUS T1110 correlation + Mimikatz LSASS patterns) |
| `command_and_control` | template T1071 + **observed Mini Shai-Hulud npm supply-chain C2 T1071** |
| `defense_evasion` | templates |
| `execution` | templates |
| `exfiltration` | templates |
| `impact` | templates + observed (Lazarus + LockBit BTC) |
| `initial_access` | templates + observed (spearphishing link side T1566.002) |
| `lateral_movement` | templates |
| `resource_development` | templates |
| `collection` | templates |
| `code_review` | 5 AI-fingerprint observed rules (ANSI-color class, decoy block, docstring density, hallucinated CVSS, prompt artifacts) |

See [`resources/examples/INDEX.json`](resources/examples/INDEX.json) for full enumeration.

### Resources

- `wrg-sigma://patterns/canonical-5` — canonical detection-pattern definitions
- `wrg-sigma://coverage/mitre-attack-matrix` — corpus coverage state

## Installation

### Via Anthropic Claude Code community marketplace (post-merge)

```bash
/plugin install wrg-sigma-rules
```

### Direct from this repo

```bash
git clone https://github.com/WRG-11/wrg-sigma-rules.git
# Follow Claude Code plugin install path per https://code.claude.com/docs/en/plugins
```

## Quality discipline

- **4-Layer self-audit** per WRG audit methodology (Pattern 18 v1.1 trust-but-verify sister); see [`.claude-plugin/AUDIT-SELF.md`](.claude-plugin/AUDIT-SELF.md)
- **7 Python test modules** covering rule validation + tool integration smoke
- **pySigma 0.10+ compat** + multi-backend conversion verified
- **LLM-safe output discipline**: ASCII-only output + error-path structure preserve (Pattern 34 v1.1 sister)
- **`claude plugin validate` PASS** (verified 2026-05-23 on Claude Code 2.1.149)

## Tested environments

- Windows 11 + Claude Code 2.1.149
- WSL2 Ubuntu 24.04

## Contributing

Sigma rule contributions welcome. Submit YAML to `resources/examples/<tactic>/` with:

- ATT&CK TTP mapping in `tags:` field (e.g., `attack.t1071`)
- `observed_*` prefix for incident-specific rules
- `template_*` prefix for canonical pattern templates
- pySigma validation passing via `wrg__sigma__validate_rule`

## References

- [Anthropic Claude Code plugin marketplace](https://github.com/anthropics/claude-plugins-community)
- [WRG monorepo](https://github.com/WRG-11/WinstonRedGuard)
- 4-Layer self-audit: [`.claude-plugin/AUDIT-SELF.md`](.claude-plugin/AUDIT-SELF.md)
- External validation: [`.claude-plugin/AUDIT-VERIFY.md`](.claude-plugin/AUDIT-VERIFY.md)
- Marketplace PR draft: [`PR-DRAFT.md`](PR-DRAFT.md)

## License

MIT — see [`LICENSE`](LICENSE) file.
