# WRG Sigma Rules -- Anthropic Claude Code Plugin

**Status**: Scaffold (R88-56a A operator seed, 2026-05-21 22:30 TR). Production ship target: R88-56 wave wrap (~2-3 day window; agent Pazartesi 2026-05-25 pickup).

## Value proposition

Production-grade sigma detection rule writing, validation, and conversion for SOC analysts, threat-intel teams, and bug bounty hunters using Claude Code.

- **Fastest sigma rule writing**: LLM-assisted draft from natural language description
- **Quality-aware**: pySigma validation + best practices linter + WRG 50+ rule corpus as canonical examples
- **Multi-backend**: convert to Splunk, Elastic, Wazuh, Kibana queries
- **MITRE ATT&CK integration**: TTP-aware drafting + coverage gap analysis
- **WRG ecosystem anchor**: 100+ actor TTP corpus + 6+ months threat-intel discipline


## Why this plugin exists

Sigma rule niche in Anthropic marketplace is **100% empty** (verified 2026-05-21: 35 plugins, 0 sigma, 1 generic security). SOC + threat-intel community has latent demand for fast, quality-aware rule writing tools integrated with LLM workflows.

WRG (WinstonRedGuard) has accumulated 6+ months of threat-intel infrastructure including 50+ canonical sigma rules + actor catalog + pySigma integration + Pattern-driven discipline. This plugin packages that capability for the broader Anthropic ecosystem.

## Capabilities (post-ship)

### Tools

- `wrg__sigma__draft_rule` -- NL description -> sigma YAML scaffold
- `wrg__sigma__validate_rule` -- YAML schema + pySigma compat + best practices linter
- `wrg__sigma__convert_rule` -- sigma -> splunk/elastic/wazuh/kibana query

### Skills

- `sigma-rule-writer` -- guided rule writing workflow
- `sigma-rule-reviewer` -- paste rule for quality review + improvement
- `threat-coverage-gap-analyzer` -- MITRE ATT&CK coverage analysis

### Prompts

- `canonical-sigma-patterns` -- 5 detection pattern shapes
- `mitre-attack-rule-template` -- TTP ID -> rule scaffold
- `wrg-actor-rule-template` -- actor-specific rule scaffold
- `incident-response-sigma-mapping` -- incident -> sigma rule mapping

### Resources

- `wrg-sigma://patterns/canonical-5` -- canonical pattern definitions
- `wrg-sigma://coverage/mitre-attack-matrix` -- coverage state

## Quality discipline

- 4-Layer self-audit per [WRG audit methodology](../../docs/standards/anthropic-plugin-4-layer-audit.md) (Pattern 18 v1.1 trust-but-verify sister)
- 80+ test cases: 50 existing rule validation + 20 NL->YAML golden + 10 integration smoke (C R88-56c)
- pySigma 0.10+ compat + multi-backend conversion verified
- LLM-safe output discipline: PII redact + ASCII-only + error path structure preserve (Pattern 34 v1.1 sister)

## Installation (post-ship)

```bash
# Via Anthropic marketplace (post-merge)
/plugin install wrg-sigma-rules

# Or direct from this repo
git clone https://github.com/WRG-11/wrg-sigma-rules-plugin.git
```

## Status

| Stream | Status | Notes |
|---|---|---|
| A R88-56a | scaffold seed | This file + plugin.json + dir tree |
| B R88-56b | pending | 3 tool impl (draft + validate + convert) |
| C R88-56c | pending (wait_for_b_finalize) | Test corpus 80+ tests |
| D R88-56d | pending | WRG rules -> resources/examples migration |
| F R88-56f | pending (wait_for_a_scaffold) | Manifest + SKILL.md + 4-Layer self-audit |
| G R88-56g | pending (wait_for_all_finalize) | Marketplace submission audit + PR draft |
| E R88-56e | pending (last) | Codify-combo DECADE+6 MILESTONE |

## References

- Anthropic plugin marketplace: https://github.com/anthropics/claude-plugins-official (22K stars, 35 plugins, 2026-05-21)
- WRG W0 audit methodology: [`docs/standards/anthropic-plugin-4-layer-audit.md`](../../docs/standards/anthropic-plugin-4-layer-audit.md)
- WRG Pattern 18 v1.1 trust-but-verify endpoint-supply-chain super-cluster (sister discipline)
- WRG Pattern 33 v1.0 MCP capability category discipline (Resources URI sister)
- WRG Pattern 34 v1.0 LLM-safe always-redact (output discipline sister)

## License

MIT
