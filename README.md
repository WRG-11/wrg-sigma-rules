# WRG Sigma Rules — Claude Code Plugin


## Status

Production — actively maintained rule corpus. Not yet submitted to a plugin marketplace — install directly from this repo (see [Installation](#installation)).

Production-grade sigma detection rule writing, validation, and conversion for SOC analysts, threat-intel teams, and detection engineers using Claude Code.

## TL;DR

- **3 MCP tools**: `draft_rule` (NL → sigma YAML) + `validate_rule` (pySigma + best-practice linter) + `convert_rule` (sigma → Splunk/Elastic/OpenSearch/Wazuh/Kibana query)
- **3 Claude Code skills**: sigma-rule-writer + sigma-rule-reviewer + threat-coverage-gap-analyzer
- **<!-- METRIC:sigma_rule_count -->73<!-- /METRIC:sigma_rule_count --> production sigma rule corpus**: 12 ATT&CK tactic categories (templates + observed campaign rules)
- **Multi-backend conversion**: Splunk SPL, Elastic/Kibana Lucene, OpenSearch Lucene + PPL, Wazuh verified (pySigma 1.x + 3 backend packages)
- **Logsource-aware output**: `config={"pipeline": "sysmon"}` maps Sigma's abstract logsource to the product's real event selection — without it a `process_creation` rule converts to a query that matches events of every type
- **WRG ecosystem anchor**: 6+ months threat-intel discipline + 100+ actor TTP corpus + observed_* rules (Mini Shai-Hulud npm worm, Nx campaign 4-vector cluster, SOCKS5 silent-fix, ClawHavoc Claude Skills, Lazarus, LockBit, LAPSUS, AI-fingerprint)
- **Live demo**: see [`DEMO.md`](DEMO.md) for end-to-end tool invocation on Mini Shai-Hulud rule (pySigma 1.x + Splunk + Elastic real output)

## Why this plugin exists

The sigma-rule niche in the Anthropic Claude Code plugin marketplace is **empty** (verified 2026-05-23: 200+ plugins, 0 sigma-focused, 1 generic security plugin). SOC + threat-intel community has latent demand for fast, quality-aware rule writing tools integrated with LLM workflows.

WRG (WinstonRedGuard) has accumulated 6+ months of threat-intel infrastructure: <!-- METRIC:sigma_rule_count -->73<!-- /METRIC:sigma_rule_count --> canonical sigma rules + actor catalog + pySigma integration + Pattern-driven detection-engineering discipline. This plugin packages that capability for the broader Anthropic ecosystem.

## What's included

### MCP tools (3)

- `mcp__plugin_wrg-sigma-rules_wrg-sigma-rules__draft_rule` — NL description → sigma YAML scaffold
- `mcp__plugin_wrg-sigma-rules_wrg-sigma-rules__validate_rule` — YAML schema + pySigma compat + best-practice linter
- `mcp__plugin_wrg-sigma-rules_wrg-sigma-rules__convert_rule` — sigma → Splunk/Elastic/OpenSearch/Wazuh/Kibana query

### Claude Code skills (3)

- `sigma-rule-writer` — guided rule writing workflow
- `sigma-rule-reviewer` — paste rule for quality review + improvement suggestions
- `threat-coverage-gap-analyzer` — MITRE ATT&CK coverage analysis vs your existing corpus

### Sigma rule corpus (<!-- METRIC:sigma_rule_count -->73<!-- /METRIC:sigma_rule_count --> production rules across 12 ATT&CK tactic categories)

| Tactic | Coverage |
|---|---|
| `credential_access` | templates + observed (LAPSUS T1110 correlation, Kali365 OAuth device-code phishing T1528, Mimikatz LSASS) |
| `command_and_control` | template T1071 + **observed Mini Shai-Hulud npm supply-chain C2 T1071** (Nx campaign cluster) |
| `defense_evasion` | templates + observed (AlphV T1027 obfuscation) |
| `execution` | templates + observed (AlphV T1059.001) |
| `persistence` | observed (Photo ZIP campaign, Node.js HKCU Run-key persistence T1547.001) |
| `exfiltration` | templates + **observed SOCKS5 hostname null-byte egress T1041** (Claude Code v2.0.24-v2.1.89 silent-fix; +backslash extension variant) |
| `impact` | templates + observed (Lazarus + LockBit BTC + Nullsec Nigeria T1491 defacement) |
| `initial_access` | templates + **observed Nx campaign 4-vector** (s1ngularity npm token exfil, nx-console VS Code extension compromise, ClawHavoc Claude Skills T1195.002) + LAPSUS T1078 + OWASP lab-validated (SQLi auth-bypass, XSS reflected, path traversal) |
| `lateral_movement` | templates (RDP EventID 4624 + SMB admin shares) |
| `resource_development` | templates (newly registered domain + lookalike domain + social media signup) |
| `collection` | templates (archive utility staging + SharePoint access) |
| `code_review` | 5 AI-fingerprint observed rules (ANSI-color class, decoy block, docstring density, hallucinated CVSS, prompt artifacts) |

See [`resources/examples/INDEX.json`](resources/examples/INDEX.json) for full enumeration.

### Resources

- `wrg-sigma://patterns/canonical-5` — canonical detection-pattern definitions
- `wrg-sigma://patterns/canonical-5/{pattern_id}` — individual pattern by ID (`01`–`05`)
- `wrg-sigma://coverage/mitre-attack-matrix` — corpus ATT&CK coverage state (technique-by-tactic rollup, observed/template split, rules contributing no coverage), computed from the corpus at read time

## Installation

### Direct from this repo

```bash
git clone https://github.com/WRG-11/wrg-sigma-rules.git
# Follow Claude Code plugin install path per https://code.claude.com/docs/en/plugins
```

## Quick example

Validate + convert a corpus rule end-to-end, from the repo root (commands from [`DEMO.md`](DEMO.md), captured against pySigma 1.x + the Splunk and Elasticsearch backends):

```bash
pip install pysigma pysigma-backend-splunk pysigma-backend-elasticsearch
python -c "
import sys, json
sys.path.insert(0, '.')
from tools.validate_rule.validate_rule import validate_rule_body
from tools.convert_rule.convert_rule import convert_rule_body

rule = open('resources/examples/command_and_control/observed_mini_shai_hulud_npm_supply_chain_c2_t1071.yml', encoding='utf-8').read()

print(json.dumps(validate_rule_body(rule), indent=2))
print(json.dumps(convert_rule_body(rule, target='splunk'), indent=2))
print(json.dumps(convert_rule_body(rule, target='elasticsearch'), indent=2))
"
```

Full captured outputs (validate JSON + Splunk SPL + Elasticsearch Lucene) are in [`DEMO.md`](DEMO.md).

## Quality discipline

- **4-Layer self-audit** per WRG audit methodology (trust-but-verify self-audit)
- **<!-- METRIC:test_module_count -->12<!-- /METRIC:test_module_count --> Python test modules** covering rule validation + tool integration smoke
- **pySigma 1.x compat** + multi-backend conversion verified (`pysigma-backend-splunk` + `pysigma-backend-elasticsearch` + `pysigma-backend-opensearch`)
- **LLM-safe output discipline**: ASCII-only output + error-path structure preserve
- **`claude plugin validate` PASS** (verified 2026-05-25)
- **Live demo evidence**: [`DEMO.md`](DEMO.md) — 3 real tool invocations on Mini Shai-Hulud rule

## Tested environments

- Windows 11 + Claude Code
- WSL2 Ubuntu 24.04

## Contributing

Sigma rule contributions welcome. Submit YAML to `resources/examples/<tactic>/` with:

- ATT&CK TTP mapping in `tags:` field (e.g., `attack.t1071`)
- `observed_*` prefix for incident-specific rules
- `template_*` prefix for canonical pattern templates
- pySigma validation passing via `mcp__plugin_wrg-sigma-rules_wrg-sigma-rules__validate_rule`

Read [`CONTRIBUTING.md`](CONTRIBUTING.md) first if the rule claims to detect
something observed in the wild. It sets out the sourcing bar — attribution,
platform, and manifestation all matched against the cited source — and the
three upstream rejections that produced it.

## References

- [Anthropic Claude Code plugin marketplace](https://github.com/anthropics/claude-plugins-community)

## License

MIT — see [`LICENSE`](LICENSE) file.

---

## Part of the WRG-11 ecosystem

- [mcp-objauthz-lab](https://github.com/WRG-11/mcp-objauthz-lab) — vulnerable-by-design MCP server for learning BOLA/IDOR
- [osint-trust-envelope](https://github.com/WRG-11/osint-trust-envelope) — honest trust envelopes for OSINT results

Full index → [github.com/WRG-11](https://github.com/WRG-11)
