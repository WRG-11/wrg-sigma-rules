# WRG Sigma Rules — Anthropic Claude Code Plugin

> 💡 **Found this useful?** ⭐ Star the repo (helps others find it) and subscribe to weekly detection-engineering writeups at [Detection Frontier](https://detection-frontier.kit.com/subscribe).

> **Status**: Production-ready. Not yet submitted to a plugin marketplace — install directly from this repo (see [Installation](#installation)).

Production-grade sigma detection rule writing, validation, and conversion for SOC analysts, threat-intel teams, and detection engineers using Claude Code.

## TL;DR

- **3 MCP tools**: `draft_rule` (NL → sigma YAML) + `validate_rule` (pySigma + best-practice linter) + `convert_rule` (sigma → Splunk/Elastic/Wazuh/Kibana query)
- **3 Claude Code skills**: sigma-rule-writer + sigma-rule-reviewer + threat-coverage-gap-analyzer
- **<!-- METRIC:sigma_rule_count -->68<!-- /METRIC:sigma_rule_count --> production sigma rule corpus**: 11 ATT&CK tactic categories (templates + observed campaign rules)
- **Multi-backend conversion**: Splunk SPL, Elastic Lucene, Wazuh, Kibana verified (pySigma 1.x + 2 backend packages)
- **WRG ecosystem anchor**: 6+ months threat-intel discipline + 100+ actor TTP corpus + observed_* rules (Mini Shai-Hulud npm worm, Nx campaign 4-vector cluster, SOCKS5 silent-fix, ClawHavoc Claude Skills, Lazarus, LockBit, LAPSUS, AI-fingerprint)
- **Live demo**: see [`DEMO.md`](DEMO.md) for end-to-end tool invocation on Mini Shai-Hulud rule (pySigma 1.x + Splunk + Elastic real output)

## Why this plugin exists

The sigma-rule niche in the Anthropic Claude Code plugin marketplace is **empty** (verified 2026-05-23: 200+ plugins, 0 sigma-focused, 1 generic security plugin). SOC + threat-intel community has latent demand for fast, quality-aware rule writing tools integrated with LLM workflows.

WRG (WinstonRedGuard) has accumulated 6+ months of threat-intel infrastructure: <!-- METRIC:sigma_rule_count -->68<!-- /METRIC:sigma_rule_count --> canonical sigma rules + actor catalog + pySigma integration + Pattern-driven detection-engineering discipline. This plugin packages that capability for the broader Anthropic ecosystem.

## What's included

### MCP tools (3)

- `wrg__sigma__draft_rule` — NL description → sigma YAML scaffold
- `wrg__sigma__validate_rule` — YAML schema + pySigma compat + best-practice linter
- `wrg__sigma__convert_rule` — sigma → Splunk/Elastic/Wazuh/Kibana query

### Claude Code skills (3)

- `sigma-rule-writer` — guided rule writing workflow
- `sigma-rule-reviewer` — paste rule for quality review + improvement suggestions
- `threat-coverage-gap-analyzer` — MITRE ATT&CK coverage analysis vs your existing corpus

### Sigma rule corpus (<!-- METRIC:sigma_rule_count -->68<!-- /METRIC:sigma_rule_count --> production rules across 11 ATT&CK tactic categories)

| Tactic | Coverage |
|---|---|
| `credential_access` | templates + observed (LAPSUS T1110 correlation, Kali365 OAuth device-code phishing T1528, Mimikatz LSASS) |
| `command_and_control` | template T1071 + **observed Mini Shai-Hulud npm supply-chain C2 T1071** (Nx campaign cluster) |
| `defense_evasion` | templates + observed (AlphV T1027 obfuscation) |
| `execution` | templates + observed (AlphV T1059.001) |
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
- `wrg-sigma://coverage/mitre-attack-matrix` — corpus coverage state

## Installation

### Direct from this repo

```bash
git clone https://github.com/WRG-11/wrg-sigma-rules.git
# Follow Claude Code plugin install path per https://code.claude.com/docs/en/plugins
```

## Quality discipline

- **4-Layer self-audit** per WRG audit methodology (trust-but-verify self-audit)
- **7 Python test modules** covering rule validation + tool integration smoke
- **pySigma 1.x compat** + multi-backend conversion verified (`pysigma-backend-splunk` + `pysigma-backend-elasticsearch`)
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
- pySigma validation passing via `wrg__sigma__validate_rule`

## References

- [Anthropic Claude Code plugin marketplace](https://github.com/anthropics/claude-plugins-community)
- [WRG monorepo](https://github.com/WRG-11/WinstonRedGuard)

## License

MIT — see [`LICENSE`](LICENSE) file.
