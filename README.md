# WRG Sigma Rules — Claude Code Plugin

[![tests](https://github.com/WRG-11/wrg-sigma-rules/actions/workflows/tests.yml/badge.svg)](https://github.com/WRG-11/wrg-sigma-rules/actions/workflows/tests.yml)
[![release](https://img.shields.io/github/v/release/WRG-11/wrg-sigma-rules)](https://github.com/WRG-11/wrg-sigma-rules/releases)
[![last commit](https://img.shields.io/github/last-commit/WRG-11/wrg-sigma-rules)](https://github.com/WRG-11/wrg-sigma-rules/commits/main)
[![sigma rules](https://img.shields.io/badge/sigma__rules-108-1f6feb)](resources/examples/INDEX.json)
[![license](https://img.shields.io/github/license/WRG-11/wrg-sigma-rules)](LICENSE)
[![python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](requirements.txt)

## Status

Production — actively maintained rule corpus. Not yet listed in the community plugin marketplace; install directly from this repo (see [Installation](#installation)).

Listing is submitted through [clau.de/plugin-directory-submission](https://clau.de/plugin-directory-submission), which feeds Anthropic's review pipeline. `anthropics/claude-plugins-community` is a read-only mirror of the approved list and closes pull requests opened against it automatically, so a PR there is not the route.

Production-grade sigma detection rule writing, validation, and conversion for SOC analysts, threat-intel teams, and detection engineers using Claude Code.

## TL;DR

- **3 MCP tools**: `draft_rule` (NL → sigma YAML) + `validate_rule` (pySigma + best-practice linter) + `convert_rule` (sigma → Splunk/Elastic/OpenSearch/Wazuh/Kibana query)
- **3 Claude Code skills**: sigma-rule-writer + sigma-rule-reviewer + threat-coverage-gap-analyzer
- **<!-- METRIC:sigma_rule_count -->108<!-- /METRIC:sigma_rule_count --> published sigma rule corpus**: <!-- METRIC:tactic_category_count -->14<!-- /METRIC:tactic_category_count --> ATT&CK tactic categories (templates + observed campaign rules). Every rule carries a sigma `status:` — none of them `stable`; see [rule status](#rule-status) for the breakdown and what it means before you deploy one
- **Multi-backend conversion**: Splunk SPL, Elastic/Kibana Lucene, OpenSearch Lucene + PPL, Wazuh verified (pySigma 1.x + 3 backend packages). Re-measured against the full 101-rule corpus on 2026-08-06 (the corpus was 80 rules when this was first measured, so the number is restated rather than carried forward): Splunk and OpenSearch-PPL convert every rule; the Lucene-family targets (Elastic, Kibana, Wazuh, OpenSearch) fail on the 10 correlation rules, because that backend cannot express them — `convert_rule` reports this as a capability gap and names the targets that can
- **Logsource-aware output**: `config={"pipeline": "sysmon"}` maps Sigma's abstract logsource to the product's real event selection — without it a `process_creation` rule converts to a query that matches events of every type
- **WRG ecosystem anchor**: 6+ months threat-intel discipline + 100+ actor TTP corpus + observed_* rules (Mini Shai-Hulud npm worm, Nx campaign 4-vector cluster, SOCKS5 silent-fix, ClawHavoc Claude Skills, Lazarus, LockBit, LAPSUS, AI-fingerprint)
- **Live demo**: see [`DEMO.md`](DEMO.md) for end-to-end tool invocation on Mini Shai-Hulud rule (pySigma 1.x + Splunk + Elastic real output)

## Why this plugin exists

The sigma-rule niche in the Anthropic Claude Code plugin marketplace is **empty**: re-counted against `anthropics/claude-plugins-community` on 2026-08-06, 0 of 2298 community plugins mention sigma. The count is reproducible: fetch `.claude-plugin/marketplace.json` and grep each entry's name, description and homepage — the only fields the manifest carries. By that same method 290 entries mention at least one of security, vulnerability, exploit, pentest, CVE, threat, malware, OWASP, secrets, appsec, infosec, detection or SIEM. So the niche being empty is not the same as the area being empty, and the claim here is specific: nobody is doing sigma rule authoring, validation and multi-backend conversion, not "nobody is doing security".

(For scale, the same count on 2026-05-23 found 200+ plugins and one security plugin. The marketplace grew more than tenfold in under three months; the sigma count stayed at zero.)

WRG (WinstonRedGuard) has accumulated 6+ months of threat-intel infrastructure: <!-- METRIC:sigma_rule_count -->108<!-- /METRIC:sigma_rule_count --> canonical sigma rules + actor catalog + pySigma integration + Pattern-driven detection-engineering discipline. This plugin packages that capability for the broader Anthropic ecosystem.

## What's included

### MCP tools (3)

- `mcp__plugin_wrg-sigma-rules_wrg-sigma-rules__draft_rule` — NL description → sigma YAML scaffold
- `mcp__plugin_wrg-sigma-rules_wrg-sigma-rules__validate_rule` — YAML schema + pySigma compat + best-practice linter
- `mcp__plugin_wrg-sigma-rules_wrg-sigma-rules__convert_rule` — sigma → Splunk/Elastic/OpenSearch/Wazuh/Kibana query

### Claude Code skills (3)

- `sigma-rule-writer` — guided rule writing workflow
- `sigma-rule-reviewer` — paste rule for quality review + improvement suggestions
- `threat-coverage-gap-analyzer` — MITRE ATT&CK coverage analysis vs your existing corpus

### Sigma rule corpus (<!-- METRIC:sigma_rule_count -->108<!-- /METRIC:sigma_rule_count --> rules across <!-- METRIC:tactic_category_count -->14<!-- /METRIC:tactic_category_count --> ATT&CK tactic categories)

| Tactic | Coverage |
|---|---|
| `credential_access` | templates + observed (LAPSUS [T1110](https://attack.mitre.org/techniques/T1110/) correlation, Kali365 OAuth device-code phishing [T1528](https://attack.mitre.org/techniques/T1528/), Mimikatz LSASS) |
| `command_and_control` | template [T1071](https://attack.mitre.org/techniques/T1071/) + **observed Mini Shai-Hulud npm supply-chain C2 [T1071](https://attack.mitre.org/techniques/T1071/)** (Nx campaign cluster) |
| `defense_evasion` | templates + observed (AlphV [T1027](https://attack.mitre.org/techniques/T1027/) obfuscation) |
| `execution` | templates + observed (AlphV [T1059.001](https://attack.mitre.org/techniques/T1059/001/)) |
| `persistence` | template [T1053.005](https://attack.mitre.org/techniques/T1053/005/) (scheduled task created by a scripting host) + observed (Photo ZIP campaign, Node.js HKCU Run-key persistence [T1547.001](https://attack.mitre.org/techniques/T1547/001/)) |
| `exfiltration` | templates + **observed SOCKS5 hostname null-byte egress [T1041](https://attack.mitre.org/techniques/T1041/)** (Claude Code v2.0.24-v2.1.89 silent-fix; +backslash extension variant) |
| `impact` | templates + observed (Lazarus + LockBit BTC + Nullsec Nigeria [T1491](https://attack.mitre.org/techniques/T1491/) defacement) |
| `initial_access` | templates + **observed Nx campaign 4-vector** (s1ngularity npm token exfil, nx-console VS Code extension compromise, ClawHavoc Claude Skills [T1195.002](https://attack.mitre.org/techniques/T1195/002/)) + LAPSUS [T1078](https://attack.mitre.org/techniques/T1078/) + OWASP lab-validated (SQLi auth-bypass, XSS reflected, path traversal) |
| `lateral_movement` | templates (RDP EventID 4624 + SMB admin shares + WinRM remote execution [T1021.006](https://attack.mitre.org/techniques/T1021/006/)) |
| `privilege_escalation` | templates (AWS IAM wildcard-admin policy creation [T1098.003](https://attack.mitre.org/techniques/T1098/003/) + UAC bypass via auto-elevating binary [T1548.002](https://attack.mitre.org/techniques/T1548/002/)) |
| `resource_development` | templates (newly registered domain + lookalike domain + social media signup) |
| `collection` | templates (archive utility staging + SharePoint access + local email collection [T1114.001](https://attack.mitre.org/techniques/T1114/001/)) + **observed Diffusers sharded-checkpoint `weight_map` path traversal [T1005](https://attack.mitre.org/techniques/T1005/)** (CVE-2026-65920) |
| `discovery` | templates ([T1082](https://attack.mitre.org/techniques/T1082/) system information discovery + [T1083](https://attack.mitre.org/techniques/T1083/) file and directory discovery, both keyed on recon command bursts) |
| `code_review` | 9 AI-fingerprint observed rules (AI prose, AI provenance, ANSI-color class, decoy block, docstring density, hallucinated CVSS, hallucinated import, prompt artifacts, unicode watermark) |

See [`resources/examples/INDEX.json`](resources/examples/INDEX.json) for full enumeration.

Some rules have a companion write-up under [`docs/detection-notes/`](docs/detection-notes/)
explaining the detection logic in prose — why the signal is specific, what
the false-positive trap looks like, and what the coverage gaps are — for
cases where the rule's `description:` field alone would not carry that.

### Rule status

Sigma's `status:` field says how far a rule has been proven, and this corpus
uses it literally rather than aspirationally:

| `status:` | Count | What it means here |
|---|---|---|
| `test` | <!-- METRIC:status_test_count -->8<!-- /METRIC:status_test_count --> | Derived from a real, cited incident — the `observed_*` campaign rules |
| `experimental` | <!-- METRIC:status_experimental_count -->100<!-- /METRIC:status_experimental_count --> | Canonical detection shapes; many describe themselves as synthetic exemplars in their own `description:` |
| `stable` | <!-- METRIC:status_stable_count -->0<!-- /METRIC:status_stable_count --> | Deliberately unused |

`stable` in the sigma specification means a rule is running in production and
well tested. Nothing here has earned that: the template layer is pattern
material to adapt, not detections that have been validated against a real
environment's telemetry. Marking them `stable` would make the corpus look
more finished than it is, which is the same failure as writing "Unknown" in
`falsepositives:`.

Treat any rule here as a starting point to bind to your own logsource and
tune — the `falsepositives:` block on each one names the benign activity to
expect first.

### Resources

- `wrg-sigma://patterns/canonical-5` — canonical detection-pattern definitions
- `wrg-sigma://patterns/canonical-5/{pattern_id}` — individual pattern by ID (`01`–`05`)
- `wrg-sigma://coverage/mitre-attack-matrix` — corpus ATT&CK coverage state (technique-by-tactic rollup, observed/template split, rules contributing no coverage), computed from the corpus at read time

## Installation

### Direct from this repo

```bash
git clone https://github.com/WRG-11/wrg-sigma-rules.git
cd wrg-sigma-rules
pip install -r requirements.txt
claude plugin validate .
```

`requirements.txt` is not optional for the MCP tools. `validate_rule` needs
pySigma, `convert_rule` needs the backend packages, and the two pipeline
packages are what make the logsource mapping above work — install them and
the suite is green, skip them and the pipeline paths import fine while
converting a `process_creation` rule to a query that matches every event
type.

`claude plugin validate .` reads `.claude-plugin/plugin.json` and exits 0 on
success. The repo ships that plugin manifest plus `.mcp.json`, which wires
`server.py` through `${CLAUDE_PLUGIN_ROOT}`; point your Claude Code plugin
configuration at this checkout per
[the plugin docs](https://code.claude.com/docs/en/plugins).

## Quick example

Validate + convert a corpus rule end-to-end, from the repo root (commands from [`DEMO.md`](DEMO.md), captured against pySigma 1.x + the Splunk and Elasticsearch backends):

```bash
pip install pysigma pysigma-backend-splunk pysigma-backend-elasticsearch
```

(Those three are all this example needs. `pip install -r requirements.txt`
from [Installation](#installation) is the superset — add it if you also want
OpenSearch or the `config={"pipeline": ...}` logsource mapping.)

```python
import sys, json
sys.path.insert(0, '.')
from tools.validate_rule.validate_rule import validate_rule_body
from tools.convert_rule.convert_rule import convert_rule_body

rule = open('resources/examples/command_and_control/observed_mini_shai_hulud_npm_supply_chain_c2_t1071.yml', encoding='utf-8').read()

print(json.dumps(validate_rule_body(rule), indent=2))
print(json.dumps(convert_rule_body(rule, target='splunk'), indent=2))
print(json.dumps(convert_rule_body(rule, target='elasticsearch'), indent=2))
```

Full captured outputs (validate JSON + Splunk SPL + Elasticsearch Lucene) are in [`DEMO.md`](DEMO.md).

## Quality discipline

- **4-Layer self-audit** per WRG audit methodology (trust-but-verify self-audit)
- **<!-- METRIC:test_module_count -->17<!-- /METRIC:test_module_count --> Python test modules** covering rule validation + tool integration smoke
- **pySigma 1.x compat** + multi-backend conversion verified (`pysigma-backend-splunk` + `pysigma-backend-elasticsearch` + `pysigma-backend-opensearch`)
- **LLM-safe output discipline**: ASCII-only output + error-path structure preserve
- **`claude plugin validate` PASS** — not yet wired into CI (see [tests.yml](.github/workflows/tests.yml)); run it yourself with `claude plugin validate .` before relying on a dated claim here
- **Live demo evidence**: [`DEMO.md`](DEMO.md) — 3 real tool invocations on Mini Shai-Hulud rule

## Tested environments

- Windows 11 + Claude Code (manual)
- WSL2 Ubuntu 24.04 (manual)
- Ubuntu, Windows, and macOS GitHub Actions runners — see the
  [tests](https://github.com/WRG-11/wrg-sigma-rules/actions/workflows/tests.yml)
  workflow, which runs the full suite on all three on every push

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

Questions about *why* a rule is shaped the way it is, or whether a technique
is worth a rule at all, belong in
[Discussions](https://github.com/WRG-11/wrg-sigma-rules/discussions) rather
than an issue — [issues](https://github.com/WRG-11/wrg-sigma-rules/issues)
are for concrete bugs and rule submissions (see the issue templates).

## References

- [Anthropic Claude Code plugin marketplace](https://github.com/anthropics/claude-plugins-community)
- [Sigma specification](https://github.com/SigmaHQ/sigma) — the rule format this corpus targets
- [pySigma](https://github.com/SigmaHQ/pySigma) — the validation/conversion engine `validate_rule` and `convert_rule` wrap
- [MITRE ATT&CK](https://attack.mitre.org/) — the technique taxonomy used in `tags:` and the coverage resource

## License

MIT — see [`LICENSE`](LICENSE) file. Covers the tooling (`server.py`, `tools/`,
`scripts/`) and the rule corpus (`resources/`) under one license, a deliberate
choice: some Sigma corpora split rule content under a separate
[Detection Rule License](https://github.com/SigmaHQ/Detection-Rule-License)
to preserve attribution on redistribution, but that trades off against
frictionless reuse by SOC teams adapting a rule into their own tooling. MIT
was chosen for the latter.

Runtime dependencies bring in LGPL-2.1/3.0 (pySigma and its backend/pipeline
packages, from SigmaHQ) and a handful of MIT/BSD/Apache packages. Using an
LGPL library — importing it, not modifying it — does not require this
repo's own code to be LGPL; see the
[dependency-licenses](https://github.com/WRG-11/wrg-sigma-rules/actions/workflows/tests.yml)
CI job for the full, re-derivable list rather than trusting this paragraph
to stay current on its own.

---

## Part of the WRG-11 ecosystem

- [mcp-objauthz-lab](https://github.com/WRG-11/mcp-objauthz-lab) — vulnerable-by-design MCP server for learning BOLA/IDOR
- [osint-trust-envelope](https://github.com/WRG-11/osint-trust-envelope) — honest trust envelopes for OSINT results

Full index → [github.com/WRG-11](https://github.com/WRG-11)
