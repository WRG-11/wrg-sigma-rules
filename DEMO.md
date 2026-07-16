# wrg-sigma-rules -- DEMO

End-to-end demonstration of the three MCP tools (`validate_rule`,
`convert_rule`, `draft_rule`) using a real production rule from the
plugin's corpus: **Mini Shai-Hulud npm supply chain C2 egress**
(MsftSecIntel 2026-05-21 disclosure; rule
`observed_mini_shai_hulud_npm_supply_chain_c2_t1071.yml`).

Functionality demo for the plugin.
Captured with pySigma 1.X stable (+ `pysigma-backend-splunk` +
`pysigma-backend-elasticsearch`). All outputs are real tool invocations,
not hand-edited.

---

## Input -- sigma YAML rule (corpus member)

```yaml
title: Mini Shai-Hulud -- T1071 npm supply chain C2 egress to m-kosche.com IOC
id: 6d9183d6-562c-5445-987a-1df5f450f9af
status: experimental
description: Campaign-bound sigma detection for Mini Shai-Hulud npm supply chain
  attack (MsftSecIntel 2026-05-21 disclosure). Detects outbound C2 communication
  to the m-kosche.com domain family or hardcoded C2 IP 185.95.159.32.
references:
- https://attack.mitre.org/techniques/T1071/
- https://attack.mitre.org/techniques/T1195/002/
- https://attack.mitre.org/techniques/T1041/
- https://twitter.com/MsftSecIntel
author: WinstonRedGuard -- sigma plugin observed rules (derived from breach corpus)
date: '2026-05-22'
logsource:
  category: dns
  product: windows
detection:
  selection_dns_query_apex:
    QueryName|endswith:
    - .m-kosche.com
    - m-kosche.com
  selection_dns_query_t_subdomain:
    QueryName: t.m-kosche.com
  selection_network_ip_c2:
    DestinationIp: 185.95.159.32
  selection_npm_process_parent:
    ParentImage|endswith:
    - \node.exe
    - \npm.cmd
    - \npm.exe
    - \bun.exe
    - \yarn.cmd
    - \yarn.exe
    - \pnpm.cmd
    - \pnpm.exe
  condition: 1 of selection_dns_* or selection_network_ip_c2 or (selection_npm_process_parent and 1 of selection_dns_*)
falsepositives:
- None expected -- campaign-specific IOCs; no legitimate use case anticipated.
level: high
tags:
- attack.t1071
- attack.t1195.002
- attack.t1041
```

---

## Demo 1 -- `validate_rule(yaml_content)`

Schema check + pySigma parse + best-practices linter + MITRE coverage
extraction. Deterministic; no LLM call at tool layer.

**Output**:

```json
{
  "ok": true,
  "valid": true,
  "schema_errors": [],
  "pysigma_errors": [],
  "pysigma_available": true,
  "linter_warnings": [],
  "mitre_coverage": {
    "techniques": ["T1071", "T1195.002", "T1041"],
    "count": 3
  },
  "target_backend": "default",
  "strict": false
}
```

**Interpretation**:
- `valid: true` -- rule passes schema, pySigma round-trip, and all 6 lint
  checks (title length + description >= 10 + non-empty references +
  populated falsepositives + at least one `attack.txxxx` tag + non-vague
  condition).
- `mitre_coverage` -- 3 MITRE ATT&CK techniques extracted from rule tags
  (T1071 C2, T1195.002 supply chain compromise, T1041 exfiltration).

---

## Demo 2 -- `convert_rule(yaml_content, target="splunk")`

Sigma YAML -> Splunk SPL query, via pySigma 1.X +
`pysigma-backend-splunk` 2.X.

**Output**:

```json
{
  "ok": true,
  "query": "QueryName IN (\"*.m-kosche.com\", \"*m-kosche.com\") OR QueryName=\"t.m-kosche.com\" OR DestinationIp=\"185.95.159.32\" OR (ParentImage IN (\"*\\\\node.exe\", \"*\\\\npm.cmd\", \"*\\\\npm.exe\", \"*\\\\bun.exe\", \"*\\\\yarn.cmd\", \"*\\\\yarn.exe\", \"*\\\\pnpm.cmd\", \"*\\\\pnpm.exe\") QueryName IN (\"*.m-kosche.com\", \"*m-kosche.com\") OR QueryName=\"t.m-kosche.com\")",
  "target": "splunk",
  "warnings": [],
  "metadata": {
    "title": "Mini Shai-Hulud -- T1071 npm supply chain C2 egress to m-kosche.com IOC",
    "id": "6d9183d6-562c-5445-987a-1df5f450f9af",
    "level": "high",
    "logsource": "SigmaLogSource(category='dns', product='windows')"
  }
}
```

**Splunk SPL (rendered, query field)**:

```spl
QueryName IN ("*.m-kosche.com", "*m-kosche.com")
  OR QueryName="t.m-kosche.com"
  OR DestinationIp="185.95.159.32"
  OR (ParentImage IN ("*\\node.exe", "*\\npm.cmd", "*\\npm.exe", "*\\bun.exe", "*\\yarn.cmd", "*\\yarn.exe", "*\\pnpm.cmd", "*\\pnpm.exe")
      QueryName IN ("*.m-kosche.com", "*m-kosche.com") OR QueryName="t.m-kosche.com")
```

---

## Demo 3 -- `convert_rule(yaml_content, target="elasticsearch")`

Sigma YAML -> Elasticsearch Lucene query, via pySigma 1.X +
`pysigma-backend-elasticsearch` 2.X.

**Output**:

```json
{
  "ok": true,
  "query": "((QueryName:(*.m\\-kosche.com OR *m\\-kosche.com)) OR QueryName:t.m\\-kosche.com) OR DestinationIp:185.95.159.32 OR ((ParentImage:(*\\\\node.exe OR *\\\\npm.cmd OR *\\\\npm.exe OR *\\\\bun.exe OR *\\\\yarn.cmd OR *\\\\yarn.exe OR *\\\\pnpm.cmd OR *\\\\pnpm.exe)) AND ((QueryName:(*.m\\-kosche.com OR *m\\-kosche.com)) OR QueryName:t.m\\-kosche.com))",
  "target": "elasticsearch",
  "warnings": [],
  "metadata": {
    "title": "Mini Shai-Hulud -- T1071 npm supply chain C2 egress to m-kosche.com IOC",
    "id": "6d9183d6-562c-5445-987a-1df5f450f9af",
    "level": "high",
    "logsource": "SigmaLogSource(category='dns', product='windows')"
  }
}
```

**Elasticsearch Lucene (rendered, query field)**:

```text
((QueryName:(*.m\-kosche.com OR *m\-kosche.com)) OR QueryName:t.m\-kosche.com)
  OR DestinationIp:185.95.159.32
  OR ((ParentImage:(*\\node.exe OR *\\npm.cmd OR *\\npm.exe OR *\\bun.exe OR *\\yarn.cmd OR *\\yarn.exe OR *\\pnpm.cmd OR *\\pnpm.exe))
      AND ((QueryName:(*.m\-kosche.com OR *m\-kosche.com)) OR QueryName:t.m\-kosche.com))
```

---

## Reproducibility

To regenerate these outputs locally:

```bash
pip install pysigma pysigma-backend-splunk pysigma-backend-elasticsearch
cd wrg-sigma-rules
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

The plugin's pytest suite covers these tool invocations end-to-end
(`tests/test_validate_rule.py`, `tests/test_convert_rule.py`,
`tests/test_sigma_integration_e2e.py`). Suite status: 287/287 PASS.

---

## See also

- [`README.md`](README.md) -- installation + quick start
- [`.claude-plugin/plugin.json`](.claude-plugin/plugin.json) -- plugin manifest
- [`skills/sigma-rule-writer/SKILL.md`](skills/sigma-rule-writer/SKILL.md) -- guided NL -> sigma workflow
- [`resources/examples/INDEX.json`](resources/examples/INDEX.json) -- 3-D corpus taxonomy (73 rules)
