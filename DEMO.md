# wrg-sigma-rules -- DEMO

End-to-end demonstration of the MCP tools (`validate_rule`, `convert_rule`,
`draft_rule`) and the coverage resource, using real production rules from the
plugin's corpus. Demos 1-3 use **Mini Shai-Hulud npm supply chain C2 egress**
(MsftSecIntel 2026-05-21 disclosure; rule
`observed_mini_shai_hulud_npm_supply_chain_c2_t1071.yml`); demos 4-6 use the
rules named in each section.

Captured with pySigma 1.x (+ `pysigma-backend-splunk`,
`pysigma-backend-elasticsearch`, `pysigma-backend-opensearch` and the sysmon
pipeline). All outputs are real tool invocations, not hand-edited.

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
- Threat-intel enrichment tooling or a sandbox resolving the indicator domain during analysis
- The security team's own verification lookups after this rule fires
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
- `valid: true` -- rule passes schema, pySigma round-trip, and the
  best-practice linter: title length, description length, non-empty
  references, at least one `attack.txxxx` tag, a non-vague condition, no
  deprecated aggregation pipe, no leftover `REPLACE_ME` scaffolding, and
  `falsepositives:` that names real benign scenarios rather than placeholder
  text.
- That last check is why this rule's `falsepositives:` reads the way it does.
  It previously said "None expected -- campaign-specific IOCs; no legitimate
  use case anticipated", which the linter now reports as
  `falsepositives_placeholder`: an analyst triaging the alert learns nothing
  from it. Enrichment tooling and the security team's own verification
  lookups genuinely do resolve an IOC domain, so those are named instead.
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

## Demo 4 -- processing pipelines change the query, not just a flag

A sigma rule is written against abstract logsource taxonomy
(`category: process_creation`), not a product's field names. Mapping that to
what a SIEM actually stores is a pySigma *processing pipeline*'s job. Without
one, the emitted query keeps the field names and drops the event selection.

Rule: `resources/examples/execution/template_t1059_001_powershell_encoded_command_execution.yml`

Without a pipeline:

```json
{
  "ok": true,
  "query": "Image=\"*\\\\powershell.exe\" CommandLine IN (\"* -enc *\", \"* -EncodedCommand *\", \"* -e *\") NOT CommandLine=\"* -NoProfile -EncodedCommand *\"",
  "pipelines_applied": []
}
```

With `config={"pipeline": "sysmon"}`:

```json
{
  "ok": true,
  "query": "EventID=1 Image=\"*\\\\powershell.exe\" CommandLine IN (\"* -enc *\", \"* -EncodedCommand *\", \"* -e *\") NOT CommandLine=\"* -NoProfile -EncodedCommand *\"",
  "pipelines_applied": ["sysmon"]
}
```

The difference is the leading `EventID=1`. Without it the query matches *any*
event carrying an `Image` field, not just process creation -- it runs, returns
results, and is scoped wrong. 66 of the 100 corpus rules are `product: windows`,
so this is the common case rather than an edge one.

---

## Demo 5 -- correlation rules, and where they cannot go

Rule: `resources/examples/credential_access/template_t1110_brute_force_high_volume_failed_logons.yml`
(a base rule plus an `event_count` correlation rule).

`convert_rule(..., target="splunk")`:

```json
{
  "ok": true,
  "query": "EventID=4625 LogonType IN (2, 3, 10)\n\n| bin _time span=10m\n| stats count as event_count by _time SourceIP\n\n| search event_count > 10"
}
```

`convert_rule(..., target="elastic")`:

```json
{
  "ok": false,
  "error": "backend 'elastic' does not support sigma correlation rules: Backend does not support correlation rules.",
  "hint": "the rule is valid -- this backend cannot express correlations. Targets in this plugin that can: splunk, opensearch-ppl",
  "kind": "backend_capability_gap",
  "capability": "correlation_rules"
}
```

This is a backend limit, not a defect in the rule, and the envelope says so
rather than returning a bare parse error that reads as "your rule is broken".
The Lucene-family targets (`elastic`, `kibana`, `wazuh`, `opensearch`) all
share it: measured across the corpus, they convert 90 of 100 rules while
`splunk` and `opensearch-ppl` convert all 100.

---

## Demo 6 -- `wrg-sigma://coverage/mitre-attack-matrix`

The coverage resource is computed from the corpus when read, so it cannot go
stale against the rules. Reading it returns markdown beginning:

```markdown
## Summary

- Rules: 203
- Incident rules (observed_*): 137
- Pattern rules (template_*): 66
- Distinct ATT&CK techniques covered: 86
- Tactic groupings: 14
```

followed by a technique-by-tactic table, a per-technique rule count, and a
list of any rule contributing no coverage at all.

---

## Reproducibility

To regenerate these outputs locally:

```bash
pip install -r requirements.txt
cd wrg-sigma-rules
python -c "
import sys, json
sys.path.insert(0, '.')
from tools.validate_rule.validate_rule import validate_rule_body
from tools.convert_rule.convert_rule import convert_rule_body
from tools.resources.coverage_resource import coverage_matrix_body

rule = open('resources/examples/command_and_control/observed_mini_shai_hulud_npm_supply_chain_c2_t1071.yml', encoding='utf-8').read()

print(json.dumps(validate_rule_body(rule), indent=2))
print(json.dumps(convert_rule_body(rule, target='splunk'), indent=2))
print(json.dumps(convert_rule_body(rule, target='elasticsearch'), indent=2))

# Demo 4 -- the same rule with and without a processing pipeline
enc = open('resources/examples/execution/template_t1059_001_powershell_encoded_command_execution.yml', encoding='utf-8').read()
print(convert_rule_body(enc, target='splunk')['query'])
print(convert_rule_body(enc, target='splunk', config={'pipeline': 'sysmon'})['query'])

# Demo 5 -- a correlation rule on a backend that cannot express it
corr = open('resources/examples/credential_access/template_t1110_brute_force_high_volume_failed_logons.yml', encoding='utf-8').read()
print(json.dumps(convert_rule_body(corr, target='splunk'), indent=2))
print(json.dumps(convert_rule_body(corr, target='elastic'), indent=2))

# Demo 6 -- the coverage resource
print(coverage_matrix_body())
"
```

`requirements.txt` is used instead of naming packages by hand, because the
pipeline and OpenSearch demos need extras the old three-package line omitted.

The plugin's pytest suite covers these tool invocations end-to-end
(`tests/test_validate_rule.py`, `tests/test_convert_rule.py`,
`tests/test_sigma_integration_e2e.py`). Suite status: green on every push via
[`.github/workflows/tests.yml`](.github/workflows/tests.yml) — deliberately no
hard-coded pass count here, because a hand-maintained number silently rots
(this line already claimed a stale 286, then a stale 287).

---

## See also

- [`README.md`](README.md) -- installation + quick start
- [`.claude-plugin/plugin.json`](.claude-plugin/plugin.json) -- plugin manifest
- [`skills/sigma-rule-writer/SKILL.md`](skills/sigma-rule-writer/SKILL.md) -- guided NL -> sigma workflow
- [`resources/examples/INDEX.json`](resources/examples/INDEX.json) -- 3-D corpus taxonomy
