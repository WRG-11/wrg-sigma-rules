# wrg-sigma-rules -- DEMO

End-to-end demonstration of the `validate_rule` and `convert_rule` MCP tools
and the coverage resource, using rules from the plugin's published corpus
(none of them `stable`; see the README's Rule status section). Demos 1-3 use **Mini Shai-Hulud npm supply chain C2 egress**
(Microsoft Threat Intelligence, 2026-05-20; rule
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
description: 'Campaign-bound sigma detection for Mini Shai-Hulud npm supply chain
  attack (Microsoft Threat Intelligence, 2026-05-20). Detects outbound C2 communication
  to the m-kosche.com domain family (apex + wildcard subdomains; published IOC
  t.m-kosche.com) or to 185.95.159.32. That address is not an IOC in the cited
  sources: it is what t.m-kosche.com resolved to when checked on 2026-09-30, and
  the address behind a domain can change. Initial infection vector:
  compromised npm packages (antv family confirmed; Bun preinstall hook activation
  + SLSA provenance forge) -- post-install egress to credential-theft + worm
  propagation C2 endpoint. The rule adds a SIEM-side detection layer for log
  enrichment and retrospective hunting.

  Aggregated from 1 active campaign disclosure 2026-05-20 (Microsoft Threat
  Intelligence).

  Sister cluster: Nx campaign 4-vector cluster (COMPLETE). Mini Shai-Hulud is the 1st vector (npm package compromise);
  cross-reference observed_s1ngularity_nx_npm_token_exfil_t1195_002.yml (2nd
  vector; CLI installer), observed_nx_console_t1195_002.yml (3rd vector; VS
  Code extension), and observed_clawhavoc_claude_skills_t1195_002.yml (4th
  vector; Claude Code Skills) in the same corpus for campaign-wide detection
  coverage.'
references:
- https://attack.mitre.org/techniques/T1071/
- https://attack.mitre.org/techniques/T1195/002/
- https://attack.mitre.org/techniques/T1041/
- https://www.microsoft.com/en-us/security/blog/2026/05/20/mini-shai-hulud-compromised-antv-npm-packages-enable-ci-cd-credential-theft/
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
- wrg.observed.campaign.mini_shai_hulud
- wrg.observed.cluster.nx_campaign_4_vector
- wrg.observed.cluster.nx_campaign_4_vector_complete
- wrg.observed.ioc.m_kosche_com_domain_family
- wrg.observed.ioc.ip_185_95_159_32
- wrg.observed.vector.npm_supply_chain_bun_preinstall_hook
- wrg.severity.high
- wrg.observed
- wrg.tactic.command_and_control
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
results, and is scoped wrong. <!-- METRIC:windows_product_count -->139<!-- /METRIC:windows_product_count --> of the <!-- METRIC:sigma_rule_count -->294<!-- /METRIC:sigma_rule_count --> corpus rules
are `product: windows`, so this is the common case rather than an edge one.

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
  "hint": "the rule is valid -- this backend cannot express this correlation shape. Targets in this plugin that can convert it: splunk, esql, eql, opensearch-ppl. A successful conversion lists in 'correlation_semantics' where the query changes the rule's window, order or threshold",
  "kind": "backend_capability_gap",
  "capability": "correlation_rules"
}
```

This is a backend limit, not a defect in the rule, and the envelope says so
rather than returning a bare parse error that reads as "your rule is broken".
The Lucene-family targets (`elastic`, `kibana`, `wazuh`, `opensearch`) all
share it: measured across the corpus, they convert <!-- METRIC:lucene_convert_count -->267<!-- /METRIC:lucene_convert_count --> of
<!-- METRIC:sigma_rule_count -->294<!-- /METRIC:sigma_rule_count --> rules, and all four fail on exactly the same set — the
<!-- METRIC:correlation_rule_count -->27<!-- /METRIC:correlation_rule_count --> correlation rules — and on nothing else. For Elastic, the
correlation route is `esql` or `eql` from the same backend package.
`splunk` and `esql` convert <!-- METRIC:splunk_esql_convert_count -->291<!-- /METRIC:splunk_esql_convert_count -->: every rule except the
<!-- METRIC:temporal_ordered_rule_count -->3<!-- /METRIC:temporal_ordered_rule_count --> `temporal_ordered` correlations, which neither backend can
express. `eql` and `opensearch-ppl` convert all <!-- METRIC:sigma_rule_count -->294<!-- /METRIC:sigma_rule_count -->.

Converting is not the same as keeping the rule. The same rule on
`opensearch-ppl`:

```json
{
  "ok": true,
  "query": "| search source=windows-authentication-* | where EventID=4625 AND (LogonType in (2, 3, 10)) | stats count() as event_count by SourceIP | where event_count > 10",
  "correlation_semantics": [
    {
      "code": "window_dropped",
      "detail": "the correlation timespan 10m does not appear in the opensearch-ppl query, so the threshold applies to the whole search time range instead of 10m"
    }
  ]
}
```

"More than 10 failed logons in 10 minutes" became "more than 10 in whatever
range the search covers". Every correlation conversion carries
`correlation_semantics`; the deviations it checks for, all measured on the
pinned backends:

| Code | Meaning | Seen on |
|---|---|---|
| `window_dropped` | the timespan is not in the query at all | `opensearch-ppl` (`event_count`, `value_count`), `eql` (`temporal`) |
| `fixed_window` | the window is a fixed bucket, not a sliding span | `splunk`, `esql`, `opensearch-ppl` |
| `order_not_enforced` | a `temporal_ordered` query matches in any order | `opensearch-ppl` |
| `subrule_identity_by_eventid` | sub-rules are told apart by distinct EventID | `opensearch-ppl` |
| `cannot_fire_same_logsource` | ...and every sub-rule reads the same log type, so the query cannot reach its threshold | `opensearch-ppl` (all 3 corpus `temporal_ordered` rules) |
| `value_count_joins_on_field` | a distinct-value count became a join on one repeated value | `eql` |
| `threshold_off_by_one` | `gt N` became `runs=N`, one event short | `eql` |

`eql`'s `sequence` is the one route that keeps a `temporal_ordered` rule's
order and window. An empty list means none of these was found -- not that the
query behaves like the rule in your SIEM. `python scripts/correlation_conversion_audit.py`
prints the per-target counts for the whole corpus.

---

## Demo 6 -- `wrg-sigma://coverage/mitre-attack-matrix`

The coverage resource is computed from the corpus when read, so it cannot go
stale against the rules. Reading it returns markdown beginning:

```markdown
## Summary

- Rules: 294
- Incident rules (observed_*): 198
- Pattern rules (template_*): 96
- Distinct ATT&CK techniques covered: 116
- Tactic groupings: 16
```

followed by a technique-by-tactic table, a per-technique rule count, and a
list of any rule contributing no coverage at all.

---

## Reproducibility

To regenerate these outputs locally:

```bash
git clone https://github.com/WRG-11/wrg-sigma-rules.git
cd wrg-sigma-rules
pip install -r requirements.txt
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
