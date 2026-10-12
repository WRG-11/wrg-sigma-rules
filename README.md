# WRG Sigma Rules

[![tests](https://github.com/WRG-11/wrg-sigma-rules/actions/workflows/tests.yml/badge.svg)](https://github.com/WRG-11/wrg-sigma-rules/actions/workflows/tests.yml)
[![release](https://img.shields.io/github/v/release/WRG-11/wrg-sigma-rules)](https://github.com/WRG-11/wrg-sigma-rules/releases)
[![last commit](https://img.shields.io/github/last-commit/WRG-11/wrg-sigma-rules)](https://github.com/WRG-11/wrg-sigma-rules/commits/main)
[![sigma rules](https://img.shields.io/badge/sigma__rules-294-1f6feb)](resources/examples/INDEX.json)
[![license](https://img.shields.io/github/license/WRG-11/wrg-sigma-rules)](LICENSE)
[![python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](requirements.txt)

Sigma detection-rule authoring, validation and multi-backend conversion,
delivered as a Model Context Protocol (MCP) server with a published rule corpus.
It runs under Claude Code, Codex, Cursor and any MCP-capable client.

- `draft_rule` turns a natural-language description into a Sigma YAML scaffold.
- `validate_rule` checks a rule against pySigma plus a best-practice linter.
- `convert_rule` compiles a rule to a Splunk, Elastic, OpenSearch or Kibana query.

The corpus holds <!-- METRIC:sigma_rule_count -->294<!-- /METRIC:sigma_rule_count -->
rules in <!-- METRIC:tactic_category_count -->16<!-- /METRIC:tactic_category_count -->
categories. It covers ransomware and threat-actor activity as well as vulnerabilities
disclosed in AI/LLM applications and MCP servers.

## Install

```bash
git clone https://github.com/WRG-11/wrg-sigma-rules.git
cd wrg-sigma-rules
pip install -r requirements.txt
claude plugin marketplace add .
claude plugin install wrg-sigma-rules@wrg-11
```

That installs the server as a Claude Code plugin. Codex, Cursor and other MCP clients
take the same server; [`docs/install.md`](docs/install.md) has the steps for each and the
notes on which interpreter runs it. Captured output from the tools is in
[`DEMO.md`](DEMO.md).

The plugin is installed directly from this repository, which is also its own
Claude Code and Codex marketplace; it is not yet listed in Anthropic's plugin
directory.

## Skills

There are three Claude Code skills: `sigma-rule-writer`, `sigma-rule-reviewer` and
`threat-coverage-gap-analyzer`. The packaged Codex variants retain the same
evidence boundaries: coverage counts do not establish missing ATT&CK scope,
conversion does not establish deployed semantics, and `observed_*` public
contributions require the sourcing bar in `CONTRIBUTING.md`.

## Conversion

Conversion runs on pySigma 1.x and targets Splunk SPL, Elastic and Kibana Lucene,
Elastic ES|QL and EQL, OpenSearch Lucene and PPL, plus a `wazuh` target that
reuses the Elasticsearch Lucene backend and says so in its warnings. The
Lucene-family targets cannot express Sigma correlation rules, so `convert_rule`
reports the
<!-- METRIC:correlation_rule_count -->27<!-- /METRIC:correlation_rule_count -->
correlation rules in the corpus as a capability gap and names the backends that
can convert them (`esql` and `eql` are the Elastic route).

Correlation conversions say where the query stops meaning the rule. Valid syntax
is not the same rule: measured on the pinned backends, `opensearch-ppl` drops the
time window of every count correlation, and `eql` turns a distinct-value count
into a join on one repeated value. Each correlation result carries
`correlation_semantics`, the deviations the converter checks for (dropped or
fixed window, unenforced order, threshold one short); see
[Demo 5](DEMO.md#demo-5----correlation-rules-and-where-they-cannot-go).

## Quick example

Validate and convert a corpus rule end to end, from the repo root:

```bash
pip install -r requirements.txt
```

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

Full captured output (validate JSON, Splunk SPL, Elasticsearch Lucene) is in
[`DEMO.md`](DEMO.md).

## The corpus

Every rule lives under `resources/examples/<tactic>/`: one directory per MITRE ATT&CK
Enterprise tactic (v19 names) plus `code_review` for source-code review rules. Each rule
is one of two kinds:

- `template_*`: a canonical detection shape to adapt to your own environment.
- `observed_*`: derived from a specific, cited incident. `CONTRIBUTING.md` sets
  the bar these must clear.

[`resources/examples/INDEX.json`](resources/examples/INDEX.json) enumerates every
rule, and the `wrg-sigma://coverage/mitre-attack-matrix` resource computes the
technique-by-tactic breakdown from the corpus at read time. Some rules add a
prose write-up under [`docs/detection-notes/`](docs/detection-notes/).

### Rule status

This corpus uses Sigma's `status:` field literally rather than aspirationally:

| `status:` | Count | Meaning here |
|---|---|---|
| `test` | <!-- METRIC:status_test_count -->46<!-- /METRIC:status_test_count --> | Mostly `observed_*` rules; CI requires a sidecar sample for every one, with no exceptions |
| `experimental` | <!-- METRIC:status_experimental_count -->248<!-- /METRIC:status_experimental_count --> | Both `template_*` and `observed_*` rules; new ones need a sidecar sample, older ones may sit in a tracked exception baseline |
| `stable` | <!-- METRIC:status_stable_count -->0<!-- /METRIC:status_stable_count --> | Unused, deliberately |

`stable` in the Sigma specification means a rule runs in production and is well
tested. Nothing here has earned that, so nothing claims it. Treat every rule as a
starting point to bind to your own logsource and tune; each rule's
`falsepositives:` block names the benign activity to expect first.

### Resources

- `wrg-sigma://patterns/canonical-5` and `wrg-sigma://patterns/canonical-5/{01..05}`:
  canonical detection-pattern definitions.
- `wrg-sigma://coverage/mitre-attack-matrix`: an ATT&CK coverage rollup computed
  from the corpus at read time. Its `Rules-content SHA-256` identifies the
  exact corpus bytes behind a count, so installed and checkout runtimes can be
  compared without treating different releases as measurement drift.

## Quality and testing

- <!-- METRIC:test_module_count -->36<!-- /METRIC:test_module_count --> Python test
  modules cover rule validation and tool-integration smoke tests.
- pySigma 1.x compatibility is verified against the Splunk, Elasticsearch and
  OpenSearch backend packages.
- CI runs the full suite on Ubuntu, Windows and macOS runners on every push to
  `main` and every pull request against it.
- The Docker CI smoke exchange compares the container coverage resource's
  corpus fingerprint with the checked-out corpus, so an otherwise healthy
  image cannot silently serve stale rule data.
- README counts are stamped from ground truth: a test runs the same check as
  `python readme_stamp.py --check` and fails CI on any drift, so the numbers here cannot silently go stale.
- `python scripts/runtime_identity.py --runtime-root <runtime-path>
  --expect-same-as .` compares an installed Codex runtime with this checkout
  without modifying either.

### Evidence-review audits

These local reports make review queues and conversion boundaries visible. They
are advisory: none promotes a rule, proves an actor attribution, or replaces
reading the cited source.
[`docs/evidence-review-audits.md`](docs/evidence-review-audits.md) lists the
commands and describes each report, its `--json` output and what its numbers
do and do not establish.

## Contributing

Contributions are welcome. Add YAML under `resources/examples/<tactic>/` with an
ATT&CK mapping in `tags:` (for example `attack.t1071`), the `observed_*` or
`template_*` prefix, and a passing `validate_rule`. Corpus CI rejects broad empty
matches, unsafe regex, unroutable logsource blocks, draft scaffolding and
deprecated aggregation-pipe syntax.

Read [`CONTRIBUTING.md`](CONTRIBUTING.md) before submitting an `observed_*` rule.
It sets the sourcing bar (attribution, platform and manifestation, each matched
against the cited source) and documents the three upstream rejections that
produced it.

## Scope

WRG Sigma Rules is a local, deterministic detection-engineering workbench. It
helps an MCP-capable client draft, validate and convert Sigma rules; it does
not deploy detections, collect telemetry, operate a hosted service, or claim
that a generated rule is production-ready.

Out of scope:

- A hosted multi-tenant MCP service or remote telemetry collection.
- Automatic deployment or activation of generated detections.
- Marking generic public rules `stable` without production evidence.
- Growing the corpus with uncited, duplicate or merely plausible detections.

## License

MIT; see [`LICENSE`](LICENSE). One license covers both the tooling (`server.py`,
`tools/`, `scripts/`) and the corpus (`resources/`). That is a deliberate choice
for frictionless reuse by SOC teams adapting a rule into their own tooling, over
the attribution-preserving split that some Sigma corpora use.

Runtime dependencies bring in LGPL-2.1/3.0 packages (pySigma and its backends)
alongside MIT, BSD and Apache ones. Importing an LGPL library does not make this
repo's own code LGPL. The `dependency-licenses` CI job carries the re-derivable
list.

## Part of the WRG-11 ecosystem

- [mcp-objauthz-lab](https://github.com/WRG-11/mcp-objauthz-lab): a
  vulnerable-by-design MCP server for learning BOLA and IDOR.
- [osint-trust-envelope](https://github.com/WRG-11/osint-trust-envelope): trust
  envelopes for OSINT results.

Full index at [github.com/WRG-11](https://github.com/WRG-11).
