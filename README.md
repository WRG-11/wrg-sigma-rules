# WRG Sigma Rules

[![tests](https://github.com/WRG-11/wrg-sigma-rules/actions/workflows/tests.yml/badge.svg)](https://github.com/WRG-11/wrg-sigma-rules/actions/workflows/tests.yml)
[![release](https://img.shields.io/github/v/release/WRG-11/wrg-sigma-rules)](https://github.com/WRG-11/wrg-sigma-rules/releases)
[![last commit](https://img.shields.io/github/last-commit/WRG-11/wrg-sigma-rules)](https://github.com/WRG-11/wrg-sigma-rules/commits/main)
[![sigma rules](https://img.shields.io/badge/sigma__rules-296-1f6feb)](resources/examples/INDEX.json)
[![license](https://img.shields.io/github/license/WRG-11/wrg-sigma-rules)](LICENSE)
[![python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](requirements.txt)

Sigma detection-rule authoring, validation and multi-backend conversion,
delivered as a Model Context Protocol (MCP) server with a published rule corpus.
It runs under Claude Code, Codex, Cursor and any MCP-capable client.

## What it does

- Three MCP tools. `draft_rule` turns a natural-language description into a Sigma
  YAML scaffold. `validate_rule` checks a rule against pySigma plus a
  best-practice linter. `convert_rule` compiles a rule to a Splunk, Elastic,
  OpenSearch, Wazuh or Kibana query.
- Three Claude Code skills: `sigma-rule-writer`, `sigma-rule-reviewer` and
  `threat-coverage-gap-analyzer`.
- A published corpus of <!-- METRIC:sigma_rule_count -->296<!-- /METRIC:sigma_rule_count -->
  rules across <!-- METRIC:tactic_category_count -->14<!-- /METRIC:tactic_category_count -->
  MITRE ATT&CK tactic categories. Every rule carries an honest Sigma `status:`
  (see [Rule status](#rule-status)).
- Multi-backend conversion on pySigma 1.x: Splunk SPL, Elastic and Kibana Lucene,
  OpenSearch Lucene and PPL, plus Wazuh. The Lucene-family targets cannot express
  Sigma correlation rules, so `convert_rule` reports the
  <!-- METRIC:correlation_rule_count -->52<!-- /METRIC:correlation_rule_count -->
  correlation rules in the corpus as a capability gap and names the backends that
  can convert them.

The plugin is installed directly from this repository; it is not yet listed in a
plugin marketplace.

## Install

The server is a single stdio MCP process (`server.py`). Each client points at it
in its own way.

### Claude Code

```bash
git clone https://github.com/WRG-11/wrg-sigma-rules.git
cd wrg-sigma-rules
pip install -r requirements.txt
claude plugin validate .
```

`requirements.txt` is not optional: `validate_rule` needs pySigma, `convert_rule`
needs the backend packages, and the pipeline packages drive the logsource
mapping. The repo ships `.claude-plugin/plugin.json` and `.mcp.json` (which wires
`server.py` through `${CLAUDE_PLUGIN_ROOT}`). Point your Claude Code plugin
configuration at this checkout per
[the plugin docs](https://code.claude.com/docs/en/plugins).

### Codex

```bash
codex plugin marketplace add .
codex plugin add wrg-sigma-rules@wrg-11
```

The Codex plugin carries a self-contained runtime snapshot of the server and
corpus, so its installed cache does not rely on checkout-relative paths. Keep it
current with `python scripts/sync_codex_runtime.py`; CI fails if it drifts.

### Cursor

Cursor speaks MCP directly, so the same server works with no plugin manifest. Add
it to your project `.cursor/mcp.json` (or the global `~/.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "wrg-sigma-rules": {
      "command": "python",
      "args": ["/path/to/wrg-sigma-rules/server.py"],
      "cwd": "/path/to/wrg-sigma-rules",
      "env": { "PYTHONPATH": "/path/to/wrg-sigma-rules" }
    }
  }
}
```

Replace the path with your clone, then reload Cursor's MCP servers.

### Any MCP client

`server.py` is a standard stdio MCP server, so Cline, Continue, Zed and Windsurf
load it with the same `mcpServers` block shown for Cursor. MCP is model-agnostic:
the client's backend model does not change what the server exposes.

## Quick example

Validate and convert a corpus rule end to end, from the repo root:

```bash
pip install pysigma pysigma-backend-splunk pysigma-backend-elasticsearch
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

Every rule lives under `resources/examples/<tactic>/` and is one of two kinds:

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
| `test` | <!-- METRIC:status_test_count -->82<!-- /METRIC:status_test_count --> | Derived from a real, cited incident (the `observed_*` rules) |
| `experimental` | <!-- METRIC:status_experimental_count -->214<!-- /METRIC:status_experimental_count --> | Canonical detection shapes, many self-described as synthetic exemplars |
| `stable` | <!-- METRIC:status_stable_count -->0<!-- /METRIC:status_stable_count --> | Unused, deliberately |

`stable` in the Sigma specification means a rule runs in production and is well
tested. Nothing here has earned that, so nothing claims it. Treat every rule as a
starting point to bind to your own logsource and tune; each rule's
`falsepositives:` block names the benign activity to expect first.

### Resources

- `wrg-sigma://patterns/canonical-5` and `wrg-sigma://patterns/canonical-5/{01..05}`:
  canonical detection-pattern definitions.
- `wrg-sigma://coverage/mitre-attack-matrix`: an ATT&CK coverage rollup computed
  from the corpus at read time.

## Quality and testing

- <!-- METRIC:test_module_count -->25<!-- /METRIC:test_module_count --> Python test
  modules cover rule validation and tool-integration smoke tests.
- pySigma 1.x compatibility is verified against the Splunk, Elasticsearch and
  OpenSearch backend packages.
- CI runs the full suite on Ubuntu, Windows and macOS runners on every push.
- README counts are stamped from ground truth: `python readme_stamp.py --check`
  fails CI on any drift, so the numbers here cannot silently go stale.

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

See [`ROADMAP.md`](ROADMAP.md) for the repository's current direction, explicit
product boundaries and evidence required before an item is considered complete.

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
- [osint-trust-envelope](https://github.com/WRG-11/osint-trust-envelope): honest
  trust envelopes for OSINT results.

Full index at [github.com/WRG-11](https://github.com/WRG-11).
