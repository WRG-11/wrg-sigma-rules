# Install

The server is a single stdio MCP process (`server.py`). Each client points at it
in its own way.

## Claude Code

```bash
git clone https://github.com/WRG-11/wrg-sigma-rules.git
cd wrg-sigma-rules
pip install -r requirements.txt
claude plugin marketplace add .
claude plugin install wrg-sigma-rules@wrg-11
```

Claude Code starts `server.py` with the `python` on your `PATH`, so install
`requirements.txt` into that interpreter. It is not optional: `validate_rule`
needs pySigma, `convert_rule` needs the backend packages, and the pipeline
packages drive the logsource mapping. `claude plugin marketplace add
WRG-11/wrg-sigma-rules` registers the GitHub repository instead of the clone;
use it if Claude Code refuses the local path as network-shaped or
unclassifiable, which it can do for a clone on an external drive.
`claude plugin validate .` checks the plugin and marketplace manifests, and
[the plugin docs](https://code.claude.com/docs/en/plugins) cover updating and
removing an installed plugin.

## Codex

```bash
codex plugin marketplace add .
codex plugin add wrg-sigma-rules@wrg-11
```

The Codex package under `plugins/wrg-sigma-rules/` carries its own copy of the
server and corpus, so the installed plugin does not depend on this checkout.
Codex starts it with the `python` on your `PATH`: install
`plugins/wrg-sigma-rules/runtime/requirements.txt` into that interpreter, then
confirm in Codex that the server answers before relying on it.

## Cursor

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

## Any MCP client

`server.py` is a standard stdio MCP server. Any client that can launch a stdio
server takes the same `command`, `args`, `cwd` and `env` values shown for
Cursor; your client's MCP documentation says where that configuration lives.
The model behind the client does not change what the server exposes.
