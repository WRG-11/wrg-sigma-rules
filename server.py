"""Standalone MCP server for wrg-sigma-rules tools (Glama deployment).

Glama runs this entry-point in a Docker container to perform automated
safety/quality checks. The 3 MCP tools (draft_rule, validate_rule,
convert_rule) are registered against a FastMCP instance and exposed
over stdio — matching the transport Claude Code uses internally so the
tool surface is identical across runtimes.

This is the standalone counterpart to the Claude Code plugin runtime,
which mounts the same ``tools/`` package via ``.claude-plugin/plugin.json``.
Both surfaces share the same tool implementations in
``tools/<name>/<name>.py`` (see ``<name>_body()`` functions).

Glama Dockerfile invokes this as::

    docker run -i --rm wrg-sigma-rules-mcp

Glama's MCP client connects via stdin/stdout; the server announces the
3 tools then handles JSON-RPC requests over that channel.
"""
from __future__ import annotations

import sys

from mcp.server.fastmcp import FastMCP

from tools.convert_rule import register_convert_rule_tool
from tools.draft_rule import register_draft_rule_tool
from tools.validate_rule import register_validate_rule_tool

# Server name surfaces in MCP client tool catalogs; mirror the Claude Code
# plugin name from .claude-plugin/plugin.json for cross-surface consistency.
mcp = FastMCP("wrg-sigma-rules")

register_draft_rule_tool(mcp)
register_validate_rule_tool(mcp)
register_convert_rule_tool(mcp)


def main() -> int:
    """Entry point — runs stdio MCP server until stdin closes."""
    mcp.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
