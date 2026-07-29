"""Standalone MCP server for wrg-sigma-rules tools (Glama deployment).

Glama runs this entry-point in a Docker container to perform automated
safety/quality checks. The 3 MCP tools (draft_rule, validate_rule,
convert_rule) plus the canonical-patterns resource are registered
against the SDK's high-level server (``MCPServer`` on mcp 2.x, the
API-compatible ``FastMCP`` on 1.x) and exposed over stdio — matching the
transport Claude Code uses internally so the tool surface is identical
across runtimes.

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

# MCP SDK 2.0 renamed the high-level server: `mcp.server.fastmcp.FastMCP`
# became `mcp.server.MCPServer` and the old module was removed outright, so
# a plain `from mcp.server.fastmcp import FastMCP` fails hard on 2.x. The
# two classes are API-compatible for everything this server uses -- the
# `tool()` and `resource()` decorators and `list_tools()` /
# `list_resources()` / `list_resource_templates()` have identical
# signatures, and `run()` differs only in trailing keyword arguments this
# module does not pass. Supporting both keeps the plugin installable
# against whichever SDK the host environment already has, instead of
# pinning users to one major version. Try 2.x first so a machine with both
# resolutions available lands on the current API.
try:  # mcp >= 2.0
    from mcp.server import MCPServer as _McpServer
except ImportError:  # mcp 1.x
    from mcp.server.fastmcp import FastMCP as _McpServer

from tools.convert_rule import register_convert_rule_tool
from tools.draft_rule import register_draft_rule_tool
from tools.resources.canonical_patterns_resource import (
    register_canonical_pattern_resources,
)
from tools.resources.coverage_resource import register_coverage_resources
from tools.validate_rule import register_validate_rule_tool

# Server name surfaces in MCP client tool catalogs; mirror the Claude Code
# plugin name from .claude-plugin/plugin.json for cross-surface consistency.
mcp = _McpServer("wrg-sigma-rules")

register_draft_rule_tool(mcp)
register_validate_rule_tool(mcp)
register_convert_rule_tool(mcp)
register_canonical_pattern_resources(mcp)
register_coverage_resources(mcp)


def main() -> int:
    """Entry point — runs stdio MCP server until stdin closes."""
    mcp.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
