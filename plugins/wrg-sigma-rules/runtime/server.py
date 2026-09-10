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

import json
import sys
from pathlib import Path

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

    _SDK_MAJOR = 2
except ImportError:  # mcp 1.x
    from mcp.server.fastmcp import FastMCP as _McpServer

    _SDK_MAJOR = 1

from tools.convert_rule import register_convert_rule_tool
from tools.draft_rule import register_draft_rule_tool
from tools.resources.canonical_patterns_resource import (
    register_canonical_pattern_resources,
)
from tools.resources.coverage_resource import register_coverage_resources
from tools.validate_rule import register_validate_rule_tool

_PLUGIN_JSON = Path(__file__).resolve().parent / ".claude-plugin" / "plugin.json"


def _read_plugin_version(path: Path = _PLUGIN_JSON) -> str:
    """Read the server version from the single source of truth.

    Fails loudly instead of falling back to an unversioned server: a
    missing or corrupt plugin.json is a build problem the operator needs
    to see, not something this server should mask by announcing itself
    without a version.
    """
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"cannot read version from {path}: {exc}") from exc
    version = data.get("version")
    if not version:
        raise RuntimeError(f"{path} has no 'version' field")
    return version


def _announced_version(server: object) -> str | None:
    """Return the version currently set on ``server``, across both SDK majors.

    ``mcp>=2.0``'s ``MCPServer`` takes ``version=`` directly and exposes it
    as a top-level attribute. ``mcp`` 1.x's ``FastMCP`` has no ``version``
    parameter at all -- the low-level ``Server`` it wraps does, so the 1.x
    branch below sets it on the nested ``_mcp_server`` after construction.
    """
    return getattr(server, "version", None) or getattr(
        getattr(server, "_mcp_server", None), "version", None
    )


_VERSION = _read_plugin_version()

# Server name surfaces in MCP client tool catalogs; mirror the Claude Code
# plugin name from .claude-plugin/plugin.json for cross-surface consistency.
if _SDK_MAJOR >= 2:
    mcp = _McpServer("wrg-sigma-rules", version=_VERSION)
else:
    mcp = _McpServer("wrg-sigma-rules")
    mcp._mcp_server.version = _VERSION

register_draft_rule_tool(mcp)
register_validate_rule_tool(mcp)
register_convert_rule_tool(mcp)
register_canonical_pattern_resources(mcp)
register_coverage_resources(mcp)


def main() -> int:  # pragma: no cover
    """Entry point — runs stdio MCP server until stdin closes.

    Blocks on stdio until the transport closes; not something a fast unit
    test can reach the way the ``if __name__`` guard below (already
    excluded in .coveragerc) is. Excluding the function itself rather than
    leaving it as unexplained missing coverage.
    """
    mcp.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
