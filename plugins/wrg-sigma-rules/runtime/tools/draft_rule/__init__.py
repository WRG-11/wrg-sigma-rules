"""draft_rule MCP tool -- NL threat description -> sigma YAML scaffold.

Public surface:

* ``draft_rule_body(...)`` -- deterministic, testable function.
* ``register_draft_rule_tool(mcp)`` -- decorator wrapper for FastMCP.
"""
from __future__ import annotations

from .draft_rule import draft_rule_body, register_draft_rule_tool

__all__ = ["draft_rule_body", "register_draft_rule_tool"]
