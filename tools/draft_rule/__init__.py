"""draft_rule MCP tool -- NL threat description -> sigma YAML scaffold.

Public surface:

* ``draft_rule_body(...)`` -- deterministic, testable function.
* ``register_draft_rule_tool(mcp)`` -- decorator wrapper for FastMCP.

Sister to ``canonical_patterns_resource`` pattern (D R88-52d Resources
layer; B R88-56b 1st sister tool layer application).
"""
from __future__ import annotations

from .draft_rule import draft_rule_body, register_draft_rule_tool

__all__ = ["draft_rule_body", "register_draft_rule_tool"]
