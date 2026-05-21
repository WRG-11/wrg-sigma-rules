"""convert_rule MCP tool -- sigma YAML -> SIEM-native query via pySigma backends."""
from __future__ import annotations

from .convert_rule import convert_rule_body, register_convert_rule_tool

__all__ = ["convert_rule_body", "register_convert_rule_tool"]
