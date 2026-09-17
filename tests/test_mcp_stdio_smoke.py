"""Unit tests for the MCP stdio smoke contract checks."""
from __future__ import annotations

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "mcp_stdio_smoke.py"
SPEC = importlib.util.spec_from_file_location("mcp_stdio_smoke", SCRIPT)
assert SPEC and SPEC.loader
smoke = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(smoke)


def test_coverage_resource_identity_requires_a_full_sha256_line() -> None:
    digest = "a" * 64
    assert smoke._has_coverage_corpus_identity(
        [{"text": f"# Coverage\n- Rules-content SHA-256: `{digest}`\n"}]
    )
    assert not smoke._has_coverage_corpus_identity(
        [{"text": "- Rules-content SHA-256: `short`\n"}]
    )
