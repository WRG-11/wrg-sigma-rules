"""Unit tests for the MCP stdio smoke contract checks."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


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


def test_coverage_resource_identity_returns_the_announced_digest() -> None:
    digest = "b" * 64
    assert smoke._coverage_corpus_fingerprint(
        [{"text": f"- Rules-content SHA-256: `{digest}`\n"}]
    ) == digest


def test_parse_command_keeps_the_server_command_and_optional_expectation() -> None:
    digest = "c" * 64
    assert smoke._parse_command(
        ["--expect-corpus-fingerprint", digest, "--", "docker", "run"]
    ) == (digest, ["docker", "run"])

    with pytest.raises(ValueError, match="64-character"):
        smoke._parse_command(["--expect-corpus-fingerprint", "not-a-digest"])


def test_expected_server_version_requires_a_nonempty_manifest_value(tmp_path: Path) -> None:
    manifest = tmp_path / "plugin.json"
    manifest.write_text(json.dumps({"version": "1.2.3"}), encoding="utf-8")
    assert smoke._expected_server_version(manifest) == "1.2.3"

    manifest.write_text(json.dumps({"version": " "}), encoding="utf-8")
    with pytest.raises(ValueError, match="missing or invalid"):
        smoke._expected_server_version(manifest)
