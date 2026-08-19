"""Unit tests for server.py's version derivation (R89-1135b).

stdlib + pytest only; no network. Exercises `_read_plugin_version` /
`_announced_version` directly against `tmp_path` fixtures so a change to the
repo's real `.claude-plugin/plugin.json` value never breaks these tests --
only a live smoke test (scripts/mcp_stdio_smoke.py) needs the real file.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import server as server_module  # noqa: E402


def test_read_plugin_version_returns_version_field(tmp_path: Path) -> None:
    plugin_json = tmp_path / "plugin.json"
    plugin_json.write_text(json.dumps({"version": "9.9.9"}), encoding="utf-8")
    assert server_module._read_plugin_version(plugin_json) == "9.9.9"


def test_read_plugin_version_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="cannot read version"):
        server_module._read_plugin_version(tmp_path / "does-not-exist.json")


def test_read_plugin_version_corrupt_json_raises(tmp_path: Path) -> None:
    plugin_json = tmp_path / "plugin.json"
    plugin_json.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(RuntimeError, match="cannot read version"):
        server_module._read_plugin_version(plugin_json)


def test_read_plugin_version_missing_field_raises(tmp_path: Path) -> None:
    plugin_json = tmp_path / "plugin.json"
    plugin_json.write_text(json.dumps({"name": "no-version-here"}), encoding="utf-8")
    with pytest.raises(RuntimeError, match="no 'version' field"):
        server_module._read_plugin_version(plugin_json)


def test_live_server_version_matches_plugin_json() -> None:
    """The module-level `mcp` instance must announce the repo's real version.

    Mutation-checked: temporarily editing `.claude-plugin/plugin.json`'s
    `version` field and re-running this test (fresh process, since `server`
    is imported once per interpreter) turns this red -- proving the
    assertion is not comparing a value against itself.
    """
    expected = json.loads(
        server_module._PLUGIN_JSON.read_text(encoding="utf-8")
    )["version"]
    actual = server_module._announced_version(server_module.mcp)
    assert actual == expected


def test_announced_version_reads_sdk1_style_nested_attribute() -> None:
    class _FakeInner:
        version = "1.2.3"

    class _FakeFastMCPStyle:
        _mcp_server = _FakeInner()

    assert server_module._announced_version(_FakeFastMCPStyle()) == "1.2.3"


def test_announced_version_prefers_top_level_sdk2_style_attribute() -> None:
    class _FakeMCPServerStyle:
        version = "2.0.0"

    assert server_module._announced_version(_FakeMCPServerStyle()) == "2.0.0"
