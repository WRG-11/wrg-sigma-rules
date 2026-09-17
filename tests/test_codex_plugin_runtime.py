"""The installed Codex plugin must retain every runtime dependency it needs."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "plugins" / "wrg-sigma-rules"
RUNTIME = PLUGIN / "runtime"


def _files(root: Path) -> dict[Path, str]:
    return {
        path.relative_to(root): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in root.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts
    }


def _release_version(version: str) -> str:
    """Drop a package-local suffix without accepting a different release."""
    return version.split("+", 1)[0]


def test_codex_plugin_runtime_matches_canonical_server_sources() -> None:
    for filename in ("server.py", "requirements.txt"):
        assert (RUNTIME / filename).read_bytes() == (ROOT / filename).read_bytes()
    for directory in (".claude-plugin", "tools", "resources"):
        assert _files(RUNTIME / directory) == _files(ROOT / directory)


def test_codex_plugin_manifest_registers_the_self_contained_runtime() -> None:
    manifest = json.loads((PLUGIN / ".codex-plugin" / "plugin.json").read_text())
    mcp_config = json.loads((PLUGIN / ".mcp.json").read_text())
    assert manifest["mcpServers"] == "./.mcp.json"
    assert mcp_config["mcpServers"]["wrg-sigma-rules"]["args"] == [
        "scripts/codex_server.py"
    ]


def test_codex_package_base_version_matches_the_server_manifest() -> None:
    """Codex may carry a local build suffix, never a different release base."""
    codex_manifest = json.loads((PLUGIN / ".codex-plugin" / "plugin.json").read_text())
    server_manifest = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text())

    assert codex_manifest["name"] == server_manifest["name"]
    assert _release_version(codex_manifest["version"]) == server_manifest["version"]
