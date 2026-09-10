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
