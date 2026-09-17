"""The installed Codex plugin must retain every runtime dependency it needs."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "plugins" / "wrg-sigma-rules"
RUNTIME = PLUGIN / "runtime"
WRAPPER = PLUGIN / "scripts" / "codex_server.py"
MARKETPLACE = ROOT / ".agents" / "plugins" / "marketplace.json"
SPEC = importlib.util.spec_from_file_location("wrg_sigma_codex_server", WRAPPER)
assert SPEC and SPEC.loader
codex_server = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(codex_server)


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


def test_local_marketplace_points_at_the_self_contained_plugin() -> None:
    """Keep README's local Codex install selector tied to this package."""
    marketplace = json.loads(MARKETPLACE.read_text(encoding="utf-8"))
    assert marketplace["name"] == "wrg-11"
    plugins = marketplace["plugins"]
    assert isinstance(plugins, list)
    matches = [entry for entry in plugins if entry.get("name") == "wrg-sigma-rules"]
    assert len(matches) == 1
    source = matches[0]["source"]
    assert source["source"] == "local"
    assert (ROOT / source["path"]).resolve() == PLUGIN.resolve()


def test_codex_package_base_version_matches_the_server_manifest() -> None:
    """Codex may carry a local build suffix, never a different release base."""
    codex_manifest = json.loads((PLUGIN / ".codex-plugin" / "plugin.json").read_text())
    server_manifest = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text())

    assert codex_manifest["name"] == server_manifest["name"]
    assert _release_version(codex_manifest["version"]) == server_manifest["version"]


def test_codex_wrapper_requires_every_runtime_input(tmp_path: Path) -> None:
    """A missing corpus must fail before a client sees an empty resource."""
    script = tmp_path / "plugin" / "scripts" / "codex_server.py"
    script.parent.mkdir(parents=True)
    script.write_text("# test anchor\n", encoding="utf-8")
    runtime = script.parents[1] / "runtime"
    runtime.mkdir()
    for name in ("server.py", "requirements.txt"):
        (runtime / name).write_text("# runtime\n", encoding="utf-8")
    manifest = runtime / ".claude-plugin" / "plugin.json"
    manifest.parent.mkdir()
    manifest.write_text("{}\n", encoding="utf-8")
    (runtime / "tools").mkdir()

    with pytest.raises(RuntimeError, match="runtime is incomplete"):
        codex_server._runtime_root(script)

    (runtime / "resources").mkdir()
    assert codex_server._runtime_root(script) == runtime


def test_packaged_skills_keep_evidence_and_conversion_boundaries_explicit() -> None:
    skills = PLUGIN / "skills"
    coverage = skills.joinpath("threat-coverage-gap-analyzer", "SKILL.md").read_text(
        encoding="utf-8"
    )
    writer = skills.joinpath("sigma-rule-writer", "SKILL.md").read_text(
        encoding="utf-8"
    )
    reviewer = skills.joinpath("sigma-rule-reviewer", "SKILL.md").read_text(
        encoding="utf-8"
    )

    assert "wrg-sigma://coverage/mitre-attack-matrix" in coverage
    assert "Do not claim missing tactics or techniques" in coverage
    assert "never invent an `observed_*` rule" in coverage
    assert "`CONTRIBUTING.md`" in writer
    assert "`observed_*` rule" in writer
    assert "syntax evidence only" in reviewer
    assert "semantic equivalence" in reviewer


def test_checkout_skills_keep_the_same_evidence_and_conversion_boundaries() -> None:
    skills = ROOT / "skills"
    coverage = skills.joinpath("threat-coverage-gap-analyzer", "SKILL.md").read_text(
        encoding="utf-8"
    )
    writer = skills.joinpath("sigma-rule-writer", "SKILL.md").read_text(
        encoding="utf-8"
    )
    reviewer = skills.joinpath("sigma-rule-reviewer", "SKILL.md").read_text(
        encoding="utf-8"
    )

    assert "Do not claim missing tactics or techniques" in coverage
    assert "versioned comparison scope" in coverage
    assert "`CONTRIBUTING.md`" in writer
    assert "`observed_*`" in writer
    assert "syntax evidence only" in reviewer
    assert "semantic equivalence" in reviewer


def test_codex_wrapper_resolves_its_runtime_outside_the_plugin_cwd(
    tmp_path: Path,
) -> None:
    """Installed plugins must not depend on the host launching them in cwd:."""
    code = (
        "import importlib.util; "
        f"spec = importlib.util.spec_from_file_location('wrapper', {str(WRAPPER)!r}); "
        "module = importlib.util.module_from_spec(spec); "
        "spec.loader.exec_module(module); "
        "print(module._runtime_root())"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    )

    assert Path(result.stdout.strip()).resolve() == RUNTIME.resolve()
