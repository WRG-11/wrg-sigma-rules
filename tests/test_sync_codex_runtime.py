"""Tests for the safe, read-only Codex-runtime parity check."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "sync_codex_runtime.py"
SPEC = importlib.util.spec_from_file_location("sync_codex_runtime", SCRIPT)
assert SPEC and SPEC.loader
runtime_sync = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runtime_sync
SPEC.loader.exec_module(runtime_sync)


def _write_runtime_tree(root: Path) -> None:
    root.joinpath("server.py").write_text("server\n", encoding="utf-8")
    root.joinpath("requirements.txt").write_text("dependency\n", encoding="utf-8")
    for directory in (".claude-plugin", "tools", "resources"):
        path = root / directory
        path.mkdir()
        path.joinpath("content.txt").write_text(directory, encoding="utf-8")


def test_runtime_differences_is_empty_for_identical_trees(tmp_path: Path) -> None:
    source = tmp_path / "source"
    runtime = tmp_path / "runtime"
    source.mkdir()
    runtime.mkdir()
    _write_runtime_tree(source)
    _write_runtime_tree(runtime)

    assert runtime_sync.runtime_differences(source, runtime) == []


def test_runtime_differences_names_missing_and_changed_content(tmp_path: Path) -> None:
    source = tmp_path / "source"
    runtime = tmp_path / "runtime"
    source.mkdir()
    runtime.mkdir()
    _write_runtime_tree(source)
    _write_runtime_tree(runtime)
    runtime.joinpath("server.py").write_text("stale\n", encoding="utf-8")
    runtime.joinpath("resources", "content.txt").unlink()

    assert runtime_sync.runtime_differences(source, runtime) == [
        "content differs: server.py",
        "content differs: resources/content.txt",
    ]
