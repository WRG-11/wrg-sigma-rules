"""Refresh or verify the self-contained Codex plugin runtime.

Run this before committing changes to ``server.py``, ``tools/``, ``resources/``
or ``requirements.txt`` that must also reach installed Codex plugins. The
matching regression test prevents a stale runtime from being published.
"""
from __future__ import annotations

import argparse
import hashlib
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "plugins" / "wrg-sigma-rules" / "runtime"
FILES = ("server.py", "requirements.txt")
DIRECTORIES = (".claude-plugin", "tools", "resources")


def _tree_hashes(root: Path) -> dict[Path, str]:
    """Return content hashes without treating a snapshot as trustworthy."""
    if not root.is_dir():
        return {}
    return {
        path.relative_to(root): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in root.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts
    }


def runtime_differences(root: Path = ROOT, runtime: Path = RUNTIME) -> list[str]:
    """List canonical/runtime mismatches suitable for a CI or release gate."""
    differences: list[str] = []
    for name in FILES:
        source = root / name
        copied = runtime / name
        if not copied.is_file():
            differences.append(f"missing runtime file: {name}")
        elif source.read_bytes() != copied.read_bytes():
            differences.append(f"content differs: {name}")
    for name in DIRECTORIES:
        source_hashes = _tree_hashes(root / name)
        runtime_hashes = _tree_hashes(runtime / name)
        for path in sorted(set(source_hashes).union(runtime_hashes)):
            if source_hashes.get(path) != runtime_hashes.get(path):
                differences.append(f"content differs: {name}/{path.as_posix()}")
    return differences


def sync_runtime(root: Path = ROOT, runtime: Path = RUNTIME) -> None:
    """Replace the generated snapshot with the canonical runtime inputs."""
    if runtime.exists():
        shutil.rmtree(runtime)
    runtime.mkdir(parents=True)
    for name in FILES:
        shutil.copy2(root / name, runtime / name)
    for name in DIRECTORIES:
        shutil.copytree(root / name, runtime / name)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify runtime parity without modifying the snapshot",
    )
    args = parser.parse_args(argv)

    if args.check:
        differences = runtime_differences()
        if differences:
            print("Codex runtime is stale:")
            for difference in differences:
                print(f"  - {difference}")
            return 1
        print(f"Codex runtime is in sync: {RUNTIME}")
        return 0

    sync_runtime()
    print(f"Synced Codex runtime: {RUNTIME}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
