"""Refresh the self-contained Codex plugin runtime from canonical sources.

Run this before committing changes to ``server.py``, ``tools/``, ``resources/``
or ``requirements.txt`` that must also reach installed Codex plugins. The
matching regression test prevents a stale runtime from being published.
"""
from __future__ import annotations

import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "plugins" / "wrg-sigma-rules" / "runtime"
FILES = ("server.py", "requirements.txt")
DIRECTORIES = (".claude-plugin", "tools", "resources")


def main() -> int:
    if RUNTIME.exists():
        shutil.rmtree(RUNTIME)
    RUNTIME.mkdir(parents=True)
    for name in FILES:
        shutil.copy2(ROOT / name, RUNTIME / name)
    for name in DIRECTORIES:
        shutil.copytree(ROOT / name, RUNTIME / name)
    print(f"Synced Codex runtime: {RUNTIME}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
