"""Start the repository's shared stdio MCP server from the Codex plugin."""
from __future__ import annotations

import sys
from pathlib import Path


def _repository_root() -> Path:
    for parent in Path(__file__).resolve().parents:
        if (parent / "server.py").is_file() and (parent / "tools").is_dir():
            return parent
    raise RuntimeError("WRG Sigma Rules repository root was not found")


def main() -> int:
    root = _repository_root()
    sys.path.insert(0, str(root))
    from server import main as server_main

    return server_main()


if __name__ == "__main__":
    raise SystemExit(main())
