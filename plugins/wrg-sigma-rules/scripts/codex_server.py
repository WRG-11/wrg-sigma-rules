"""Start the self-contained stdio MCP runtime bundled with the Codex plugin."""
from __future__ import annotations

import sys
from pathlib import Path


def _runtime_root() -> Path:
    runtime = Path(__file__).resolve().parents[1] / "runtime"
    if (runtime / "server.py").is_file() and (runtime / "tools").is_dir():
        return runtime
    raise RuntimeError("WRG Sigma Rules Codex runtime is incomplete")


def main() -> int:
    runtime = _runtime_root()
    sys.path.insert(0, str(runtime))
    from server import main as server_main

    return server_main()


if __name__ == "__main__":
    raise SystemExit(main())
