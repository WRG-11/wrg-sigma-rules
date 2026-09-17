"""Start the self-contained stdio MCP runtime bundled with the Codex plugin."""
from __future__ import annotations

import sys
from pathlib import Path


def _runtime_root(script_path: Path | None = None) -> Path:
    """Return a complete package-local runtime, never a checkout-relative one."""
    script = script_path if script_path is not None else Path(__file__)
    runtime = script.resolve().parents[1] / "runtime"
    required_files = ("server.py", "requirements.txt", ".claude-plugin/plugin.json")
    required_directories = ("tools", "resources")
    if all((runtime / path).is_file() for path in required_files) and all(
        (runtime / path).is_dir() for path in required_directories
    ):
        return runtime
    raise RuntimeError("WRG Sigma Rules Codex runtime is incomplete")


def main() -> int:
    runtime = _runtime_root()
    sys.path.insert(0, str(runtime))
    from server import main as server_main

    return server_main()


if __name__ == "__main__":
    raise SystemExit(main())
