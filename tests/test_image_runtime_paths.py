"""Does every path server.py opens actually reach the image?

Why this suite exists: the version fix started reading
`.claude-plugin/plugin.json` and raises RuntimeError when it cannot find it --
correct behaviour, no silent fallback. But `.dockerignore` excluded that
directory. The result: the image BUILDS, the test suite is GREEN, and the
server never starts inside the container.

    FileNotFoundError: [Errno 2] No such file or directory:
        '/app/.claude-plugin/plugin.json'

The existing `test_image_contents.py` could not catch this because it READS
the Dockerfile -- it verifies the COPY lines but does not know `.dockerignore`
takes them back. Two files cancelled each other out and both looked correct
on their own.

This suite measures on two axes:
  1. static -- every repo-relative path server.py opens must reach the image
               (a COPY exists AND .dockerignore does not revoke it)
  2. live   -- if docker is available, perform a real `initialize` handshake;
               a green build proves nothing about the server starting

Axis 2 is SKIPPED when docker is absent, but the skip is not silent: the
reason is spelled out.
"""

from __future__ import annotations

import ast
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / "Dockerfile"
DOCKERIGNORE = ROOT / ".dockerignore"


def _literal_paths_opened_by(src: Path) -> set[str]:
    """Collect repo-relative literal paths built inside `src`.

    Catches expressions like `ROOT / ".claude-plugin" / "plugin.json"`. It does
    NOT catch dynamically assembled paths -- this is a guard against a known
    failure mode repeating, not a completeness claim.
    """
    tree = ast.parse(src.read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.BinOp) or not isinstance(node.op, ast.Div):
            continue
        parts: list[str] = []
        cur: ast.expr = node
        while isinstance(cur, ast.BinOp) and isinstance(cur.op, ast.Div):
            if isinstance(cur.right, ast.Constant) and isinstance(cur.right.value, str):
                parts.insert(0, cur.right.value)
            cur = cur.left
        # Accept ANY root: `ROOT / "a"` and
        # `Path(__file__).resolve().parent / "a" / "b"` mean the same thing.
        #
        # The first version only accepted an `ast.Name` root, and server.py's
        # real line starts with an `ast.Call` chain. The scanner returned an
        # EMPTY set, so the test stayed green while the defect was live. The
        # mutation check caught it: removing the negative rule turned ONLY the
        # other test red, not this one.
        if parts:
            found.add("/".join(parts))
    return found


def _dockerignore_blocks(rel: str) -> bool:
    """Does `.dockerignore` exclude this path (negative rules considered)?"""
    if not DOCKERIGNORE.exists():
        return False
    blocked = False
    for raw in DOCKERIGNORE.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        neg = line.startswith("!")
        pat = line.lstrip("!").rstrip("/")
        if rel == pat or rel.startswith(pat + "/"):
            blocked = not neg
    return blocked


def test_server_literal_paths_reach_the_image() -> None:
    """Every literal path server.py opens MUST be present in the image."""
    server = ROOT / "server.py"
    assert server.exists()
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")

    for rel in sorted(_literal_paths_opened_by(server)):
        # `is_file()`, not `exists()`: the scanner also yields intermediate
        # steps of a `ROOT / "a" / "b"` chain (such as `.claude-plugin`). That
        # directory is excluded on purpose -- only `plugin.json` is let back
        # in. Checking the directory too made this test fail on its own
        # correct configuration.
        if not (ROOT / rel).is_file():
            continue
        top = rel.split("/")[0]
        copied = f"COPY {rel}" in dockerfile or f"COPY {top}/" in dockerfile
        assert copied, (
            f"server.py opens '{rel}' but the Dockerfile does not COPY it. "
            "The image builds; the server does not start."
        )
        assert not _dockerignore_blocks(rel), (
            f"The Dockerfile COPYs '{rel}' but .dockerignore takes it back. "
            "The two files cancel out; each one looks correct in isolation."
        )


def test_plugin_json_is_reachable_and_has_version() -> None:
    """The concrete case: the single source of the version."""
    pj = ROOT / ".claude-plugin" / "plugin.json"
    assert pj.exists(), "plugin.json missing -- the version source is gone"
    assert json.loads(pj.read_text(encoding="utf-8")).get("version"), "empty version"
    assert not _dockerignore_blocks(".claude-plugin/plugin.json"), (
        ".dockerignore excludes plugin.json -- the server will not start in the container"
    )


@pytest.mark.skipif(shutil.which("docker") is None,
                    reason="docker absent: live handshake NOT MEASURED (static axis did run)")
def test_container_starts_and_announces_version() -> None:
    """A green build does not prove the server STARTS -- run it."""
    tag = "wrg-sigma-rules-mcp:pytest"
    build = subprocess.run(["docker", "build", "-q", "-t", tag, str(ROOT)],
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=900, check=False,
                           stdin=subprocess.DEVNULL)
    if build.returncode != 0:
        pytest.skip(f"docker build could not run (daemon may be down): {build.stderr[-200:]}")

    req = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                   "clientInfo": {"name": "pytest", "version": "0"}},
    })
    run = subprocess.run(["docker", "run", "-i", "--rm", tag],
                         input=req + "\n", capture_output=True, text=True,
                         encoding="utf-8", errors="replace", timeout=120, check=False)
    assert '"result"' in run.stdout, (
        f"server did not complete the handshake (rc={run.returncode}):\n{run.stderr[-800:]}"
    )
    info = json.loads(run.stdout.splitlines()[0])["result"]["serverInfo"]
    assert info["version"], "serverInfo.version is EMPTY -- version is not announced"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
