"""The image must contain every directory the server reads at runtime.

2026-07-30: the published image answered its own MITRE coverage resource with
``{"ok": false, "error": "rule corpus directory not found"}``. Nothing was
broken in the usual sense -- the Docker build succeeded, the container started,
the MCP handshake completed, ``tools/list`` and ``resources/list`` answered.
The image simply did not contain ``resources/examples/``, because
``.dockerignore`` excluded it and its comment said the image "only needs
server.py + tools/ + requirements.txt". That comment was true when it was
written and stopped being true when a resource that reads the corpus was added.

A comment cannot notice that. This test derives the answer from the code: it
finds the repo-root-relative directories the runtime modules resolve, and
asserts the Dockerfile copies each one. Add a resource that reads a new
directory and forget the COPY, and this fails before the image ships.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
DOCKERFILE = REPO / "Dockerfile"
DOCKERIGNORE = REPO / ".dockerignore"

#: Top-level names that are source, not runtime data -- copied as whole trees.
_SOURCE_TREES = {"tools"}


def _copied_paths() -> list[str]:
    """Source paths named by ``COPY`` in the Dockerfile, normalised."""
    out: list[str] = []
    for line in DOCKERFILE.read_text(encoding="utf-8").splitlines():
        m = re.match(r"\s*COPY\s+(?:--\S+\s+)*(\S+)\s+(\S+)\s*$", line)
        if m:
            out.append(m.group(1).rstrip("/"))
    return out


def _runtime_dirs() -> set[str]:
    """Repo-root-relative directories the runtime code resolves.

    Matches the shape the modules actually use -- walking up from ``__file__``
    with ``.parent`` and then joining literal segments:

        Path(__file__).resolve().parent.parent.parent / "resources" / "examples"

    Only the literal segments matter here; how many parents were walked is the
    module's own business, and a wrong count is a bug this test cannot see.
    """
    def segments(node: ast.AST) -> list[str]:
        """Literal path segments of a ``/`` chain, in SOURCE order.

        Flattened left-then-right by hand. ``ast.walk`` is breadth-first, so
        it yields the outermost segment first and reading it directly produced
        ``examples/resources`` -- a path that exists nowhere, and one the
        assertion would have reported as missing for the wrong reason.
        """
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            return segments(node.left) + segments(node.right)
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return [node.value]
        return []

    found: set[str] = set()
    for py in sorted((REPO / "tools").rglob("*.py")):
        try:
            tree = ast.parse(py.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:  # pragma: no cover - a parse failure is its own test's job
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.BinOp) or not isinstance(node.op, ast.Div):
                continue
            if "__file__" not in ast.dump(node):
                continue
            segs = segments(node)
            if segs:
                found.add("/".join(segs))
    return found


@pytest.mark.parametrize("path", sorted(_runtime_dirs()))
def test_every_runtime_directory_is_copied_into_the_image(path: str) -> None:
    copied = _copied_paths()
    assert any(path == c or path.startswith(c + "/") or c.startswith(path + "/")
               for c in copied), (
        f"{path!r} is resolved from a module under tools/ but no COPY in the "
        f"Dockerfile brings it into the image. COPY lines: {copied}. "
        f"An absent directory does not fail the build -- the resource that "
        f"reads it answers ok:false and the image ships looking healthy."
    )


def test_the_rule_corpus_is_not_excluded_from_the_build_context() -> None:
    """A COPY cannot bring in what .dockerignore filtered out first.

    Both halves are needed and they live in different files, which is exactly
    how the original defect survived: the COPY list looked deliberate and the
    ignore list looked deliberate, and neither mentioned the other.
    """
    ignored = [ln.strip().rstrip("/") for ln in
               DOCKERIGNORE.read_text(encoding="utf-8").splitlines()
               if ln.strip() and not ln.lstrip().startswith("#")]
    for path in sorted(_runtime_dirs()):
        head = path.split("/")[0]
        assert head not in ignored, (
            f".dockerignore excludes {head!r}, so the COPY of {path!r} brings "
            f"in nothing. Narrow the ignore rule or drop it."
        )


def test_the_probe_finds_the_known_runtime_directory() -> None:
    """Control arm: the two tests above pass trivially if the AST walk finds
    nothing. Pin the one directory we know is read at runtime, so an extraction
    that silently stops working fails here instead of going quiet."""
    dirs = _runtime_dirs()
    assert "resources/examples" in dirs, (
        f"the coverage resource resolves resources/examples from __file__; "
        f"the probe found {sorted(dirs)}"
    )
    assert not (dirs & _SOURCE_TREES), "source trees are copied wholesale, not derived"
