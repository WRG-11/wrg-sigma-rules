"""The image must contain every path the server reads at runtime.

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
TESTS_WORKFLOW = REPO / ".github" / "workflows" / "tests.yml"
PUBLISH_WORKFLOW = REPO / ".github" / "workflows" / "publish-image.yml"
README_STAMP_WORKFLOW = REPO / ".github" / "workflows" / "readme-stamp.yml"

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


def _runtime_paths() -> set[str]:
    """Repo-root-relative paths the runtime code resolves.

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
    source_files = [REPO / "server.py", *sorted((REPO / "tools").rglob("*.py"))]
    for py in source_files:
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
    # AST visits both the full path expression and every inner ``/`` node.
    # Keep only leaves: ``.claude-plugin`` is an intermediate component of
    # ``.claude-plugin/plugin.json``, not a separately-read runtime path.
    return {
        path for path in found
        if not any(other.startswith(path + "/") for other in found)
    }


def _is_ignored_by_build_context(path: str) -> bool:
    """Evaluate the simple literal .dockerignore rules used by this image."""
    ignored = False
    for line in DOCKERIGNORE.read_text(encoding="utf-8").splitlines():
        rule = line.strip().rstrip("/")
        if not rule or rule.startswith("#"):
            continue
        include = rule.startswith("!")
        rule = rule.removeprefix("!")
        if path == rule or path.startswith(rule + "/"):
            ignored = not include
    return ignored


def test_build_context_honors_the_manifest_reinclude_rule() -> None:
    """The one runtime manifest is intentionally re-included after its parent."""
    assert not _is_ignored_by_build_context(".claude-plugin/plugin.json")
    assert _is_ignored_by_build_context(".claude-plugin/other.json")
    assert _is_ignored_by_build_context("skills/sigma-rule-writer/SKILL.md")


@pytest.mark.parametrize("path", sorted(_runtime_paths()))
def test_every_runtime_path_is_copied_into_the_image(path: str) -> None:
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
    for path in sorted(_runtime_paths()):
        assert not _is_ignored_by_build_context(path), (
            f".dockerignore excludes {path!r}, so its Dockerfile COPY brings "
            f"in nothing. Narrow the ignore rule or drop it."
        )


def test_base_image_is_digest_pinned() -> None:
    """The Docker base must be reproducible rather than follow a mutable tag."""
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    assert re.search(
        r"^FROM python:3\.12-slim@sha256:[0-9a-f]{64}$",
        dockerfile,
        flags=re.MULTILINE,
    ), "Dockerfile must pin python:3.12-slim to a sha256 digest"


def test_ci_container_smokes_keep_the_runtime_filesystem_read_only() -> None:
    """Both pre-merge and pre-publish MCP checks must prove no app write need."""
    expected_run = (
        "docker run -i --rm --read-only "
        "--tmpfs /tmp:rw,noexec,nosuid,size=16m"
    )
    for workflow in (TESTS_WORKFLOW, PUBLISH_WORKFLOW):
        assert expected_run in workflow.read_text(encoding="utf-8"), (
            f"{workflow.name} MCP smoke must run with a read-only rootfs and "
            "a narrowly scoped temporary filesystem"
        )


def test_release_smoke_checks_the_checkout_corpus_identity() -> None:
    """Do not publish an image whose live resource differs from its source."""
    workflow = PUBLISH_WORKFLOW.read_text(encoding="utf-8")
    assert "collect_coverage()['corpus_sha256']" in workflow
    assert "--expect-corpus-fingerprint \"$EXPECTED_FINGERPRINT\"" in workflow


def test_workflow_actions_are_pinned_to_immutable_commit_shas() -> None:
    """A mutable action tag must not enter the public CI supply chain."""
    for workflow in sorted((REPO / ".github" / "workflows").glob("*.yml")):
        actions = re.findall(
            r"^\s*(?:-\s+)?uses:\s*([^\s#]+)",
            workflow.read_text(encoding="utf-8"),
            flags=re.MULTILINE,
        )
        assert actions, f"{workflow.name} has no action references to inspect"
        for action in actions:
            assert re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", action), (
                f"{workflow.name} action is not pinned to a full commit SHA: {action}"
            )


def test_readme_stamp_write_job_is_main_and_readme_scoped() -> None:
    """The sole contents-write job must not write a caller-selected ref."""
    workflow = README_STAMP_WORKFLOW.read_text(encoding="utf-8")
    assert "if: github.ref == 'refs/heads/main'" in workflow
    assert "git add README.md" in workflow
    assert "git push origin HEAD:main" in workflow
    assert "git add ." not in workflow
    assert "git add -A" not in workflow


def test_ci_keeps_both_declared_mcp_sdk_compatibility_legs() -> None:
    """Do not reduce the MCP 1.x/2.x support claim to one untested major."""
    workflow = TESTS_WORKFLOW.read_text(encoding="utf-8")
    assert 'mcp-version: ["<2", ">=2"]' in workflow
    assert 'pip install "mcp${{ matrix.mcp-version }}"' in workflow


def test_the_probe_finds_known_runtime_paths() -> None:
    """Control arm: the two tests above pass trivially if the AST walk finds
    nothing. Pin the one directory we know is read at runtime, so an extraction
    that silently stops working fails here instead of going quiet."""
    paths = _runtime_paths()
    assert "resources/examples" in paths, (
        f"the coverage resource resolves resources/examples from __file__; "
        f"the probe found {sorted(paths)}"
    )
    assert ".claude-plugin/plugin.json" in paths, (
        "server.py resolves the manifest from __file__; the image must copy it"
    )
    assert not (paths & _SOURCE_TREES), "source trees are copied wholesale, not derived"
