#!/usr/bin/env python3
"""Measure a bundled Codex runtime's manifest and corpus identity.

This is a local, read-only diagnostic for comparing a checkout with an
installed or cached Codex runtime.  It does not contact a marketplace, refresh
any client cache, or treat matching bytes as publication evidence.

Examples:
    python scripts/runtime_identity.py
    python scripts/runtime_identity.py --runtime-root C:/path/to/plugin/runtime
    python scripts/runtime_identity.py --runtime-root C:/path/to/plugin/runtime \
        --expect-same-as .
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
RULE_GLOBS = ("resources/examples/**/*.yml", "resources/examples/**/*.yaml")


def _rule_files(root: Path) -> list[Path]:
    files: set[Path] = set()
    for pattern in RULE_GLOBS:
        files.update(root.glob(pattern))
    return sorted(files, key=lambda path: path.relative_to(root).as_posix())


def corpus_fingerprint(root: Path) -> str:
    """Return a path-and-content digest for the complete published corpus."""
    digest = hashlib.sha256()
    for path in _rule_files(root):
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def runtime_identity(root: Path) -> dict[str, Any]:
    """Measure a runtime without assuming that it is current or published."""
    manifest_path = root / ".claude-plugin" / "plugin.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read runtime manifest: {manifest_path}") from exc

    version = manifest.get("version") if isinstance(manifest, dict) else None
    if not isinstance(version, str) or not version.strip():
        raise ValueError("runtime manifest has no non-empty version")

    rules = _rule_files(root)
    if not rules:
        raise ValueError(f"runtime has no published corpus rules: {root}")

    return {
        "runtime_root": str(root.resolve()),
        "manifest_version": version,
        "rule_count": len(rules),
        "corpus_sha256": corpus_fingerprint(root),
    }


def _same_identity(left: dict[str, Any], right: dict[str, Any]) -> bool:
    """Compare the fields that identify the loaded runtime and corpus."""
    return all(
        left[name] == right[name]
        for name in ("manifest_version", "rule_count", "corpus_sha256")
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--runtime-root",
        type=Path,
        default=ROOT,
        help="runtime directory to inspect (default: this checkout)",
    )
    parser.add_argument(
        "--expect-same-as",
        type=Path,
        metavar="CHECKOUT",
        help="fail when the inspected runtime differs from this checkout",
    )
    args = parser.parse_args(argv)

    try:
        runtime = runtime_identity(args.runtime_root)
        result: dict[str, Any] = {"runtime": runtime}
        if args.expect_same_as is not None:
            expected = runtime_identity(args.expect_same_as)
            result["expected"] = expected
            result["matches_expected"] = _same_identity(runtime, expected)
        print(json.dumps(result, indent=2, sort_keys=True))
    except ValueError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 2

    if args.expect_same_as is not None and not result["matches_expected"]:
        print("FAIL: runtime identity differs from expected checkout", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
