"""Regression tests for local, read-only Codex runtime identity checks."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "runtime_identity.py"
SPEC = importlib.util.spec_from_file_location("runtime_identity", SCRIPT)
assert SPEC and SPEC.loader
identity = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(identity)


def _runtime(root: Path, *, version: str = "1.0.0", body: str = "rule") -> Path:
    (root / ".claude-plugin").mkdir(parents=True)
    (root / ".claude-plugin" / "plugin.json").write_text(
        json.dumps({"version": version}), encoding="utf-8"
    )
    rule = root / "resources" / "examples" / "execution" / "rule.yml"
    rule.parent.mkdir(parents=True)
    rule.write_text(body, encoding="utf-8")
    return root


def test_runtime_identity_measures_manifest_and_path_content_digest(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path / "runtime")

    result = identity.runtime_identity(runtime)

    assert result["manifest_version"] == "1.0.0"
    assert result["rule_count"] == 1
    assert len(result["rule_tree_sha256"]) == 64


def test_runtime_identity_digest_changes_for_rule_bytes_or_paths(tmp_path: Path) -> None:
    first = _runtime(tmp_path / "first", body="first")
    second = _runtime(tmp_path / "second", body="second")

    assert identity.rule_tree_fingerprint(first) != identity.rule_tree_fingerprint(second)


def test_runtime_identity_rejects_missing_manifest_or_corpus(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="cannot read runtime manifest"):
        identity.runtime_identity(tmp_path)

    empty = tmp_path / "empty"
    (empty / ".claude-plugin").mkdir(parents=True)
    (empty / ".claude-plugin" / "plugin.json").write_text(
        '{"version": "1"}', encoding="utf-8"
    )
    with pytest.raises(ValueError, match="no published corpus rules"):
        identity.runtime_identity(empty)


def test_same_identity_requires_version_count_and_digest() -> None:
    baseline = {"manifest_version": "1", "rule_count": 1, "rule_tree_sha256": "a"}
    assert identity._same_identity(baseline, dict(baseline))
    assert not identity._same_identity(baseline, {**baseline, "rule_count": 2})
