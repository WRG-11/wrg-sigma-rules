"""No rule may repeat a mapping key.

YAML allows a duplicate key to parse, and PyYAML (therefore pySigma and this
repository's own validation) silently keeps only the last value. Three rules
lost part of their detection that way: a selection listed
`cs-uri-stem|contains` twice, so the first condition vanished and the rule
matched far more than it was written to. RSigma rejects such files, which is
how they were found; this test makes the same check part of this repository's
CI.

Scope: every YAML document in every rule file and sidecar sample under
resources/examples/. It does NOT judge whether two differently named keys are
redundant.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest
import yaml

pytestmark = pytest.mark.unit

_EXAMPLES = Path(__file__).resolve().parents[1] / "resources" / "examples"


class _StrictLoader(yaml.SafeLoader):
    """SafeLoader that raises on a repeated key instead of keeping the last one."""


def _construct_mapping(loader: _StrictLoader, node: yaml.MappingNode, deep: bool = False):
    keys = [loader.construct_object(key_node, deep=deep) for key_node, _ in node.value]
    repeated = sorted(str(k) for k, n in Counter(keys).items() if n > 1)
    if repeated:
        raise yaml.constructor.ConstructorError(
            None, None, f"duplicate key(s) {repeated}", node.start_mark
        )
    return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)


_StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


def _duplicates_in(text: str) -> str | None:
    try:
        for _ in yaml.load_all(text, Loader=_StrictLoader):
            pass
    except yaml.constructor.ConstructorError as exc:
        return str(exc.problem)
    return None


def test_no_rule_file_repeats_a_mapping_key() -> None:
    offenders = []
    for path in sorted(_EXAMPLES.rglob("*.yml")):
        problem = _duplicates_in(path.read_text(encoding="utf-8"))
        if problem:
            offenders.append((path.relative_to(_EXAMPLES).as_posix(), problem))
    assert not offenders, offenders


def test_strict_loader_catches_the_shape_that_slipped_through() -> None:
    """Canary: the exact shape of the defect, and a legitimate neighbour."""
    broken = "detection:\n  sel:\n    cs-uri-stem|contains: /knowledge/\n    cs-uri-stem|contains: /sync\n"
    fixed = "detection:\n  sel:\n    cs-uri-stem|contains|all:\n    - /knowledge/\n    - /sync\n"
    assert _duplicates_in(broken) is not None
    assert _duplicates_in(fixed) is None
    # PyYAML's default behaviour, which is why this test exists at all
    assert yaml.safe_load(broken)["detection"]["sel"] == {"cs-uri-stem|contains": "/sync"}
