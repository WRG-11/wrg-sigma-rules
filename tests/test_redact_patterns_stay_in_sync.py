"""Sync guard: the 3 tools' OPSEC redaction pattern-sets must stay identical.

draft_rule.py / validate_rule.py / convert_rule.py each keep their own copy
of ``_REDACT_PATTERNS`` (RFC1918 IPs, email, internal-domain suffixes) --
*intentionally* duplicated per each module's own comment ("Kept inline so
convert_rule is runnable in isolation (no cross-tool import) -- mirrors the
canonical_patterns_resource.py 'module-isolated' convention"). This test
does not challenge that isolation choice; it closes the one real risk it
leaves open -- silent drift between the 3 copies over time, so a future edit
to one tool's redaction rules quietly stops applying to a sibling tool.

This exact failure class has already happened once in a sibling WRG project
(apps/<wrg-app>/validate.py's own docstring: two independent copies
of a domain-shape gate drifted, one kept embedding a raw tab into a live
RDAP URL for weeks after the other was fixed). Cheap prevention here: fail
loudly the moment the 3 copies disagree, before it ships.
"""
from __future__ import annotations

import sys
from pathlib import Path

_PLUGIN_ROOT = Path(__file__).resolve().parent.parent
if str(_PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(_PLUGIN_ROOT))

from tools.convert_rule.convert_rule import _REDACT_PATTERNS as _CONVERT_PATTERNS  # noqa: E402
from tools.draft_rule.draft_rule import _REDACT_PATTERNS as _DRAFT_PATTERNS  # noqa: E402
from tools.validate_rule.validate_rule import _REDACT_PATTERNS as _VALIDATE_PATTERNS  # noqa: E402


def _shape(patterns: tuple) -> list[tuple[str, int, str]]:
    """Reduce a ``_REDACT_PATTERNS`` tuple to a comparable (pattern-string,
    flags, placeholder) list -- ``re.Pattern`` objects from independently
    compiled sources are not otherwise meaningfully comparable."""
    return [(p.pattern, p.flags, placeholder) for p, placeholder in patterns]


def test_all_three_tools_have_the_same_redact_pattern_set() -> None:
    draft = _shape(_DRAFT_PATTERNS)
    validate = _shape(_VALIDATE_PATTERNS)
    convert = _shape(_CONVERT_PATTERNS)

    assert draft == validate, (
        "draft_rule._REDACT_PATTERNS and validate_rule._REDACT_PATTERNS have "
        "drifted apart -- a rule drafted by one tool may not be flagged the "
        "same way by the other. Sync both copies (the duplication itself is "
        "intentional, see module docstrings; only drift is the bug)."
    )
    assert draft == convert, (
        "draft_rule._REDACT_PATTERNS and convert_rule._REDACT_PATTERNS have "
        "drifted apart -- a rule drafted by one tool may not be flagged the "
        "same way when converted. Sync both copies (the duplication itself "
        "is intentional, see module docstrings; only drift is the bug)."
    )
