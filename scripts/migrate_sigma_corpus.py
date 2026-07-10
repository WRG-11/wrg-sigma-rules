"""Migrate WRG sigma rule corpus to plugin resources/examples.

One-shot helper for the sigma-corpus migration ship. Reads WRG threat-intel sigma sources
and renders ~50 canonical sigma example rules into
``internal plus an
INDEX.json with 3-dimensional indexing (MITRE ATT&CK tactic +
detection_type + target_platform).

Sources (V_api_shape Rule 2 pre-write reads):

* ``internal
  -- ``TECHNIQUE_PATTERN_LIBRARY`` (37 technique-keyed curated patterns).
  Rendered as synthetic exemplars (no actor binding; status experimental).
* ``internal
  -- 6 observed actor-bound goldens (alphv + lapsus + lockbit +
  nullsec_nigeria).
* ``internal
  -- 2 observed OFAC sanction goldens.
* ``apps/wrg_ai_fingerprint_sigma/tests/fixtures/expected_sigma_output.yml``
  -- 5 detector goldens (multi-doc YAML).

LLM-safe redaction discipline (OPSEC redactions applied):

1. ``WRG-[A-Z0-9-]+`` -> ``WRG-INTERNAL`` (actor catalog ID redact).
2. ``apps/wrg_[a-z_]+`` -> ``apps/<wrg-app>`` (internal path redact).
3. ``AKIA[0-9A-Z]{16}`` / ``gh[ps]_[A-Za-z0-9]{36,}`` /
   ``sk-[A-Za-z0-9]{20,}`` -> ``<PII_REDACTED>`` (key regex sweep).
4. Non-ASCII chars normalised (em-dash -> ``--``, smart quotes ->
   straight quotes); final ``encode('ascii')`` round-trip verify.
5. Internal delivery-gate names, pattern-catalog version tags, and
   sibling-module identifiers -> genericised (taxonomy redact, added
   after a 2026-07-08 public-repo content audit found these leaking
   into rendered rule text).

Char cap per rule <= 2000 (verbose rules truncated with warning).

Idempotent: re-running overwrites outputs deterministically (uuid5
namespaces match the source modules so rule IDs stay stable).

Usage::

    cd <repo-clone-path>
    py -3 internal script writes to
``internal plus
``resources/examples/INDEX.json``; canonical pattern catalog is
written separately (see ``scripts/render_canonical_patterns.py``).
"""
from __future__ import annotations

import json
import re
import sys
import uuid
from pathlib import Path
from typing import Any

import yaml


# ---------------------------------------------------------------------------
# Path config
# ---------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parent.parent.parent.parent  # repo root
WRG_THREAT_INTEL_SRC = ROOT / "apps" / "wrg_threat_intel" / "src"
WRG_AI_FP_SIGMA_SRC = ROOT / "apps" / "wrg_ai_fingerprint_sigma" / "src"
PLUGIN_RESOURCES = ROOT / "plugins" / "wrg-sigma-rules" / "resources"
EXAMPLES_DIR = PLUGIN_RESOURCES / "examples"

# Add wrg_threat_intel + wrg_ai_fingerprint_sigma to sys.path for import.
sys.path.insert(0, str(WRG_THREAT_INTEL_SRC))
sys.path.insert(0, str(WRG_AI_FP_SIGMA_SRC))


# ---------------------------------------------------------------------------
# LLM-safe redaction discipline (OPSEC redactions applied)
# ---------------------------------------------------------------------------

# WRG-NN (pure digits) is the public GitHub org name (WRG-11) -- legitimate
# public attribution, NOT redacted. WRG-<actual-id-pattern> (mixed
# alphanumeric beyond digits) IS internal and gets redacted.
_WRG_INTERNAL_ID_RE = re.compile(r"WRG-(?!\d+\b)[A-Z][A-Z0-9_-]*")
_INTERNAL_PATH_RE = re.compile(r"apps/wrg_[a-z_]+")
_AWS_KEY_RE = re.compile(r"AKIA[0-9A-Z]{16}")
_GITHUB_PAT_RE = re.compile(r"gh[ps]_[A-Za-z0-9]{36,}")
_OPENAI_KEY_RE = re.compile(r"sk-[A-Za-z0-9]{20,}")
# Content-audit follow-up: internal delivery-gate naming, the
# pattern-catalog internal version tag, and sibling monorepo module names
# leak into rendered rule text same as secrets/IDs above -- redact them too.
_DELIVERY_GATE_RE = re.compile(r"Layer 4 G\d")
_PATTERN_VERSION_RE = re.compile(r"Pattern \d+ v\d(?:\.\d+)?")
_SIBLING_MODULE_RE = re.compile(r"\b(?:breach_corpus|llm_incident\w*|wrg_mcp_server)\b")

_ASCII_NORMALISE = {
    "—": "--",   # em-dash
    "–": "-",    # en-dash
    "‘": "'",    # left single quote
    "’": "'",    # right single quote
    "“": '"',    # left double quote
    "”": '"',    # right double quote
    "…": "...",  # ellipsis
}

CHAR_CAP_PER_RULE = 4000  # 2000 was too tight for verbose rules; bumped to 4000.


def redact_llm_safe(text: str) -> str:
    """Apply 4-rule LLM-safe redaction discipline."""
    out = text
    out = _WRG_INTERNAL_ID_RE.sub("WRG-INTERNAL", out)
    out = _INTERNAL_PATH_RE.sub("apps/<wrg-app>", out)
    out = _AWS_KEY_RE.sub("<PII_REDACTED>", out)
    out = _GITHUB_PAT_RE.sub("<PII_REDACTED>", out)
    out = _OPENAI_KEY_RE.sub("<PII_REDACTED>", out)
    out = _DELIVERY_GATE_RE.sub("detection layer", out)
    out = _PATTERN_VERSION_RE.sub("OPSEC redaction applied", out)
    out = _SIBLING_MODULE_RE.sub("<wrg-sibling-module>", out)
    for src, dst in _ASCII_NORMALISE.items():
        out = out.replace(src, dst)
    # Final encoding round-trip verify (strip remaining non-ASCII)
    out = out.encode("ascii", errors="replace").decode("ascii")
    return out


def is_url_broken_post_redaction(url: str) -> bool:
    """Return True if a URL contains redaction placeholders + would be broken."""
    return any(
        marker in url
        for marker in ("WRG-INTERNAL", "<wrg-app>", "<PII_REDACTED>")
    )


def redact_doc_recursive(obj: Any) -> Any:
    """Recursively redact dict/list/string values; drop broken URLs in lists."""
    if isinstance(obj, str):
        return redact_llm_safe(obj)
    if isinstance(obj, list):
        out: list[Any] = []
        for item in obj:
            new_item = redact_doc_recursive(item)
            # Drop URLs that became broken post-redaction.
            if isinstance(new_item, str) and new_item.startswith(("http://", "https://")):
                if is_url_broken_post_redaction(new_item):
                    continue
            out.append(new_item)
        return out
    if isinstance(obj, dict):
        return {k: redact_doc_recursive(v) for k, v in obj.items()}
    return obj


# ---------------------------------------------------------------------------
# Categorization tables (MITRE ATT&CK tactic + detection_type + platform)
# ---------------------------------------------------------------------------

# MITRE ATT&CK technique -> tactic primary mapping. Multi-tactic techniques
# (e.g. T1078 spans initial_access + persistence + defense_evasion) are
# assigned their MOST-COMMON tactic for top-level categorization; the rule
# tags carry the full mapping.
TECHNIQUE_TACTIC: dict[str, str] = {
    "T1003": "credential_access",
    "T1110": "credential_access",
    "T1555": "credential_access",
    "T1556": "credential_access",
    "T1552": "credential_access",
    "T1552.001": "credential_access",
    "T1078": "initial_access",
    "T1078.002": "initial_access",
    "T1133": "initial_access",
    "T1190": "initial_access",
    "T1199": "initial_access",
    "T1021.001": "lateral_movement",
    "T1021.002": "lateral_movement",
    "T1195": "initial_access",
    "T1566.001": "initial_access",
    "T1566.002": "initial_access",
    "T1059": "execution",
    "T1059.001": "execution",
    "T1059.006": "execution",
    "T1204.001": "execution",
    "T1082": "discovery",
    "T1027": "defense_evasion",
    "T1027.005": "defense_evasion",
    "T1027.013": "defense_evasion",
    "T1036.005": "defense_evasion",
    "T1656": "defense_evasion",
    "T1656.002": "defense_evasion",
    "T1005": "collection",
    "T1213": "collection",
    "T1486": "impact",
    "T1490": "impact",
    "T1491": "impact",
    "T1567": "exfiltration",
    "T1657": "impact",
    "T1071": "command_and_control",
    "T1071.001": "command_and_control",
    "T1583": "resource_development",
    "T1583.001": "resource_development",
    "T1585": "resource_development",
    "T1585.001": "resource_development",
    "T1588": "resource_development",
    "T1622": "defense_evasion",
}


def resolve_tactic(technique: str) -> str:
    """Map technique -> tactic, with parent fallback."""
    if technique in TECHNIQUE_TACTIC:
        return TECHNIQUE_TACTIC[technique]
    base = technique.split(".", 1)[0]
    return TECHNIQUE_TACTIC.get(base, "other")


# ---------------------------------------------------------------------------
# Rule rendering helpers
# ---------------------------------------------------------------------------

PLUGIN_NAMESPACE = uuid.UUID("a7b3c2d1-4e5f-6a7b-8c9d-0e1f2a3b4c5d")


def deterministic_id(seed: str) -> str:
    """Return a deterministic UUIDv5 string for a seed."""
    return str(uuid.uuid5(PLUGIN_NAMESPACE, seed))


def safe_filename(s: str) -> str:
    """Normalise a string into a safe filesystem-friendly slug."""
    s = redact_llm_safe(s).lower()
    s = re.sub(r"[^a-z0-9_]+", "_", s)
    s = re.sub(r"_+", "_", s).strip("_")
    return s[:80]


def write_rule_yaml(category: str, filename: str, rule_doc: dict[str, Any]) -> Path:
    """Write a single sigma rule as YAML under category dir; return path."""
    cat_dir = EXAMPLES_DIR / category
    cat_dir.mkdir(parents=True, exist_ok=True)
    path = cat_dir / filename
    # Recursively redact + drop broken URLs BEFORE yaml dump so em-dashes etc
    # become ASCII substitutes (--) rather than \uXXXX escape sequences in
    # the rendered output.
    safe_doc = redact_doc_recursive(rule_doc)
    yaml_text = yaml.safe_dump(
        safe_doc,
        sort_keys=False,
        allow_unicode=False,
        default_flow_style=False,
        width=120,
    )
    # Second-pass text redact (catches anything yaml.dump added back).
    yaml_text = redact_llm_safe(yaml_text)
    if len(yaml_text) > CHAR_CAP_PER_RULE:
        # Truncate with discipline warning embedded.
        yaml_text = (
            yaml_text[: CHAR_CAP_PER_RULE - 200]
            + "\n# WARNING: Rule truncated to char cap; see full source in WRG corpus.\n"
        )
    path.write_text(yaml_text, encoding="utf-8", newline="\n")
    return path


# ---------------------------------------------------------------------------
# Part A -- 37 TECHNIQUE_PATTERN_LIBRARY template rules
# ---------------------------------------------------------------------------

TECHNIQUE_NAMES: dict[str, str] = {
    "T1003": "OS Credential Dumping (LSASS access, mimikatz)",
    "T1110": "Brute Force (high-volume failed logons)",
    "T1555": "Credentials from Password Stores (browser cred files)",
    "T1556": "Modify Authentication Process (MFA fatigue / ADFS)",
    "T1552": "Unsecured Credentials (multi-vendor printer admin)",
    "T1552.001": "Unsecured Credentials in Files (Kyocera kmaddrbook)",
    "T1078": "Valid Accounts (anomalous remote interactive logon)",
    "T1078.002": "Domain Account Exploitation (noPac CVE-2021-42278/42287)",
    "T1133": "External Remote Services (anomalous LogonType 10)",
    "T1190": "Exploit Public-Facing Application (webshell spawn)",
    "T1199": "Trusted Relationship (third-party/contractor pivot)",
    "T1021.001": "Remote Services (RDP / EventID 4624 LogonType 10)",
    "T1021.002": "Remote Services SMB (admin shares ADMIN$/C$/IPC$)",
    "T1195": "Supply Chain Compromise (untrusted installer execution)",
    "T1566.001": "Spearphishing Attachment (office app child process)",
    "T1566.002": "Spearphishing Link (proxy-side suspicious link)",
    "T1059": "Command and Scripting Interpreter (generic shell spawn)",
    "T1059.001": "PowerShell Encoded Command Execution",
    "T1059.006": "Python Scripting (interpreter spawned by shell)",
    "T1204.001": "User Execution Malicious Link (click follow-through)",
    "T1027": "Obfuscated Files or Information (encoded payload)",
    "T1036.005": "Masquerading Match Legitimate Name (anomalous path)",
    "T1656": "Impersonation (persona-generation tooling on host)",
    "T1656.002": "Impersonation Brand or Personnel (profile setup)",
    "T1071": "Application Layer Protocol (C2 over HTTP/HTTPS)",
    "T1005": "Data from Local System (archive utility staging)",
    "T1213": "Data from Information Repositories (SharePoint access)",
    "T1486": "Data Encrypted for Impact (ransomware extension marker)",
    "T1490": "Inhibit System Recovery (vssadmin shadow copy delete)",
    "T1491": "Defacement (web root content modification)",
    "T1567": "Exfiltration Over Web Service (mega/anonfiles host)",
    "T1657": "Financial Theft (extortion crypto mixer payout)",
    "T1583": "Acquire Infrastructure (newly-registered-domain query)",
    "T1583.001": "Acquire Infrastructure Domains (lookalike domain)",
    "T1585": "Establish Accounts (anomalous account creation burst)",
    "T1585.001": "Establish Accounts Social Media (signup hosts)",
    "T1588": "Obtain Capabilities (threat-intel lookup DNS)",
}


def render_technique_template_rules() -> list[tuple[str, str, dict[str, Any]]]:
    """Render 37 template rules from TECHNIQUE_PATTERN_LIBRARY.

    Returns a list of (category, filename, rule_doc) tuples ready for
    INDEX.json + filesystem write.
    """
    from wrg_threat_intel.breach.sigma.templates import (
        CURATED_FP_WARNING,
        SEVERITY_TO_SIGMA_LEVEL,
        SIGMA_AUTHOR,
        TECHNIQUE_PATTERN_LIBRARY,
        get_detection_block,
        has_aggregation,
        technique_logsource,
        technique_tag,
        technique_url,
    )

    rendered: list[tuple[str, str, dict[str, Any]]] = []
    for technique in sorted(TECHNIQUE_PATTERN_LIBRARY.keys()):
        detection, _curated = get_detection_block(technique)
        logsource = technique_logsource(technique)
        tactic = resolve_tactic(technique)
        name = TECHNIQUE_NAMES.get(technique, f"Template {technique}")
        tags = [
            technique_tag(technique),
            "wrg.template",
            f"wrg.tactic.{tactic}",
        ]
        if has_aggregation(technique):
            tags.append("wrg.correlation")

        rule_doc: dict[str, Any] = {
            "title": f"Template -- {name}",
            "id": deterministic_id(f"template:{technique}"),
            "status": "experimental",
            "description": (
                f"Canonical sigma detection template for MITRE ATT&CK "
                f"{technique} ({name}). Synthetic exemplar from the "
                "WinstonRedGuard threat-intel corpus -- no actor binding; "
                "review and bind to your environment before deployment."
            ),
            "references": [technique_url(technique)],
            "author": "WinstonRedGuard -- sigma plugin canonical templates",
            "date": "2026-05-21",
            "logsource": logsource,
            "detection": detection,
            "falsepositives": [CURATED_FP_WARNING],
            "level": "medium",
            "tags": tags,
        }
        category = tactic
        filename = f"template_{safe_filename(technique)}_{safe_filename(name)}.yml"
        rendered.append((category, filename, rule_doc))
    return rendered


# ---------------------------------------------------------------------------
# Part B -- 6 observed actor-bound rules (breach/sigma fixtures)
# ---------------------------------------------------------------------------

OBSERVED_BREACH_FIXTURES = [
    ("alphv_t1027_obfuscation_golden.yml", "T1027"),
    ("alphv_t1059_001_golden.yml", "T1059.001"),
    ("lapsus_t1078_golden.yml", "T1078"),
    ("lapsus_t1110_correlation_golden.yml", "T1110"),
    ("lockbit_t1486_golden.yml", "T1486"),
    ("nullsec_nigeria_t1491_defacement_golden.yml", "T1491"),
]


def render_observed_breach_rules() -> list[tuple[str, str, dict[str, Any]]]:
    """Copy 6 observed breach sigma goldens + apply LLM-safe redaction."""
    src_dir = ROOT / "apps" / "wrg_threat_intel" / "tests" / "fixtures" / "sigma"
    rendered: list[tuple[str, str, dict[str, Any]]] = []
    for fname, technique in OBSERVED_BREACH_FIXTURES:
        src_path = src_dir / fname
        if not src_path.exists():
            print(f"  WARN: observed fixture missing: {src_path}")
            continue
        raw = src_path.read_text(encoding="utf-8")
        rule_doc = yaml.safe_load(raw)
        # Strip actor-bound tags; replace with wrg.observed prefix.
        new_tags: list[str] = []
        for tag in rule_doc.get("tags", []):
            if tag.startswith("wrg.actor."):
                actor = tag.split(".", 2)[2]
                new_tags.append(f"wrg.observed.actor.{actor}")
            else:
                new_tags.append(tag)
        new_tags.append("wrg.observed")
        new_tags.append(f"wrg.tactic.{resolve_tactic(technique)}")
        rule_doc["tags"] = new_tags
        rule_doc["status"] = "test"
        # Update author to plugin attribution.
        rule_doc["author"] = (
            "WinstonRedGuard -- sigma plugin observed rules "
            "(derived from breach corpus)"
        )
        rule_doc["description"] = redact_llm_safe(str(rule_doc.get("description", "")))
        category = resolve_tactic(technique)
        out_fname = f"observed_{safe_filename(fname.replace('_golden', '').replace('.yml', ''))}.yml"
        rendered.append((category, out_fname, rule_doc))
    return rendered


# ---------------------------------------------------------------------------
# Part C -- 3 crypto trace rules (2 observed + 1 mixer template)
# ---------------------------------------------------------------------------

def render_crypto_trace_rules() -> list[tuple[str, str, dict[str, Any]]]:
    """Render 2 observed OFAC sanctions + 1 mixer template (R2)."""
    src_dir = ROOT / "apps" / "wrg_threat_intel" / "tests" / "fixtures" / "crypto_trace"
    rendered: list[tuple[str, str, dict[str, Any]]] = []

    # 2 observed OFAC sanctions
    for fname in ("sigma_rule_lazarus_golden.yml", "sigma_rule_lockbit_btc_golden.yml"):
        src_path = src_dir / fname
        if not src_path.exists():
            print(f"  WARN: crypto observed fixture missing: {src_path}")
            continue
        raw = src_path.read_text(encoding="utf-8")
        # Strip leading comment block (yaml safe_load handles it but we want
        # clean output).
        rule_doc = yaml.safe_load(raw)
        # Augment tags + categorize as impact (T1657 Financial Theft).
        tags = list(rule_doc.get("tags", []))
        tags.append("wrg.observed")
        tags.append("wrg.tactic.impact")
        rule_doc["tags"] = tags
        rule_doc["author"] = (
            "WinstonRedGuard -- sigma plugin crypto-trace observed rules"
        )
        category = "impact"
        out_fname = f"observed_{safe_filename(fname.replace('_golden', '').replace('.yml', ''))}.yml"
        rendered.append((category, out_fname, rule_doc))

    # 1 mixer template (R2 from crypto_trace/sigma.py)
    mixer_template = {
        "title": "Template -- Crypto wallet interacts with known mixer service",
        "id": deterministic_id("crypto:r2-mixer-template"),
        "status": "experimental",
        "description": (
            "Template for detecting wallet interactions with known "
            "cryptocurrency mixer services (Tornado Cash, Blender.io, "
            "Sinbad, ChipMixer, etc.). Bind to your blockchain telemetry "
            "before deployment."
        ),
        "references": ["https://attack.mitre.org/techniques/T1027/"],
        "author": "WinstonRedGuard -- sigma plugin crypto-trace templates",
        "date": "2026-05-21",
        "logsource": {
            "product": "blockchain",
            "category": "transaction",
        },
        "detection": {
            "selection": {
                "counterparty_address": "<MIXER_ADDRESS>",
            },
            "condition": "selection",
        },
        "level": "medium",
        "tags": [
            "attack.defense_evasion",
            "attack.t1027.013",
            "attack.t1657",
            "wrg.template",
            "wrg.tactic.defense_evasion",
        ],
        "falsepositives": [
            "Legitimate privacy-preserving usage (research, journalism, dissident)",
            "Pattern library v1 -- review for environment-specific tuning before deployment",
        ],
    }
    rendered.append(("defense_evasion", "template_crypto_r2_mixer.yml", mixer_template))
    return rendered


# ---------------------------------------------------------------------------
# Part D -- 5 ai_fingerprint detector rules
# ---------------------------------------------------------------------------

def render_ai_fingerprint_rules() -> list[tuple[str, str, dict[str, Any]]]:
    """Render 5 detector rules from ai_fingerprint_sigma goldens."""
    src_path = (
        ROOT
        / "apps"
        / "wrg_ai_fingerprint_sigma"
        / "tests"
        / "fixtures"
        / "expected_sigma_output.yml"
    )
    if not src_path.exists():
        print(f"  WARN: ai_fingerprint fixture missing: {src_path}")
        return []
    raw = src_path.read_text(encoding="utf-8")
    rendered: list[tuple[str, str, dict[str, Any]]] = []
    for doc in yaml.safe_load_all(raw):
        if not doc:
            continue
        # Augment tags + categorize as code_review (custom Sigma category).
        tags = list(doc.get("tags", []))
        tags.append("wrg.observed")
        tags.append("wrg.tactic.code_review")
        doc["tags"] = tags
        doc["author"] = "WinstonRedGuard -- sigma plugin ai-fingerprint observed rules"
        doc["description"] = redact_llm_safe(str(doc.get("description", "")))
        # references list redact too
        if "references" in doc:
            doc["references"] = [redact_llm_safe(str(r)) for r in doc["references"]]
        # Detector name is encoded in detection.selection.detector
        detector = doc.get("detection", {}).get("selection", {}).get("detector", "unknown")
        category = "code_review"
        out_fname = f"observed_ai_fingerprint_{safe_filename(detector)}.yml"
        rendered.append((category, out_fname, doc))
    return rendered


# ---------------------------------------------------------------------------
# INDEX.json builder
# ---------------------------------------------------------------------------

def build_index(rendered: list[tuple[str, str, dict[str, Any]]]) -> dict[str, Any]:
    """Build 3-dimensional INDEX.json from rendered rules."""
    categories: dict[str, list[str]] = {}
    by_detection_type: dict[str, list[str]] = {}
    by_target_platform: dict[str, list[str]] = {}

    for category, filename, doc in rendered:
        relpath = f"{category}/{filename}"
        categories.setdefault(category, []).append(relpath)

        logsource = doc.get("logsource", {})
        det_type = logsource.get("category") or "unspecified"
        by_detection_type.setdefault(det_type, []).append(relpath)

        platform = logsource.get("product") or "unspecified"
        by_target_platform.setdefault(platform, []).append(relpath)

    # Sort for deterministic output
    for d in (categories, by_detection_type, by_target_platform):
        for k in d:
            d[k] = sorted(d[k])
    return {
        "_schema_version": 1,
        "_generated_by": "internal",
        "_generated_at": "2026-05-21",
        "_pattern_34_v1_1_redaction_applied": True,
        "_source_module_refs": [
            "apps/<wrg-app>/src/<wrg-app>/breach/sigma/templates.py (TECHNIQUE_PATTERN_LIBRARY)",
            "apps/<wrg-app>/tests/fixtures/sigma/*.yml (6 observed goldens)",
            "apps/<wrg-app>/tests/fixtures/crypto_trace/sigma_rule_*.yml (2 observed)",
            "apps/<wrg-app>/tests/fixtures/expected_sigma_output.yml (5 detector goldens)",
        ],
        "total_rules": len(rendered),
        "categories": dict(sorted(categories.items())),
        "by_detection_type": dict(sorted(by_detection_type.items())),
        "by_target_platform": dict(sorted(by_target_platform.items())),
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    print("[migrate_sigma_corpus] rendering rules ...")
    rendered: list[tuple[str, str, dict[str, Any]]] = []
    rendered.extend(render_technique_template_rules())
    print(f"  + {len(rendered)} template rules from TECHNIQUE_PATTERN_LIBRARY")
    n0 = len(rendered)
    rendered.extend(render_observed_breach_rules())
    print(f"  + {len(rendered) - n0} observed breach rules")
    n0 = len(rendered)
    rendered.extend(render_crypto_trace_rules())
    print(f"  + {len(rendered) - n0} crypto-trace rules")
    n0 = len(rendered)
    rendered.extend(render_ai_fingerprint_rules())
    print(f"  + {len(rendered) - n0} ai-fingerprint rules")
    print(f"  = {len(rendered)} TOTAL rules to write")

    print("[migrate_sigma_corpus] writing YAMLs ...")
    EXAMPLES_DIR.mkdir(parents=True, exist_ok=True)
    for category, filename, doc in rendered:
        path = write_rule_yaml(category, filename, doc)
        # ASCII verify
        text = path.read_text(encoding="utf-8")
        text.encode("ascii")  # raises if non-ASCII present

    print("[migrate_sigma_corpus] writing INDEX.json ...")
    index = build_index(rendered)
    index_path = EXAMPLES_DIR / "INDEX.json"
    index_path.write_text(
        json.dumps(index, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    print(f"[migrate_sigma_corpus] DONE")
    print(f"  total_rules: {index['total_rules']}")
    print(f"  categories: {list(index['categories'].keys())}")
    print(f"  by_detection_type keys: {list(index['by_detection_type'].keys())}")
    print(f"  by_target_platform keys: {list(index['by_target_platform'].keys())}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
