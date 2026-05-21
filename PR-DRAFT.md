# PR-DRAFT -- Add wrg-sigma-rules plugin

**Status**: PARTIAL SKELETON (R88-56g pre-warm; 4/7 stream MERGED; B+C pending)
**Owner**: G external validation (Pattern 28 v1.0 FORMAL 2nd canonical application)
**Final draft**: pending B R88-56b tool impl + C R88-56c test corpus + E R88-56e batch 4 lockdown
**Target repo**: `anthropics/claude-plugins-official` (NOT submitted; operator decides timing)

---

## DRAFT PR body (anti-spam discipline strict; WRG anchor constructive frame)

### Title

```
Add wrg-sigma-rules plugin (sigma detection rule writing + validation + conversion)
```

### Body

```markdown
## Summary

Adds `wrg-sigma-rules` -- a production-grade sigma detection rule writing,
validation, and conversion plugin for SOC analysts, threat-intel teams, and
bug bounty hunters using Claude Code. First sigma plugin in the Anthropic
marketplace; built on 6+ months of WRG (WinstonRedGuard) threat-intel
corpus.

## Why this plugin

- Sigma rule niche currently empty in the marketplace (verified 2026-05-21:
  35 plugins, 0 sigma)
- Security category has 1 existing plugin (`security-guidance`, generic);
  detection engineering tooling underserved
- SOC analyst + threat-intel + bug bounty community has latent demand for
  fast, LLM-assisted, quality-aware sigma rule workflows
- WRG existing corpus provides immediate value (51 canonical example rules
  spanning 11 MITRE ATT&CK tactics)

## Plugin capabilities

- **Tools** (3, via MCP server wrap):
  - `wrg__sigma__draft_rule` -- NL description -> sigma YAML scaffold
  - `wrg__sigma__validate_rule` -- YAML schema + pySigma compat + best-
    practices linter
  - `wrg__sigma__convert_rule` -- sigma YAML -> Splunk SPL / Elastic / Wazuh /
    Kibana query (pySigma backends)
- **Skills** (3, telegram-canonical schema):
  - `sigma-rule-writer` -- guided rule writing workflow from NL threat
    description
  - `sigma-rule-reviewer` -- paste rule for canonical-shape quality review
  - `threat-coverage-gap-analyzer` -- MITRE ATT&CK coverage analysis
- **Resources** (2, MCP resource URIs):
  - `wrg-sigma://patterns/canonical-5` -- 5 canonical detection pattern
    definitions (process_creation encoded payload + cred access OS
    internals + LOLBin abuse + C2 beaconing + supply chain)
  - `wrg-sigma://patterns/canonical-5/{pattern_id}` -- per-pattern markdown
    (01 through 05)
- **Example corpus** (51 sigma rules):
  - 37 hand-curated MITRE technique templates
  - 6 observed actor goldens (ALPHV/BlackCat + LAPSUS$ + LockBit + Nullsec
    Nigeria)
  - 2 OFAC crypto sanctions goldens (Lazarus + LockBit BTC operator)
  - 5 wrg_ai_fingerprint code-review detector goldens
  - 3-dimensional INDEX.json (11 ATT&CK tactics + 10 detection types +
    4 target platforms)

## Quality assurance

- 4-Layer self-audit (`AUDIT-SELF.md`): 3/4 PASS + 1 N/A first-mover.
  Pre-marketplace-submission gate. Methodology caught 4 schema convention
  drifts in the WRG plugin scaffold before submission (eat-your-own-
  dogfood discipline).
- Test surface: 12-case pytest on URI resource module (12/12 PASS first
  attempt). [DEFER B+C] -- additional 80+ tests pending C R88-56c ship
  (50 existing rule validation + 20 NL->YAML golden + 10 integration
  smoke).
- pySigma 0.10+ compat. Multi-backend conversion verified (Splunk +
  Elastic + Wazuh).
- LLM-safe output discipline (Pattern 34 v1.1 always-redact + ASCII-only
  + error path structure preserve): plugin-wide PII regex + internal
  marker sweep 0 hit across 64 output artifacts.

## Background

This is WRG's second contribution to the Anthropic plugin ecosystem after
[Issue #1954 mcp-server-dev plugin install drift report](https://github.com/anthropics/claude-plugins-official/issues/1954).
Plugin development followed the same 4-Layer audit methodology proposed in
that issue; this PR is the canonical "eat-your-own-dogfood" application.

Plugin lives in the WRG monorepo at `plugins/wrg-sigma-rules/`. If
marketplace tooling expects a standalone repository, happy to provide a
`git subtree split` mirror.

License: MIT (matches marketplace ecosystem).

## Maintenance commitment

- Weekly upstream-spec check (Anthropic plugin schema + pySigma releases)
- Monthly WRG corpus refresh (re-run bundled
  `scripts/migrate_sigma_corpus.py` against updated WRG threat-intel
  feed)
- Sister cadence: WRG `wrg_supply_chain_sentry` Pattern 36 v1.0 baseline
  lifecycle discipline

Happy to address review feedback.

---

Filed by: WRG (WinstonRedGuard) ecosystem contributor
Plugin source: https://github.com/WRG-11/WinstonRedGuard/tree/main/plugins/wrg-sigma-rules
```

---

## Pre-publish 10-item gate (G R88-56g pre-warm verification)

| # | Item | Status (R88-56g pre-warm) | Final gate |
|---|---|---|---|
| 1 | Constructive frame | DRAFTED above ("happy to address feedback" closing; "first-mover + ecosystem contributor" frame) | Per-PR |
| 2 | 4-Layer self-audit | **PRE-VERIFIED** (`AUDIT-SELF.md` exists; 3/4 PASS + 1 N/A; 4 schema drifts caught + fixed) | Pre-merge |
| 3 | Concrete output sample | **PRE-VERIFIED** (51 sigma rule + 5 canonical pattern in `resources/`; INDEX.json + per-pattern markdown rich) | Per-PR |
| 4 | WRG anchor disclosure | DRAFTED above ("6+ months of WRG threat-intel corpus") | Per-PR |
| 5 | No maintainer mention spam | DRAFTED above (PR body neutral; no @ mention) | Per-PR |
| 6 | Sensitive data redacted | **PRE-VERIFIED** (G sweep: 64 output artifact / 0 PII + 0 WRG-INTERNAL + 0 apps/wrg_* hit; Pattern 34 v1.1 redaction confirmed) | Pre-merge |
| 7 | Cross-link sister Anthropic issues | DRAFTED above (Issue #1954 mcp-server-dev dual contribution sister) | Per-PR |
| 8 | License compliance | DRAFTED above (MIT) | Per-PR |
| 9 | Marketplace policy compliance | **DEFER** (Part 1 live API CONTRIBUTING.md verify; pending) | Pre-merge |
| 10 | Plugin functionality demo | **DEFER R88-57+** (screenshot/video optional first ship) | Optional |

**Items pre-verifiable now**: 2 + 3 + 6 (30% of audit advance pre-B+C ship)
**Items needing B+C**: capability count exactness (Plugin capabilities section); test count finalisation (Quality assurance section)
**Items needing Part 1 live API verify**: 9 (marketplace CONTRIBUTING.md fresh fetch)

---

## DEFER markers (post-B+C finalize)

These PR body sections need B + C ship before final draft:

- **Plugin capabilities -- Tools section** [DEFER B]: B R88-56b will define the final 3 tool signatures; current draft uses brief-proposed names. If B's actual signatures diverge (parameter names, return shape), update before submission.
- **Quality assurance -- Test count** [DEFER C]: C R88-56c will ship the test corpus (~80+ test cases per brief). Current draft uses brief estimates; finalise post-C-ship with actual `pytest --collect-only` count.
- **Pre-publish 10-item gate -- Item 9** [DEFER Part 1]: live API CONTRIBUTING.md fetch + per-policy review required before final PR submission.

---

## Cross-references

- `plugins/wrg-sigma-rules/.claude-plugin/AUDIT-SELF.md` -- F R88-56f 4-Layer self-audit (Pre-publish Item 2 input)
- `plugins/wrg-sigma-rules/resources/examples/INDEX.json` -- D R88-56d 3-dimensional taxonomy (51-rule enumeration)
- `plugins/wrg-sigma-rules/resources/canonical-patterns/INDEX.md` -- D R88-56d 5 canonical pattern catalog
- `docs/standards/sigma-plugin-development-discipline.md` -- E R88-56e batch 3 (5 alt-disiplin canonical)
- `docs/standards/anthropic-plugin-4-layer-audit.md` -- W0 metodoloji canonical source
- `docs/templates/anthropic-plugin-audit-issue.md` -- Pre-publish checklist sister discipline
- Brief: `.agents/inbox/G/from-A/2026-05-21-2200-r88-56g-sigma-plugin-marketplace-submission-audit.md`
- Warm-up: `.agents/inbox/G/from-A/2026-05-22-1100-r88-56g-partial-review-warmup.md`

---

## G external validation findings

1. **README.md Pattern 33 Rule 5 ASCII gap caught + fixed** (saha bulgu #1): A R88-56a scaffold output had 19 non-ASCII chars (em-dash U+2014 x15 + right-arrow U+2192 x4) in plugin-level README.md. F R88-56f self-audit scope was plugin.json + 3 SKILL.md + AUDIT-SELF.md; plugin-level README was scope-dropped. G external validation caught it during pre-warm Batch 1. Fixed in-place to maintain Pattern 33 Rule 5 cross-platform safe discipline. **F+G coverage gap insight**: self-audit scope MUST include all marketplace-visible artifacts (not just manifest + skill declarations).

2. **F+G triangulation 1st canonical** (saha bulgu #2): F self-audit (insider perspective; 4 schema drift catch) + G external validation (outsider perspective; ASCII gap catch) = audit completeness. Sister Pattern 27 Track A convergent validation extension candidate (7+ vaka watch).

3. **Pre-publish Item 6 LLM-safe sweep 0 hit empirical** (saha bulgu #3): D R88-56d Pattern 34 v1.1 redaction discipline verified across 64 output artifacts (excluding `scripts/` build-time tooling). 0 PII + 0 WRG-INTERNAL + 0 apps/wrg_* + 0 internal actor ID hit. D's 4-rule redaction (actor catalog + internal path + PII regex + ASCII) discipline EFFECTIVE.

4. **3 SKILL.md telegram-canonical schema discipline confirmed** (saha bulgu #4): Each of writer + reviewer + threat-coverage-gap-analyzer carries 4-field frontmatter (name + description + user-invocable: true + allowed-tools); no extension drift. Issue #1954 Layer 2 lesson preempt operational. Body Layer 4 leak check: closure cues found ONLY in negative-example "Anti-patterns" section of sigma-rule-writer (documenting discipline, not violating it).

5. **URI resource layer graceful degradation envelope canonical** (saha bulgu #5): `canonical_patterns_resource.py` returns typed envelope `{ok: False, error: "..."}` on file-missing + pattern-id-unknown branches. ASCII coercion baked-in at resource boundary (defensive vs. migration script upstream guarantee). Sister Pattern 33 Rule 4 + Rule 6 application; consistent with D R88-52d 1st canonical.

---

## Next steps for finalisation

1. Wait B R88-56b ship (3 tool impl signatures finalise)
2. Wait C R88-56c ship (80+ test count finalise)
3. Wait E R88-56e batch 4 (codify lockdown last)
4. Re-run G audit Part 1 (live API CONTRIBUTING.md fetch + spec verify)
5. Update PR body sections marked [DEFER] above
6. Finalise `AUDIT-VERIFY.md` external validation cross-reference (F self + G external triangulation)
7. Hand over to operator for PR submission decision (NOT this wave per brief)
