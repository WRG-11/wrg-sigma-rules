# wrg-sigma-rules plugin -- 4-Layer external validation (G R88-56g pre-warm)

**Date**: 2026-05-22 (R88-56g pre-warm partial review; 4/7 stream MERGED)
**Methodology**: [`docs/standards/anthropic-plugin-4-layer-audit.md`](../../../docs/standards/anthropic-plugin-4-layer-audit.md) v1.0
**Status**: PRE-WARM PARTIAL (full re-run deferred to post-B+C ship per Pattern 28 v1.0 spec-adoption discipline)
**Significance**: **F + G triangulation 1st canonical** -- insider self-audit (F) + outsider external validation (G) = audit completeness. Sister to Pattern 27 Track A convergent validation discipline.

---

## Triangulation principle

| Lens | Owner | Methodology |
|---|---|---|
| Insider self-audit | F R88-56f | 4-Layer pre-marketplace-submission gate; eat-your-own-dogfood discipline |
| Outsider external validation | G R88-56g | Spec-adoption + Pre-publish 10-item + marketplace policy compliance |

Each lens has distinct blind spots:
- F insider sees the manifest + skill declarations but may scope-drop adjacent artifacts (e.g., plugin-level README)
- G outsider sees marketplace-visible surface but may miss subtle manifest schema drift without F's live-API verify baseline

Triangulation closes the gap. R88-56g pre-warm caught 1 concrete F-scope-drop artifact (saha bulgu #1 below).

---

## Layer 1 -- Manifest schema (re-validation)

**F status**: PASS (post-fix); 4 schema drifts caught + fixed.
**G re-validation**: PASS + 1 scope-gap caught.

### F findings re-confirmed by G

| F Finding | G re-confirm | Status |
|---|---|---|
| `plugin.json` -> `.claude-plugin/` subdir | Located at `plugins/wrg-sigma-rules/.claude-plugin/plugin.json` | PASS |
| `keywords` (not `topics`) | 6 entries: security, sigma, detection, siem, soc, threat-intel | PASS |
| Author nested object `{"name": "WRG (WinstonRedGuard)"}` | Verified | PASS |
| No `tools`/`skills`/`prompts`/`resources` arrays in plugin.json | Verified absent | PASS |
| Telegram-canonical SKILL.md frontmatter (4 field) | 3/3 SKILL.md: name + description + user-invocable: true + allowed-tools | PASS |
| `user-invocable: true` on each SKILL.md | 3/3 confirmed | PASS |
| `allowed-tools` array non-empty + namespaced | 3/3: `mcp__wrg-sigma__*` + standard Read/Write/Bash(ls *) | PASS |

### G NEW finding (F scope-gap)

**G-1 (FIXED)**: `plugins/wrg-sigma-rules/README.md` (plugin-level marketplace-visible README) contained 19 non-ASCII characters (em-dash U+2014 x15 + right-arrow U+2192 x4). F R88-56f Layer 1 ASCII verify scope was plugin.json + 3 SKILL.md + AUDIT-SELF.md. Plugin-level README was scope-dropped. G external validation caught it during pre-warm Batch 1; fixed in-place (`--` and `->` substitutions). Post-fix verify: 0 non-ASCII chars remaining in plugin-level README.

**Lesson**: F self-audit scope MUST include ALL marketplace-visible artifacts (manifest + skill declarations + plugin-level docs + resource content). R88-56e batch 4 codify candidate: "4-Layer self-audit scope Rule N -- include every artifact the marketplace surfaces; not just declarations."

---

## Layer 2 -- Skill discovery + invocation (pre-flight re-validation)

**F status**: PASS by design (telegram-canonical schema + frontmatter discipline); runtime verify deferred.
**G re-validation**: PASS (pre-flight + body content audit).

### F pre-flight checks re-confirmed by G

| F Pre-flight | G re-confirm | Status |
|---|---|---|
| 3 SKILL.md files under `skills/<name>/SKILL.md` | sigma-rule-writer + sigma-rule-reviewer + threat-coverage-gap-analyzer | PASS |
| Skill names lowercase + kebab-case | 3/3 PASS | PASS |
| "Use when..." pattern in descriptions | 3/3 descriptions explain trigger conditions | PASS |
| Namespaced MCP tool names | 3/3 use `mcp__wrg-sigma__*` | PASS |

### G NEW finding (SKILL body content audit)

**G-2 (PASS, NEGATIVE EXAMPLE confirmed)**: Closure-cue sweep across 3 SKILL.md bodies surfaced 2 hits in `sigma-rule-writer` ("Hope this helps", "Let me know if..."). On detailed review, both hits are inside the "Anti-patterns" section as **negative examples** documenting the discipline the skill enforces (sister `feedback_no_premature_closure.md`). NOT a violation -- the skill DOCUMENTS the closure-cue anti-pattern explicitly. Discipline cross-reference baked into skill body = canonical operator-drives-next-step discipline anchor.

### Runtime verify (still deferred)

Same as F audit: `/plugins`, `/skills list`, slash command invocation, `/reload-plugins` output verification deferred to post-marketplace-install or operator local install dry-run. No state change in G pre-warm.

---

## Layer 3 -- Cross-plugin replication (W1 pilot scan WATCH)

**F status**: N/A -- first-mover sigma niche.
**G re-validation**: N/A confirmed.

### Live API re-confirm

R88-56g pre-warm spot-check: `anthropics/claude-plugins-official` 35 plugins, 0 sigma plugin replication. First-mover status preserved as of 2026-05-22 (1 day post 2026-05-21 verify). W1 pilot scan **Pazartesi 2026-05-25** still on schedule per F audit.

### Sister-replication watch (post-launch)

- W1 pilot scan (4-Layer methodology 1st external application; sister gun)
- If Layer 1 schema gap rate >= 30% across 20 plugins -> Pattern 18 v1.1 endpoint-supply-chain super-cluster extension candidate (marketplace platform issue, not per-plugin bug)
- Post-launch sigma plugin replicas: monitor for R89+ batch Layer 3 cross-plugin replication audit candidate

---

## Layer 4 -- Auth + runtime opacity (re-validation)

**F status**: PASS by design (no external auth required).
**G re-validation**: PASS + B R88-56b implementation gates explicit.

### F by-design PASS re-confirmed by G

| F Layer 4 element | G re-confirm | Status |
|---|---|---|
| No external auth required | Plugin is pure local Python + pySigma | PASS |
| Documentation alignment ("no auth, local-only") | README + SKILL.md + AUDIT-SELF consistent | PASS |

### B R88-56b implementation gates (G external pre-verify)

F audit declared 5 implementation gates B R88-56b MUST satisfy. G external validation re-confirms these gates as marketplace acceptance criteria:

- [ ] B R88-56b -- pySigma missing error includes `pip install pysigma pysigma-backend-splunk` hint (actionable)
- [ ] B R88-56b -- Backend missing error includes specific backend pip install command (actionable)
- [ ] B R88-56b -- YAML parse error includes line number + column (actionable)
- [ ] B R88-56b -- Pattern 34 LLM-safe always-redact: no operator infrastructure leak in error / tool output
- [ ] B R88-56b -- ASCII-only output (Pattern 33 Rule 5) across tool stdout + JSON envelope

G external validation post-B-ship will re-verify each gate empirically (tool invocation matrix: happy path + missing-dep + missing-backend + parse-error + redaction sweep).

### Sister discipline anchor

`sonatype-guide` Layer 4 fail canonical (Issue #1954 follow-up): auth-required plugin without actionable error. `wrg-sigma-rules` avoids this entire class by requiring no auth. **Local-first plugin = Layer 4 PASS by construction.**

---

## D R88-56d content asset spot-verification (G Batch 2 pre-warm)

External validation extension beyond F self-audit:

| Asset | F scope? | G re-verify | Status |
|---|---|---|---|
| `resources/examples/INDEX.json` (3-D taxonomy 51-rule enumeration) | NO (D scope) | 11 ATT&CK tactic + 10 detection type + 4 platform; 51 rule total matches D done report | PASS |
| `resources/examples/<tactic>/*.yml` (51 sigma rules) | NO (D scope) | Spot-check `execution/template_t1059_001_powershell_encoded_command_execution.yml`: sigma spec valid + MITRE T1059.001 tag + falsepositives populated + status: experimental + UUID5 id | PASS |
| `resources/canonical-patterns/*.md` (5 patterns + INDEX) | NO (D scope) | INDEX.md + 01-command-line-encoded-payload.md: rich content (MITRE coverage + canonical YAML shape + why-it-works + false positives + reference rules + specialisations + severity guidance) | PASS |
| `tools/resources/canonical_patterns_resource.py` (URI resource module) | NO (D scope) | Module-level body factoring + graceful degradation envelope `{ok: False, error: "..."}` + ASCII coercion at resource boundary + `register_canonical_pattern_resources(mcp)` helper; sister D R88-52d 1st canonical Pattern 33 Rule 6 application | PASS |
| LLM-safe redaction sweep | NO (D scope) | 64 output artifact (scripts/ excluded): 0 PII + 0 WRG-INTERNAL + 0 apps/wrg_* + 0 internal actor ID hit | PASS |

D R88-56d content asset external validation: **PASS across all 5 spot-check dimensions**.

---

## E R88-56e codify spot-verification (G Batch 3 pre-warm)

External validation of discipline anchors:

| Codify artifact | E batch | G re-verify | Status |
|---|---|---|---|
| `docs/standards/sigma-plugin-development-discipline.md` v1.0 | 3 | 5 alt-disiplin: 4-Layer self-audit + LLM-safe + ASCII + URI resource + Pre-publish 10-item; saha kanit R88-56 wave 1st operational application table | PASS |
| `AGENTS.md` section 15.14 (109 lines, 6th realisation) | 1 | Deferred-resume sub-pattern + import-guard 3-vaka graduation MET (R88-49c + R88-52c + R88-54c) | PASS |
| `AGENTS.md` section 15.21 (199 lines, Pattern 33 v1.2) | 2 | MCP capability + Anthropic anchor 3-leg Rule 8 (W1 pilot scan Layer 4 ek kontrol consumer) | PASS |
| `AGENTS.md` section 15.22 (155 lines, Pattern 34 v1.1) | 2 | LLM-safe + Rule 6 screenshot redact (sister Pattern 33 v1.2 Leg 2) | PASS |
| `AGENTS.md` section 15.23 (17 lines, A direct ship pattern) | 1 | 5-vaka MATURE cluster: R88-49c + R88-47d + R88-54c + R88-50d + R88-56f | PASS (stub; expected to grow with future vaka) |

E codify external validation: **PASS across all 5 discipline anchor artifacts**.

---

## Conclusion (pre-warm)

| Layer | F (insider) | G (outsider) | Triangulation |
|---|---|---|---|
| Layer 1 -- Manifest schema | PASS (post-fix; 4 drift caught) | PASS + 1 README ASCII gap caught + fixed | **F + G combined catch: 5 drifts pre-marketplace-submit** |
| Layer 2 -- Skill discovery | PASS (pre-flight) | PASS (pre-flight + body content audit) | Runtime verify deferred (consistent) |
| Layer 3 -- Cross-replication | N/A first-mover | N/A confirmed (live API spot-check 2026-05-22) | W1 pilot scan Pazartesi 2026-05-25 watch |
| Layer 4 -- Auth + opacity | PASS by design | PASS + 5 B R88-56b implementation gates explicit | B R88-56b post-ship gate verify pending |

**Pre-warm verdict**: Plugin packaging + content asset + discipline anchor are **ready for marketplace submission pending B+C completion**. G full audit re-runs post-B-ship + C-ship + E batch 4 lockdown.

**4-Layer methodology triangulation result**: F insider audit caught 4 schema drifts; G outsider audit caught 1 scope-gap (README ASCII) + 5 D content asset spot-verifies + 5 E discipline anchor spot-verifies. **F + G combined coverage > F alone** -- triangulation discipline empirically justified.

---

## R88-56e codify candidate (G pre-warm batch 4 input)

5 saha bulgu candidate from G pre-warm:

1. **F self-audit scope gap (plugin-level README ASCII)** -- 4-Layer self-audit scope must include ALL marketplace-visible artifacts, not just declarations. AGENTS.md section 15.21 / section 15.23 / sigma-plugin-development-discipline.md candidate addition.
2. **F + G triangulation 1st canonical** -- insider self-audit + outsider external validation = audit completeness. Pattern 27 Track A convergent validation extension candidate (7+ vaka watch).
3. **Pre-publish Item 6 empirical 0 hit** -- D's 4-rule redaction (actor catalog + internal path + PII regex + ASCII) discipline EFFECTIVE across 64 output artifacts. Pattern 34 v1.1 redaction empirical kanit.
4. **SKILL body anti-pattern documentation discipline** -- sigma-rule-writer body explicitly documents closure-cue anti-pattern in negative-example section. Discipline cross-reference baked into skill body = canonical operator-drives-next-step anchor.
5. **URI resource graceful degradation envelope canonical** -- 2nd application after D R88-52d 1st canonical; Pattern 33 Rule 4 + Rule 6 cross-pattern application MATURE.

---

## Re-audit cadence (post-finalisation)

- Re-run G external validation when:
  - B R88-56b tool impl ships (Layer 4 implementation gates verify)
  - C R88-56c tests ship (Layer 2 test corpus verify)
  - E R88-56e batch 4 codify lockdown ships (sigma-plugin-development-discipline.md v1.1+ verify)
  - Anthropic marketplace CONTRIBUTING.md spec evolves (live API verify)
- Annual baseline re-validation (sister Pattern 36 supply chain CVE cadence; sister F audit cadence)
- Post-marketplace-merge: 30-day check + 90-day check + 1-year baseline (sister Pattern 36 lifecycle)

---

## Cross-reference

- `plugins/wrg-sigma-rules/.claude-plugin/AUDIT-SELF.md` -- F R88-56f self-audit (G external validation input)
- `plugins/wrg-sigma-rules/PR-DRAFT.md` -- G R88-56g PR submission draft (partial skeleton; this audit feeds Pre-publish 10-item Items 2+3+6)
- `docs/standards/anthropic-plugin-4-layer-audit.md` v1.0 -- methodology source
- `docs/standards/sigma-plugin-development-discipline.md` v1.0 -- 5 alt-disiplin canonical (E R88-56e batch 3 ship)
- `docs/templates/anthropic-plugin-audit-issue.md` -- Pre-publish checklist sister discipline
- D R88-56d done report: `.agents/inbox/A/from-D/2026-05-21-2200-r88-56d-sigma-rules-migration-resources-done.md`
- F R88-56f done report: `.agents/inbox/A/from-F/2026-05-21-2200-r88-56f-sigma-plugin-manifest-skill-self-audit-done.md`
- G R88-56g brief: `.agents/inbox/G/from-A/2026-05-21-2200-r88-56g-sigma-plugin-marketplace-submission-audit.md`
- G R88-56g pre-warm: `.agents/inbox/G/from-A/2026-05-22-1100-r88-56g-partial-review-warmup.md`
- Sister Pattern 27 Track A convergent validation (5-vaka cluster; F + G triangulation 6th vaka candidate post-finalize)
- Sister Pattern 28 v1.0 FORMAL Track B spec-adoption (G R88-49g 1st FORMAL canonical; G R88-56g 2nd FORMAL application; this audit is 2nd canonical artifact)
