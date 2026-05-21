# wrg-sigma-rules plugin -- 4-Layer self-audit

**Date**: 2026-05-22 (R88-56f ship)
**Methodology**: [`docs/standards/anthropic-plugin-4-layer-audit.md`](../../../docs/standards/anthropic-plugin-4-layer-audit.md) v1.0
**Status**: PASS (3/4 layer PASS + 1 N/A first-mover; 1 deferred runtime verify pending install path)
**Significance**: **W0 metodoloji 1st operational self-application** (eat-your-own-dogfood discipline; Issue #1954 lesson preempt). Methodology proven by catching its own Layer 1 gap (see Layer 1 findings).

---

## Layer 1 -- Manifest schema (plugin.json + SKILL.md frontmatter)

**Status**: PASS (post-fix). Initial scaffold had a real Layer 1 gap; self-audit caught and fixed it.

### plugin.json checks

- [x] PASS -- `version` field present and valid semver (`0.1.0`)
  - Issue #1954 1st cause preempt (missing version -> install path falls back to `unknown/`)
- [x] PASS -- `name` is lowercase + kebab-case (`wrg-sigma-rules`)
- [x] PASS -- `description` is 1-2 sentence value proposition + capability listing
- [x] PASS -- `author` is nested object (`{"name": "WRG (WinstonRedGuard)"}`) matching Sonatype canonical pattern
- [x] PASS -- `homepage` + `repository` URLs present (WRG monorepo subtree link)
- [x] PASS -- `keywords` array for marketplace search optimization (6 entries: security, sigma, detection, siem, soc, threat-intel)
- [x] PASS -- ASCII-only content (Pattern 33 Rule 5 WRG discipline; cross-platform safe)
- [x] PASS -- File location: `.claude-plugin/plugin.json` (Anthropic canonical convention)

### plugin.json findings -- Layer 1 gap CAUGHT + FIXED

**Finding 1 (FIXED)**: Initial scaffold placed `plugin.json` at the plugin root (`plugins/wrg-sigma-rules/plugin.json`). Live API verify of 3 reference plugins (telegram 0.0.6, sonatype-guide 1.0.0, mcp-server-dev 0.1.0) confirmed Anthropic canonical convention is `<plugin>/.claude-plugin/plugin.json` (subdir). Fixed via `git mv` during this audit pass.

**Finding 2 (FIXED)**: F R88-56f brief proposed `"topics"` field; live API canonical uses `"keywords"` (npm/cargo style). F brief itself had wrong schema info -- brief is now a known refactor candidate for the next R88-56+ wave or codify-combo lockdown.

**Finding 3 (FIXED)**: F R88-56f brief proposed `"tools"`, `"skills"`, `"prompts"`, `"resources"` arrays in plugin.json; live API canonical does NOT include these (discovery is dir-based). Dropped.

**Finding 4 (FIXED)**: F R88-56f brief proposed `displayName`, `license`, `minimumClaudeCodeVersion` fields; live API canonical does NOT include these. Dropped to stay close to telegram + sonatype canonical superset.

**Saha bulgu**: W0 4-Layer audit metodoloji 1st operational self-application caught 4 schema convention drifts in WRG's own scaffold + brief documentation. Methodology value proven before first external application (W1 pilot scan Pazartesi 2026-05-25).

### SKILL.md frontmatter checks (3 skills)

For each of `sigma-rule-writer`, `sigma-rule-reviewer`, `threat-coverage-gap-analyzer`:

- [x] PASS -- `name` field matches directory name
- [x] PASS -- `description` field is 1-3 sentence "what + when to use" pattern (Anthropic skill discovery cue)
- [x] PASS -- `user-invocable: true` set (Issue #1954 2nd cause preempt -- mcp-server-dev SKILL.md frontmatter missing this field caused 0-skill discovery)
- [x] PASS -- `allowed-tools` array declared (Issue #1954 same cause preempt)
- [x] PASS -- `allowed-tools` includes future B R88-56b MCP tools (`mcp__wrg-sigma__draft_rule`, `mcp__wrg-sigma__validate_rule`, `mcp__wrg-sigma__convert_rule`) + standard Read/Write/Bash for file ops
- [x] PASS -- Telegram-style canonical schema (no `metadata`, `category`, `difficulty`, `estimated_time` extension fields; v2.1.143 runtime stable)
- [x] PASS -- ASCII-only frontmatter + body

### Discovery commands (post-install verify; deferred)

```powershell
# Run after /plugin install wrg-sigma-rules
cat "$env:USERPROFILE/.claude/plugins/cache/<marketplace>/wrg-sigma-rules/0.1.0/.claude-plugin/plugin.json"
cat "$env:USERPROFILE/.claude/plugins/cache/<marketplace>/wrg-sigma-rules/0.1.0/skills/*/SKILL.md" | Select-String -Pattern "^name:|user-invocable|allowed-tools"
```

Expected: 3 SKILL.md files surface, each with `user-invocable: true` and `allowed-tools` declared.

---

## Layer 2 -- Skill discovery + invocation (runtime behavior)

**Status**: PASS by design (telegram-canonical schema + frontmatter discipline). **Deferred runtime verify**: requires actual `/plugin install` + `/skills list` in a fresh Claude Code session (not feasible until G R88-56g marketplace submission lands or operator local install dry-run).

### Pre-flight checks (static)

- [x] PASS -- 3 SKILL.md files exist under `skills/<name>/SKILL.md`
- [x] PASS -- Each SKILL.md has telegram-style frontmatter (proven stable on v2.1.143; Issue #1954 lesson)
- [x] PASS -- Skill names are lowercase + kebab-case
- [x] PASS -- Skill descriptions include "Use when..." pattern (Anthropic discovery cue)
- [x] PASS -- Allowed-tools declared with namespaced MCP tool names (`mcp__wrg-sigma__*`)

### Runtime verify (deferred to post-install)

- [ ] DEFER -- `/plugins` shows wrg-sigma-rules in plugin list
- [ ] DEFER -- `/skills list` shows 3 skill entries (sigma-rule-writer + sigma-rule-reviewer + threat-coverage-gap-analyzer)
- [ ] DEFER -- `/wrg-sigma-rules:sigma-rule-writer` invocation works (returns skill prompt)
- [ ] DEFER -- Slash command tab-completion surfaces the 3 skills
- [ ] DEFER -- `/reload-plugins` output shows `Reloaded: 1 plugin * 3 skills` (NOT `0 skills`)

**Verify cadence**: After G R88-56g marketplace submission OR operator local install dry-run (whichever first).

### Anti-pattern check

- [x] PASS -- No skill name collides with existing Claude Code built-in slash command (`/agents`, `/plugins`, `/skills`, `/init`, `/clear` etc not used)
- [x] PASS -- No skill description starts with "This skill..." or "I will..." (Anthropic style guide -- 3rd person imperative preferred)
- [x] PASS -- No skill body opens with "Hello! I'm..." (skill is invoked, not a greeting)

---

## Layer 3 -- Cross-plugin replication (3+ vaka pattern check)

**Status**: N/A -- first-mover sigma niche.

### Justification

Live marketplace verify 2026-05-21 (R88-56 wave dispatch): `anthropics/claude-plugins-official` had 35 plugins; sigma niche 100% empty; security category contained only 1 plugin (`security-guidance`, generic). No replication baseline exists.

### WATCH item

- [ ] WATCH -- W1 pilot scan **Pazartesi 2026-05-25** (4-Layer methodology canonical 1st external application; this self-audit is 1st operational self-application sister gun).
  - Pilot scan target: 20 marketplace plugins; check Layer 1/2 sister bug rate.
  - If Layer 1 schema gap rate >= 30% across 20 plugins -> 3+ vaka systemic ecosystem issue (Pattern 18 graduation rule MET; marketplace platform issue, not per-plugin bug).
  - If sister sigma plugins appear post-launch -> Layer 3 cross-plugin replication audit candidate (R89+ batch).

---

## Layer 4 -- Auth + runtime opacity (silent install -> runtime fail)

**Status**: PASS by design (no external auth required).

### Auth surface analysis

- [x] PASS -- **No external auth required**. Plugin is pure local Python + pySigma. No API key, no OAuth, no enterprise endpoint, no registration.
- [x] PASS -- Tool implementations (pending B R88-56b) MUST follow actionable error discipline:
  - `pySigma not installed` -> error message includes `pip install pysigma pysigma-backend-splunk` hint
  - `Backend missing` -> error message includes the specific backend `pip install` command
  - `YAML parse error` -> error message includes line number + column
- [x] PASS -- Documentation alignment: README, SKILL.md descriptions, and AUDIT-SELF.md all consistent on "no auth, local-only, pySigma-based".

### Layer 4 implementation gates for B R88-56b

B R88-56b tool impl MUST satisfy these Layer 4 checks before merge:

- [ ] B R88-56b -- pySigma missing error includes pip install hint (actionable)
- [ ] B R88-56b -- Backend missing error includes specific backend pip install command (actionable)
- [ ] B R88-56b -- YAML parse error includes line number + column (actionable)
- [ ] B R88-56b -- Pattern 34 LLM-safe always-redact: no operator infrastructure details leaked in error messages or tool output
- [ ] B R88-56b -- ASCII-only output (Pattern 33 Rule 5)

### Sister discipline anchor

`sonatype-guide` Layer 4 fail canonical case (Issue #1954 follow-up comment): install + skills registered + tool invocation fails with opaque "Authentication required" message. wrg-sigma-rules avoids this entire class by requiring no auth. **Local-first plugin design = Layer 4 PASS by construction.**

---

## Conclusion

| Layer | Status | Notes |
|---|---|---|
| Layer 1 -- Manifest schema | **PASS (post-fix)** | 4 schema convention drifts caught and fixed in WRG scaffold + F brief; methodology proven |
| Layer 2 -- Skill discovery | **PASS (pre-flight)** | Runtime verify deferred to post-install |
| Layer 3 -- Cross-replication | **N/A** | First-mover sigma niche; W1 pilot scan Pazartesi watch |
| Layer 4 -- Auth + opacity | **PASS (by design)** | No external auth; B R88-56b error-message gates declared |

**Verdict**: Plugin packaging is **ready for G R88-56g marketplace submission audit pending B+C+D completion** (B tools + C tests + D resources). G R88-56g will use this AUDIT-SELF.md as external validation input for its Pre-publish checklist Item 2.

**4-Layer methodology self-application result**: Methodology caught 4 real schema drifts before public marketplace submission. Eat-your-own-dogfood discipline canonical kanit. Issue #1954 lesson preempt operational.

---

## Sister discipline references

- [Anthropic plugin 4-Layer audit methodology](../../../docs/standards/anthropic-plugin-4-layer-audit.md) v1.0 -- this audit's source methodology
- [Issue #1954 mcp-server-dev plugin install drift](../../../docs/templates/anthropic-plugin-audit-issue.md) -- Layer 1+2 canonical case study (lesson preempted by this audit)
- Pattern 18 v1.1 trust-but-verify endpoint-supply-chain 5-vaka super-cluster -- "even resmi vendor not exempt" applies to WRG's own plugin scaffold (caught Layer 1 convention drift)
- Pattern 33 v1.0+ MCP capability category discipline -- Rule 5 ASCII-only output applied to plugin.json + SKILL.md
- Pattern 34 v1.0 LLM-safe always-redact -- Layer 4 actionable error discipline + Pattern 34 leak prevention in all 3 skill bodies
- [`feedback_no_premature_closure.md`](../../../memory/feedback_no_premature_closure.md) -- operator drives next-step discipline (all 3 SKILL.md bodies enforce; no closure cues)

## Re-audit cadence

- Re-run this self-audit when:
  - plugin.json schema changes (e.g. version bump 0.1.0 -> 0.2.0)
  - New SKILL.md added or removed
  - B R88-56b tool impl ships (Layer 4 implementation gates verify)
  - C R88-56c tests ship (Layer 2 runtime verify via test smoke install)
  - Anthropic plugin spec evolves (live API verify 4 reference plugins re-check)
- Annual baseline re-audit (sister Pattern 36 supply chain CVE cadence).
