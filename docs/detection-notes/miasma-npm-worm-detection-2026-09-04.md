<!--
Companion detection note covering THREE sibling Sigma rules for a single campaign (the "Miasma" /
"Phantom Gyp" npm supply-chain worm), each covering one stage of the same attack chain:
- resources/examples/initial_access/observed_miasma_binding_gyp_command_substitution_t1195_002.yml
- resources/examples/exfiltration/observed_miasma_github_graphql_exfil_t1567_001.yml
- resources/examples/persistence/observed_miasma_ai_ide_config_poisoning_t1546.yml
Sources: StepSecurity blog + Snyk blog (independent corroboration), 2026-06-03/04.
Detection/defense only, no exploit/PoC reproduced beyond what the two source blogs already published.
-->

# Detecting the Miasma npm Worm's Full Chain: Gyp Command Substitution, GraphQL Exfil, AI-IDE Persistence

Three Sigma rules covering three stages of a single self-propagating npm worm ("Miasma" / "Phantom Gyp") that compromised 57 npm packages across 286+ malicious versions in a rolling campaign under two hours in June 2026 — first observed via `@vapi-ai/server-sdk` (408,000+ monthly downloads). All three rules are corroborated by two independent technical write-ups (StepSecurity primary disclosure, Snyk corroboration) that agree down to the exact same 157-byte `binding.gyp` body and file-path lists.

## What each stage actually does

**1. Initial access — a build file that runs a command, not a compiler (T1195.002).** node-gyp's `<!(...)` command-substitution syntax lets a `binding.gyp` file run an arbitrary shell command during the CONFIGURE phase, before any compiler runs. The worm's `binding.gyp` is `"sources": ["<!(node index.js > /dev/null 2>&1 && echo stub.c)"]` with `"type": "none"` — nothing is actually compiled; the command's side effect is the entire point. npm auto-invokes `node-gyp rebuild` whenever it sees a `binding.gyp` file, with no `preinstall`/`postinstall` script declared in `package.json` — invisible to any tooling that only watches install-hook fields. The `index.js` payload is a 4.5MB obfuscated loader (ROT-14, then AES-128-GCM self-decryption) that downloads and runs a Bun runtime binary to execute the actual credential-stealer payload under Bun instead of Node — so process-tree monitoring that only watches for `node.exe` children never sees the credential-theft stage.

**2. Exfiltration — API-mediated commits, not a local git push (T1567.001).** Using credentials the gyp stage harvested, the worm's exfiltration/propagation logic uses the stolen GitHub token two ways: self-propagation via the GraphQL API's `createCommitOnBranch` mutation (commits through the API with only a stolen token, no local git working tree needed), and exfiltration of RSA-encrypted stolen secrets as JSON uploaded to newly created private GitHub repos under a single controller account (`liuende501`, ~236 repos observed), named from two fixed theme sets StepSecurity documents verbatim — Dune terms (`atreides`, `fedaykin`, `sardaukar`, `tleilaxu`) and Greek-mythology terms (`nemean-hydra`, `cerberus`, `chimera`).

**3. Persistence — poisoning every AI-IDE integration it can find (T1546).** The standout TTP of the campaign, and as of authoring not covered by any other rule in this corpus: instead of (or in addition to) classic host persistence, the worm writes auto-executing config files into every AI-assisted IDE/agent integration in the poisoned project tree, so the backdoor re-fires the next time a developer opens the project with an AI coding tool — `.claude/setup.mjs` + `.claude/settings.json` (Claude Code), `.cursor/rules/setup.mdc` (Cursor), `.gemini/settings.json` (Gemini), `.vscode/tasks.json` (`runOn: folderOpen`) + `.vscode/setup.mjs` (VS Code), `.github/setup.js` (GitHub Actions). Both source blogs independently list this same six-path set. Social-engineering cover text: "This is required for proper IDE integration and dependency setup."

## The detection signals

- **Stage 1:** a `node-gyp rebuild`/`configure` step spawned by an npm-family package manager, immediately followed by a Bun binary being downloaded/executed as a child of the same install lineage — Bun has no legitimate reason to appear inside a native-addon compile step.
- **Stage 2:** an npm-install-lineage process combined with EITHER the `createCommitOnBranch` GraphQL mutation name OR the exfil path/repo-naming pattern (`results/results-`, the Dune/Greek theme words) — deliberately `level: medium` since the naming-pattern half alone is weaker evidence (a coincidentally-named `cerberus-monitoring` repo is plausible).
- **Stage 3:** creation of any of the six AI-IDE auto-executing config paths, attributed to a process descending from an npm-family package manager — NOT a developer hand-authoring one of these files, which is a normal, high-volume event this rule must not fire on. The process-lineage condition is load-bearing, not decorative.

## Known limitations (per rule)

**Stage 1** cannot fully rule out a developer legitimately using Bun as their primary JS runtime where a native-addon build and a Bun invocation happen to occur close together for unrelated reasons — correlate with a preceding `binding.gyp`-triggered `node-gyp` step from a freshly-installed package, not a long-lived project's own build pipeline.

**Stage 2**'s naming-pattern selection is inherently weaker than its GraphQL-mutation-name selection; do not escalate on a naming-only hit without either the mutation-name signal or external corroboration.

**Stage 3** is entirely dependent on the log source being able to attribute file writes to a specific process image — if it can't distinguish an npm-family writer from an editor/IDE process itself, this rule cannot be safely deployed as written. CI scaffolding that legitimately generates one of these six paths as part of a repo template/bootstrap step is a plausible source of noise; exclude by known-good CI runner identity.

Mapped to the T1546 PARENT technique (Event Triggered Execution) deliberately, not a sub-technique — none of the existing sub-techniques (change-default-file-association, screensaver, etc.) describes "an AI coding assistant's own project-open hook," so the rule does not force a fit that is not there.

## What to do right now

1. Audit for the exact `binding.gyp` command-substitution idiom (`<!(...)` combined with `"type": "none"`) in any recently-added dependency.
2. Any process descending from an npm-family package manager reaching Bun's download/exec surface is worth an immediate look, independent of whether this specific worm is present — it's a generalizable evasion technique (compile-step-spawns-a-different-runtime), not just this campaign's signature.
3. If your org uses Claude Code, Cursor, Gemini, VS Code tasks, or GitHub Actions setup scripts, treat any of the six listed auto-executing paths appearing in a freshly-cloned/installed project as suspect until reviewed — these are designed to fire without any user action beyond opening the project.
4. Deploy all three detection rules against the log sources each requires (process-creation for stages 1 and 2's process-lineage half; file-event for stage 3).

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of an actively-propagating npm supply-chain worm. References: [StepSecurity: binding.gyp npm supply chain attack spreads like worm](https://www.stepsecurity.io/blog/binding-gyp-npm-supply-chain-attack-spreads-like-worm), [Snyk: node-gyp supply chain compromise](https://snyk.io/blog/node-gyp-supply-chain-compromise-self-propagating-npm-worm-binding-gyp/).*
