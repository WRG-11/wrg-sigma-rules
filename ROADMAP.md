# Roadmap

This is a living direction of travel, not a delivery promise. Work is released
only when its evidence is in the repository: a test, a cited source, a
reproducible conversion result, or a documented limitation.

## Product boundary

WRG Sigma Rules is a local, deterministic detection-engineering workbench. It
helps an MCP-capable client draft, validate and convert Sigma rules; it does
not deploy detections, collect telemetry, operate a hosted service, or claim
that a generated rule is production-ready.

The corpus keeps `stable` deliberately unused. A rule earns that status only
after production evidence and environment-specific tuning, neither of which a
public, generic corpus can honestly provide.

## Current focus

### 1. Safe and reproducible MCP runtime

- Keep every MCP input boundary bounded, typed and fail-closed before YAML or
  pySigma processing.
- Keep tool responses safe to share by redacting internal-looking identifiers
  from echoed inputs and error envelopes.
- Keep the container runtime reproducible with a pinned base-image digest,
  non-root execution and automated dependency update coverage.
- Preserve parity between the checkout server and the self-contained Codex
  plugin runtime.

**Exit evidence:** full test suite, static checks, container build and a real
stdio MCP smoke exchange all pass in CI.

### 2. Trustworthy corpus growth

- Add rules only when they widen defensible actor, technique or telemetry
  coverage; raw rule count is not a goal.
- Require source, platform and telemetry-manifestation evidence for every
  `observed_*` rule, as defined in [CONTRIBUTING.md](CONTRIBUTING.md).
- Keep `template_*` rules explicit about their generic provenance and expected
  false positives.
- Add matching and non-matching sidecar evidence where the corpus test tier
  requires it, and maintain the ATT&CK coverage resource from the live corpus.

**Exit evidence:** strict validation, sample-match checks, source review and
backend conversion results are all reproducible from the submitted files.

### 3. Useful operator handoff

- Make conversion limits explicit, especially for Sigma correlation rules and
  backend-specific lossiness.
- Keep the writer, reviewer and coverage-gap skills aligned with the MCP tools
  and canonical patterns.
- Improve public installation and catalog metadata so clients can discover the
  actual tools, resources, runtime version and corpus capabilities.

**Exit evidence:** a clean install can complete the documented MCP handshake,
list the advertised surface and run the documented example without relying on
checkout-local state.

## Verified progress

The entries below are measurements from this worktree. They are not a claim
that an item has reached a public release; publication remains a separate
review and release decision.

### 2026-09-17 — runtime and corpus baseline

- **MCP runtime hardening:** tool input boundaries, response redaction and
  resource error paths received regression coverage; the checkout and bundled
  Codex runtime remain byte-for-byte parity-checked.
- **Container supply chain:** the Python base image is pinned to a
  multi-platform digest and Dependabot now monitors Docker dependencies. The
  container builds and completes the documented stdio MCP handshake as the
  non-root runtime user.
- **Runtime verification:** the full suite passed with **880 tests**. Static
  linting passed, and the container smoke exchange listed all three tools and
  both published resources before successfully calling `validate_rule` and
  reading the ATT&CK coverage matrix.
- **Corpus measurement:** **296 rules**, **91 ATT&CK techniques** and **14
  tactic categories**; coverage collection reported no unparseable or
  untagged rules. The required sidecar-sample gate passed.
- **Documentation queue:** the detection-note gap tool no longer mistakes a
  hallucinated CVSS string used as detection evidence for a vulnerability
  score. The AI-fingerprint family note now covers that review-only signal
  with a cited Google Threat Intelligence source and an explicit false-positive
  boundary. The tool currently reports **0 scored** and **0 unscored**
  observed-rule note gaps. Primary-source and context reviews documented the
  LAPSUS$, supply-chain, Play and APT45 entries' unsupported Windows event,
  process, DNS and threshold claims as test-tier hypotheses rather than actor
  attribution. A zero note-gap count means every observed entry now has a
  readable evidence-boundary record; it does **not** mean every rule has
  source-backed telemetry manifestation or is ready for promotion.
- **Evidence inventory:** `scripts/observed_evidence_inventory.py` records
  the mechanical baseline for all **228** `observed_*` files: **228** have a
  non-MITRE reference and all have a companion note. The former MITRE-only
  Megalodon entry now cites the independently reported base64 workflow payload
  while explicitly omitting unsupported campaign-correlation claims. Its attribution,
  platform and telemetry-manifestation fields deliberately remain
  `not_assessed` until a human reads the source; reference presence is not
  treated as proof.
- **Correlation conversion audit:** `scripts/correlation_conversion_audit.py`
  re-measured all **52** correlation-rule files against canonical backends.
  Splunk converted **49** and correctly reports **3** `temporal_ordered`
  type gaps; Elastic and OpenSearch Lucene report **52** capability gaps;
  OpenSearch PPL converted **52**. The audit records syntax-conversion
  envelopes only, so semantic equivalence remains `not_assessed`. A corpus-wide
  Splunk guard permits only the measured `temporal_ordered` type gap and fails
  any future unclassified conversion error.
- **Actor-labelled duplicate audit:** `scripts/duplicate_rule_check.py
  --exact-actor-logic` now normalizes generated local base-rule names and
  reports **11** exact detection/correlation-structure groups among
  actor-labelled `observed_*` rules. It also records adjacent sample hashes
  without interpreting them. The result is a reproducible review queue, not a
  provenance verdict: threshold equivalence, actor attribution and any
  consolidation or reclassification decision remain explicitly unassessed.

## Later, only with evidence

- Additional backend and processing-pipeline support, after each target has
  conversion fixtures and clear lossiness documentation.
- More correlation-rule support, after the target backend can express it and
  an end-to-end fixture proves the semantic result.
- Marketplace distribution, after the packaged runtime and install path are
  validated by the relevant client.

## Next evidence-gated execution order

This order turns the measured baselines above into small, independently
reversible improvements. It is deliberately not a target for raw rule-count
growth.

1. **Make advisory audits portable and reviewable.** Audit CLIs must accept an
   explicit corpus root, fail clearly when it is absent, and retain their
   advisory status. The duplicate audit's 11 exact-logic groups are a source
   review queue, not candidates for automatic consolidation.
   **Exit evidence:** isolated-fixture CLI tests and a reproducible JSON report.
2. **Add human-source review evidence, not mechanical certainty.** Extend the
   observed-evidence inventory only with additive fields whose values are tied
   to reviewed primary sources. Keep attribution, platform and telemetry
   manifestation `not_assessed` until that review exists; never infer them from
   an actor tag, a sample, or a conversion result.
   **Exit evidence:** cited review record plus regression coverage for its
   explicit boundary.
3. **Constrain backend claims with end-to-end fixtures.** Treat the measured
   correlation conversion gaps as capability boundaries. Add a backend only
   when its generated query and documented lossiness are proven by a fixture;
   do not relabel a syntax conversion as semantic equivalence.
   **Exit evidence:** target-specific conversion and semantic-fixture results.
4. **Keep install and runtime claims reproducible.** Evolve MCP/package
   surfaces only after checkout, bundled-runtime and clean-client handshake
   evidence agrees. Any change must preserve non-root container execution and
   response-redaction regression coverage.
   **Exit evidence:** parity, container and stdio-MCP smoke checks in the same
   change.

## Explicitly out of scope

- A hosted multi-tenant MCP service or remote telemetry collection.
- Automatic deployment or activation of generated detections.
- Marking generic public rules `stable` without production evidence.
- Growing the corpus with uncited, duplicate or merely plausible detections.

## How to contribute

Start with [CONTRIBUTING.md](CONTRIBUTING.md). For a candidate rule, include
the source evidence, run the repository checks and describe both the telemetry
assumption and the expected false positives. For runtime work, include a
regression test and preserve the bundled Codex runtime parity check.
