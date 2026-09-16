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

## Later, only with evidence

- Additional backend and processing-pipeline support, after each target has
  conversion fixtures and clear lossiness documentation.
- More correlation-rule support, after the target backend can express it and
  an end-to-end fixture proves the semantic result.
- Marketplace distribution, after the packaged runtime and install path are
  validated by the relevant client.

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
