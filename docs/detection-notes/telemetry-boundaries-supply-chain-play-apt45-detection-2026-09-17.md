<!--
Companion detection note covering three observed-rule entries whose references
provide campaign or actor context but do not establish the claimed Windows
telemetry. This note records the evidence boundary; it does not upgrade any
entry to production-ready or actor-attributed detection.
- resources/examples/defense_evasion/observed_unknown_supply_chain_2026_05_t1036_005.yml
- resources/examples/lateral_movement/observed_play_t1021_002.yml
- resources/examples/resource_development/observed_apt45_t1588.yml
No exploit or PoC involved; defensive documentation only.
-->

# Supply-Chain, Play and APT45 Rules: Telemetry Boundaries

These three `observed_*` files contain a real campaign or actor reference, but
their Windows process, Security-event, or DNS selections are detection-engineering
hypotheses. A cited report can establish that a campaign happened without
establishing how its activity appears in the local telemetry used by a Sigma
rule. All three therefore remain `status: test`.

## What each rule actually detects

**JDownloader supply-chain / T1036.005.** The rule flags a process whose
`OriginalFileName` resembles a Windows system binary outside the two canonical
Windows directories. That is a useful generic masquerading heuristic. The
linked campaign reporting is context for a Python-RAT supply-chain incident;
it does not establish that its payload used any of these original filenames,
paths, or Windows process fields. The report could not be independently
retrieved during this review, so this note makes no stronger claim about it.

**Play ransomware / T1021.002.** The base rule matches Windows Security event
5140 for an administrative SMB share and the correlation document alerts on
four matches per share in fifteen minutes. SMB administrative-share activity
is a generic lateral-movement signal. The cited CISA advisory is relevant
campaign context, but was unavailable to this review environment; neither it
nor the remaining references in this audit established event 5140, this
filter, or the four-in-fifteen-minutes threshold as Play-specific telemetry.

**APT45 / T1588.** The rule matches Sysmon-style DNS event 22 queries for
threat-intelligence sites made by a non-browser process. Google Threat
Intelligence reports APT45's use of repeated AI prompts to analyse CVEs and
validate proof-of-concepts. It does not report these domains, Windows DNS
telemetry, a non-browser process, or a link between the selected domains and
APT45. The rule is therefore a generic review/research heuristic, not an
APT45 detector.

## Operational handling

1. Treat each hit as the generic condition stated above, never as actor
   attribution.
2. Establish local baselines before alerting: expected software deployment
   paths, approved administrative-share workflows, and security-research
   tooling respectively.
3. Add actor-specific correlation only after a source or capture establishes
   the platform, observable fields and threshold. Until then, keep the rules
   in the test tier and do not promote them based on a successful YAML parse
   or a synthetic match.

---

*Detection content from WinstonRedGuard (WRG-11). Context sources: [Google
Threat Intelligence: adversaries leverage AI for vulnerability exploitation,
augmented operations, and initial access](https://cloud.google.com/blog/topics/threat-intelligence/ai-vulnerability-exploitation-initial-access),
[CISA AA23-352A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a),
[MITRE ATT&CK: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)
and [MITRE ATT&CK: Obtain Capabilities](https://attack.mitre.org/techniques/T1588/).
Context is not telemetry proof.*
