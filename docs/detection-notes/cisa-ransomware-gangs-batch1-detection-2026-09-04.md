<!--
Companion detection note covering FIVE unrelated ransomware/RaaS-group Sigma rules, each sourced from
a CISA #StopRansomware advisory (or equivalent CISA KEV listing) plus independent vendor corroboration:
- resources/examples/initial_access/observed_cl0p_t1190.yml
- resources/examples/initial_access/observed_play_t1190.yml
- resources/examples/initial_access/observed_rhysida_t1190.yml
- resources/examples/lateral_movement/observed_akira_t1021_001.yml
- resources/examples/initial_access/observed_ransomhouse_t1078.yml
Advisory sources: CISA AA23-158A (Cl0p/MOVEit) + Mandiant / CISA AA23-352A (Play) + FBI IC3 CSA
231218 / CISA AA23-319A (Rhysida) / CISA AA24-109A (Akira) + Cisco Talos + FBI IC3 CSA 240418 /
Unit42-Palo Alto (RansomHouse).
Detection/defense only, no exploit/PoC reproduced beyond what the advisories already published.
-->

# Five CISA-Advisory Ransomware Groups: Two Shared Detection Shapes Across Five Different Actors

Five distinct ransomware/RaaS operations, each with its own CISA #StopRansomware advisory or KEV listing plus independent vendor corroboration (Mandiant, Cisco Talos, FBI IC3, Unit42) — but notice the detection LOGIC itself: three of these five rules (Cl0p, Play, Rhysida) share the exact same `detection:` block verbatim, and two more (Akira, RansomHouse) build on the same underlying RDP-logon signal. This is not an authoring shortcut to be suspicious of — it reflects a genuinely recurring, group-agnostic TTP (web-shell-from-IIS/webserver, and RDP-based lateral movement) that multiple unrelated actors independently converge on, which several CISA advisories cited below explicitly call out as common tradecraft rather than any one group's signature.

## What each group actually does (per the cited advisory)

**1. Cl0p (CISA AA23-158A + Mandiant).** Best known for the 2023 MOVEit Transfer mass-exploitation campaign (a zero-day SQL injection chain, CVE-2023-34362) that let Cl0p deploy a web shell (`LEMURLOOT`) directly into the compromised MOVEit web application and exfiltrate data from hundreds of victim organizations in a matter of days — one of the largest single-vulnerability mass-exploitation events in recent ransomware history. This rule's detection logic targets the resulting web-shell-spawns-a-shell pattern generically, not the MOVEit-specific exploit chain itself.

**2. Play (CISA AA23-352A + FBI IC3 CSA 231218).** A double-extortion RaaS operation the FBI/CISA jointly attributed to 300+ breached organizations worldwide as of the advisory (Krispy Kreme among the publicly reported victims per BleepingComputer). Gains initial access predominantly via exploited public-facing applications (including FortiOS/FortiProxy and Microsoft Exchange vulnerabilities named in the advisory) and valid accounts, then deploys web shells for follow-on access before ransomware deployment.

**3. Rhysida (CISA AA23-319A).** A ransomware-as-a-service operation CISA's advisory attributes to opportunistic targeting of education, healthcare, manufacturing, IT, and government sectors — notably including an attack on the British Library. Gains initial access via external-facing remote services and phishing, then, per the advisory, similarly leverages web-facing application compromise leading to command execution.

**4. Akira (CISA AA24-109A + Cisco Talos + FBI IC3 CSA 240418).** One of the most active RaaS operations tracked through 2024-2026, notably including a wave of intrusions via a since-patched Cisco ASA/VPN zero-day (per BleepingComputer's reporting cited in this rule's references) — but the advisory's broader lesson is that Akira affiliates use STANDARD RDP for lateral movement once inside a network, not an exotic technique, which is exactly what this rule's detection logic targets rather than the specific initial-access vulnerability of the moment.

**5. RansomHouse (Unit42/Palo Alto + Fortiguard).** Distinctive among ransomware operations for explicitly marketing itself as a "professional mediator" between victims and their own security failures rather than a traditional RaaS brand — Unit42's writeup (cited in this rule's references) covers an encryption-scheme upgrade in RansomHouse's toolkit. Initial access commonly involves valid/reused credentials rather than a specific exploited CVE, which is why this rule's detection logic (unlike the other four in this note) targets ANY successful or failed logon rather than a webshell pattern.

## The shared detection shapes

- **Cl0p, Play, Rhysida (identical `detection:` block):** a process attributed to a webserver/app-server parent (`w3wp.exe`, `httpd.exe`, `nginx.exe`) spawning a shell/interpreter child (`cmd.exe`, `powershell.exe`, `bash`, `sh`) — the generic "web shell got a shell" pattern these three advisories all describe as part of each group's initial-access-to-execution chain, independent of which specific CVE or exposed application got them there.
- **Akira, Anubis (see this corpus's separate Anubis note; not part of this note's rule set):** `EventID: 4624` + `LogonType: 10` (interactive/RDP logon) — flags ANY successful RDP logon, deliberately broad since the advisory's point is that Akira uses ordinary RDP, not a specific malicious binary.
- **RansomHouse:** `EventID: 4624 or 4625` (successful OR failed logon) with `LogonType: 3 or 10` (network or RDP), narrowed by two exclusion filters: service accounts (`svc_` prefix) and admin-prefixed accounts on interactive RDP (`admin_` prefix + `LogonType: 10`) — a documented Phase-1a precision narrow after a real false-positive incident (a legitimate admin RDP session tripped the unfiltered version of this rule; see the rule's own inline comments for the full incident trail). The rule's own `falsepositives` field is explicit that this is a SINGLE-EVENT precision narrow standing in for proper multi-host correlation (`count() by account across hosts`) that this corpus's rule format doesn't yet support as a pySigma-portable aggregation.

## Known limitations (per rule)

**Cl0p/Play/Rhysida (shared):** any legitimate patch-management or vulnerability-scanning tool that spawns a shell on a web-server host during an authorized remediation window is expected, documented noise for all three — the rules cannot distinguish this from actual exploitation without correlating against a maintenance-window calendar or known-tool allowlist. None of the three rules encode the group-SPECIFIC initial-access vector (MOVEit's exact CVE for Cl0p, the specific exposed applications named in Play's advisory, Rhysida's phishing vector) — they detect the convergent web-shell-execution stage all three advisories describe, which means a hit attributes to "this generic TTP," not automatically to a SPECIFIC one of these three named groups without additional corroboration.

**Akira:** flags EVERY interactive RDP logon, not just malicious ones — this is intentionally broad (per the advisory's own framing that the technique itself, not a specific tool, is the signal) and requires correlation with account/host context (compare against the equivalent admin-exclusion filter this corpus's T1078 rule for RansomHouse already documents) before escalating.

**RansomHouse:** the `falsepositives` field candidly documents that this is a stop-gap single-event narrow, not the multi-host correlation the underlying actor pattern (credential reuse across hosts in a short window) actually needs — a real RansomHouse-style lateral-movement campaign using a NON-admin-prefixed, NON-service account would not be filtered out, which is correct (it should still fire), but the rule also cannot itself distinguish that from one-off legitimate access without the correlation layer the rule's own comments say is planned but not yet built.

## What to do right now

1. All five: none of these rules require a patch (they detect post-compromise TTP, not a specific exploited vulnerability) — review the cited CISA advisories directly for each group's own IOC list (file hashes, C2 infrastructure, specific exploited CVEs) to supplement these generic behavioral rules.
2. For the Cl0p/Play/Rhysida shared shape: if your environment already tracks planned patch/maintenance windows, correlate hits against that calendar before triage — this is the single highest-value tuning step for all three rules at once.
3. For Akira/RansomHouse's RDP-based signal: verify your environment has an actual admin-account naming convention or allowlist to filter against — both rules' precision depends on being able to distinguish "known admin doing known admin things" from "everyone else," and a deployment without consistent account-naming conventions will need a different exclusion strategy than the `admin_`/`svc_` prefix assumption these rules currently encode.
4. Deploy all five detection rules against process-creation (Cl0p/Play/Rhysida) or Windows security-event (Akira/RansomHouse) log sources as available.

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of five CISA-advisory-documented ransomware operations. References: [CISA AA23-158A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a), [Mandiant: MOVEit zero-day data theft](https://www.mandiant.com/resources/blog/zero-day-moveit-data-theft), [CISA AA23-352A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a), [FBI IC3 CSA 231218](https://www.ic3.gov/CSA/2023/231218.pdf), [CISA AA23-319A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-319a), [CISA AA24-109A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a), [Cisco Talos: Akira ransomware](https://blog.talosintelligence.com/akira-ransomware/), [Unit42: RansomHouse encryption upgrade](https://unit42.paloaltonetworks.com/ransomhouse-encryption-upgrade/).*
