<!--
Companion detection note covering FOUR unrelated named-actor Sigma rules (batch 2 of 3 in this
secondary-source cluster), grouped for authoring efficiency. Same caveat as batch 1: these are
templated actor-attributed rules built on generic technique detections and secondary/aggregator
sourcing, not vendor-confirmed CVE chains.
- resources/examples/impact/observed_stormous_ransomware_operator_t1490.yml
- resources/examples/initial_access/observed_auditteam_t1078.yml
- resources/examples/initial_access/observed_blackwater_t1133.yml
- resources/examples/initial_access/observed_killsec_t1190.yml
Detection/defense only, no exploit/PoC involved.
-->

# Four More Named-Actor Signatures: Stormous's Shadow-Copy Wipe, AuditTeam's Anomalous Logon, Blackwater's External RDP, KillSec's Webshell Spawn

Four more Sigma rules attributed to named actors/groups, continuing this corpus's secondary-source cluster (see `secondary-source-threat-groups-batch1-detection-2026-09-04.md` for the shared framing: generic technique detection, actor attribution via breach-catalog association rather than a unique behavioral fingerprint).

## What each rule actually detects

**1. Stormous — the identical shadow-copy-deletion pattern as Dire Wolf (T1490).** This rule's `detection:` block is BYTE-IDENTICAL to `observed_direwolf_t1490.yml`'s (`vssadmin`/`wmic`/`wbadmin` + `delete shadows`/`shadowcopy delete`/`delete catalog`) — the only differences are the rule's metadata and `level: informational` instead of `medium` (the rule's own authors apparently rated Stormous's version of this signal as carrying less standalone significance). Sourcing is the weakest in this note: an X.com search query and a single ransomware.live catalog entry, no named technical write-up.

**2. AuditTeam — anomalous interactive/RDP logon after filtering service and known-admin accounts (T1078).** The rule carries unusually detailed inline authoring comments (preserved in the YAML, worth reading directly) documenting a real false-positive fix cycle: an earlier version fired on legitimate admin RDP sessions, and a `filter_legit_admin_interactive_rdp` exclusion (LogonType 10 + `admin_`-prefixed account) was added as what the comments explicitly label a "Phase 1a stop-gap," with the SAME comments noting the actor's real signature is multi-host credential reuse within a short window — something this single-event rule structurally cannot detect without a correlation-rule pairing the corpus's format doesn't yet support. This is worth reading as a rule that is honest, in its own source comments, about its own detection gap.

**3. Blackwater — external-source RDP logon (T1133).** Sourced from a single incident report (a Shenzhen Gongjin Electronics breach write-up) plus secondary aggregators. The detection logic is a bare `EventID 4624 + LogonType 10` (successful interactive/RDP logon) excluding RFC1918 private-IP source ranges — this is the generic "external RDP logon" pattern, with no Blackwater-specific indicator at all.

**4. KillSec — a shell process spawned from a webserver worker process (T1190).** The detection logic (`w3wp.exe`/`httpd.exe`/`nginx.exe` spawning `cmd.exe`/`powershell.exe`/`bash`/`sh`) is the textbook webshell-execution signature — and, as this note's companion batch-3 file documents, is BYTE-IDENTICAL to two other actors' rules in this corpus (`observed_nightspire_t1190.yml`, `observed_nova_t1190.yml`). This is a generic web-shell IOC any of dozens of actors exploiting any web-facing vulnerability could produce, not evidence specific to KillSec.

## The detection signals

- **#1 (process_creation):** identical to Dire Wolf's — `vssadmin.exe`/`wmic.exe`/`wbadmin.exe` with a command line containing `delete shadows`/`shadowcopy delete`/`delete catalog`.
- **#2 (windows/security):** `EventID` 4624 or 4625 with `LogonType` 3 or 10, excluding `svc_`-prefixed accounts and `admin_`-prefixed accounts logging in via RDP (LogonType 10).
- **#3 (windows/security):** `EventID` 4624 with `LogonType` 10, excluding source IPs starting with `10.`, `172.`, `192.168.`, or `-` (no logged IP).
- **#4 (process_creation):** `ParentImage` ending in `w3wp.exe`/`httpd.exe`/`nginx.exe`, `Image` ending in `cmd.exe`/`powershell.exe`/`bash`/`sh`.

## Known limitations (per rule)

**#1** is functionally the SAME rule as Dire Wolf's under a different actor label — see batch 1's note for the shared limitation (near-universal ransomware-impact pattern, expect legitimate backup/DR noise). The `level: informational` grading here (vs. `medium` for Dire Wolf) suggests even this corpus's own authoring treated the Stormous attribution as lower-confidence than Dire Wolf's.

**#2**'s own inline comments already document its limitation better than an external note could: it is explicitly a "single-event precision narrow" standing in for a correlation rule that does not yet exist in this corpus's format. A single hit is weak evidence on its own — the actual AuditTeam signature (per the rule's own documentation) is the SAME account authenticating across MULTIPLE hosts in a short window, which this rule cannot see.

**#3** cannot distinguish a legitimate remote-office/VPN-terminated external RDP session (common in distributed or remote-first organizations) from malicious external access — narrow this against your organization's actual known-external-access inventory (VPN gateway ranges, approved remote-admin jump hosts) before treating a hit as suspicious.

**#4** cannot distinguish a legitimate WAF/APM/monitoring agent's diagnostic shell spawn, or scheduled web-application maintenance scripts, from actual webshell exploitation — and because the identical pattern is shared across at least three actor-labeled rules in this corpus, a hit's actor attribution should be treated as essentially unsupported without additional corroborating evidence (the specific vulnerability exploited, post-exploitation IOCs matching a documented KillSec toolset).

## What to do with a hit

1. **#1**: correlate with other ransomware impact-stage indicators before escalating; do not treat Stormous attribution as more confident than Dire Wolf's identical pattern would be.
2. **#2**: a single hit should prompt a search for the SAME account authenticating from multiple hosts in the surrounding time window — that correlation, not this rule alone, is what would actually confirm the documented AuditTeam pattern.
3. **#3**: cross-check the source IP against your own known-external-access inventory before escalating.
4. **#4**: investigate the actual vulnerability that let a process reach the webserver worker in the first place — the webshell-spawn signal is generic; the entry vector is where actor-specific evidence would actually live.
5. Deploy all four detection rules against the log sources each requires; treat every hit here as an investigation starting point, not a confirmed actor attribution.

---

*Detection content from WinstonRedGuard (WRG-11). Generic-technique detections associated with named threat actors via secondary/aggregator sourcing. References: [ransomware.live: Stormous](https://www.ransomware.live/id/U0EyMDAwLkNPTUBzdG9ybW91cw==), [ransomware.live: AuditTeam](https://www.ransomware.live/group/AuditTeam), [galaxywarden: Blackwater/Shenzhen Gongjin breach](https://www.galaxywarden.com/blog/breach/shenzhen-gongjin-electronics-blackwater-2026-04), [halcyon.ai: KillSec](https://www.halcyon.ai/threat-group/killsec).*
