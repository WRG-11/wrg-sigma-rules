<!--
Companion detection note covering FOUR unrelated named-actor Sigma rules (batch 3 of 3 in this
secondary-source cluster), grouped for authoring efficiency. Same caveat as batches 1-2: these are
templated actor-attributed rules built on generic technique detections and secondary/aggregator
sourcing, not vendor-confirmed CVE chains. LAPSUS$ is the one partial exception -- it has a
genuine, well-documented 2022 incident (Vodafone Portugal) behind it.
- resources/examples/initial_access/observed_lapsus_t1078.yml
- resources/examples/initial_access/observed_nightspire_t1190.yml
- resources/examples/initial_access/observed_nova_t1190.yml
- resources/examples/initial_access/observed_xpl0itrs_t1195.yml
Detection/defense only, no exploit/PoC involved.
-->

# Four More Named-Actor Signatures: LAPSUS$'s Anomalous Logon, NightSpire's and Nova's Webshell Spawn, Xpl0itrs's Unsigned Execution

The last four rules in this corpus's secondary-source actor cluster (see batch 1 and batch 2 notes for the shared framing).

## What each rule actually detects

**1. LAPSUS$ — the identical anomalous-logon pattern as AuditTeam (T1078), but with a real named incident behind it.** LAPSUS$ is a genuinely well-documented, MITRE-catalogued group (`G1004`) — this rule's references include the actual 2022 Vodafone Portugal cyberattack (BleepingComputer, The Register), a confirmed, named incident rather than an aggregator profile page. The `detection:` block is structurally identical to `observed_auditteam_t1078.yml`'s (same `EventID`/`LogonType` selection, same `svc_`/`admin_`-prefix filters, same inline comments about being a "single-event precision narrow" standing in for the correlation rule LAPSUS$'s actual multi-host-credential-reuse signature would require) — the two rules share the SAME underlying detection engineering, just attributed to two different actors. Of the two, LAPSUS$'s attribution rests on the stronger evidentiary basis (a confirmed incident vs. an aggregator's generic profile).

**2 & 3. NightSpire and Nova — BYTE-IDENTICAL webshell-spawn detection logic to KillSec's (T1190).** All three rules (`observed_killsec_t1190.yml` in batch 2, plus these two) share the exact same `detection:` block: a shell process (`cmd.exe`/`powershell.exe`/`bash`/`sh`) spawned from a webserver worker process (`w3wp.exe`/`httpd.exe`/`nginx.exe`). NightSpire is documented (socradar, Picus Security, Barracuda) as an active 2026 ransomware group; Nova is documented (Xcitium, Cyjax) as a rebrand of the earlier RALord RaaS operation. Neither rule's detection LOGIC distinguishes itself from the other two actors sharing the identical pattern — the only thing differentiating these three rules from each other is the `tags:` actor label and the `falsepositives:` prose, not the actual detection mechanism.

**4. Xpl0itrs — unsigned executable/installer run from a staging directory (T1195, supply chain).** Xpl0itrs is sourced entirely from Dataminr intel briefs (three of them) documenting leak-site claims against Spotify, OpenAI, Treasury, Trustpilot, and RapidFort — claimed breaches, not independently confirmed by a second source in the material available. The detection logic (an unsigned `.exe`/`.msi`/`.dll` run from a Temp/Downloads/Installers path) is a reasonable generic supply-chain/unsigned-payload heuristic, unconnected to any Xpl0itrs-specific technical indicator.

## The detection signals

- **#1 (windows/security):** `EventID` 4624 or 4625 with `LogonType` 3 or 10 (category: `authentication`, vs. AuditTeam's `service: security` — a minor logsource-declaration difference for what is otherwise the identical selection), excluding `svc_`-prefixed and RDP-via-`admin_`-prefixed accounts.
- **#2, #3 (process_creation):** identical — `ParentImage` ending in a webserver worker binary, `Image` ending in a shell binary.
- **#4 (process_creation):** `Image` under a Temp/Downloads/Installers path, ending in `.exe`/`.msi`/`.dll`, excluding anything with `Signed: true`.

## Known limitations (per rule)

**#1** carries the SAME structural limitation as AuditTeam's rule: a single-event precision narrow standing in for the correlation rule the actor's actual multi-host-credential-reuse signature requires (per the rule's own inline authoring comments). LAPSUS$'s stronger sourcing (a real confirmed incident) does not change the detection logic's limitation — it changes only how much weight to put on the ACTOR label when a hit does occur.

**#2, #3** cannot distinguish a legitimate WAF/APM/monitoring agent's diagnostic shell, or scheduled maintenance scripts, from actual webshell exploitation — same limitation documented for KillSec in batch 2. Because THREE actor-labeled rules in this corpus share this identical pattern byte-for-byte, treat the actor attribution on any hit as essentially unsupported by the rule's own logic; the entry vector that let a process reach the webserver worker is where real actor-specific evidence would live, not the webshell-spawn signal itself.

**#4** rests entirely on unconfirmed leak-site claims (per Dataminr's own framing as "claims," not confirmed breaches) — treat both the Xpl0itrs attribution AND the underlying incidents themselves as unverified. The detection logic itself (unsigned execution from a staging path) is sound as a generic heuristic but will fire on any IT-sanctioned unsigned internal tool or portable app.

## What to do with a hit

1. **#1**: search for the same account authenticating from multiple hosts in the surrounding window — same guidance as AuditTeam (batch 2); LAPSUS$'s better-documented history makes this worth prioritizing slightly higher if other indicators align (rapid privilege escalation, MFA-reset activity, social-engineering-flavored help-desk contact).
2. **#2, #3**: investigate the entry vector, not just the webshell-spawn event — this is where evidence distinguishing NightSpire, Nova, KillSec, or an unrelated fourth actor would actually surface.
3. **#4**: verify against your own file reputation/hash tooling before treating a hit as meaningful; do not treat the underlying Xpl0itrs claims as confirmed incidents without independent corroboration.
4. Deploy all four detection rules against the log sources each requires; as with batches 1-2, expect a higher baseline false-positive rate than this corpus's CVE-based rules and treat actor attribution as a hypothesis, not a conclusion.

---

*Detection content from WinstonRedGuard (WRG-11). Generic-technique detections associated with named threat actors via secondary/aggregator sourcing (LAPSUS$ partially excepted — confirmed 2022 incident). References: [MITRE ATT&CK: LAPSUS$ (G1004)](https://attack.mitre.org/groups/G1004/), [BleepingComputer: Vodafone Portugal](https://www.bleepingcomputer.com/news/security/vodafone-portugal-confirms-cyberattack-disrupted-services-nationwide/), [socradar: NightSpire](https://socradar.io/blog/dark-web-profile-nightspire-ransomware/), [Xcitium: Nova/RALord](https://threatlabsnews.xcitium.com/blog/from-ralord-to-nova-how-this-raas-gang-is-wreaking-havoc-worldwide/), [Dataminr: Xpl0itrs leak-site launch](https://www.dataminr.com/resources/intel-brief/xpl0itrs-leak-site-launch/).*
