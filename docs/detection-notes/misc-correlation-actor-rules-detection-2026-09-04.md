<!--
Companion detection note covering SIX sibling Sigma correlation rules across six unrelated named
actors:
- resources/examples/collection/observed_medusa_t1005.yml
- resources/examples/collection/observed_shinyhunters_t1213.yml
- resources/examples/command_and_control/observed_shadowbyt3_t1071.yml
- resources/examples/command_and_control/observed_shai_hulud_npm_worm_t1071.yml
- resources/examples/initial_access/observed_safepay_t1133.yml
- resources/examples/command_and_control/observed_teampcp_unc6780_t1071.yml (added 2026-09-04, from sigma_rule_farmer's queue)
All six are Sigma correlation pairs (a `status: test` base event-match rule + a `type: event_count`
correlation document). This note closes out the last of 25 correlation-rule-shaped actor entries this
corpus's multi-document YAML format caused an earlier tag-based scan to miss entirely (`yaml.safe_load`
only reads the first of two `---`-separated documents, so the actor/campaign tag living in the SECOND
document was invisible to a naive single-document parse).
Detection/defense only, no exploit/PoC reproduced.
-->

# Six More Correlation-Rule Actor Detections: Archive Staging, Repo-Access Bursts, C2 Beaconing, and External RDP

Six correlation-pair rules, closing out this corpus's full set of actor/campaign-tagged detections. Three (ShadowByt3, Shai-Hulud T1071, TeamPCP/UNC6780) share identical logic; the other three (Medusa, ShinyHunters, SafePay) are each genuinely distinct.

## What each rule actually detects

**1. Medusa Team — archive-staging burst before exfiltration (T1005, `process_creation`).** Base match: an archive utility (`7z.exe`, `rar.exe`, `winrar.exe`) or PowerShell invoked with a command line referencing user-document paths (`\Users\`, `\Documents\`, `\Desktop\`) or common sensitive file types (`.pst`, `.docx`, `.xlsx`, `.pdf`). Correlation: the same `Image` doing this more than 5 times within 10 minutes — one archive command is routine; repeated archive-and-stage activity against document directories in a short window is consistent with an attacker collecting data before exfiltration. Medusa is a CISA-advisory-documented (AA25-071A) ransomware group with 300+ claimed critical-infrastructure victims, including a confirmed Toyota Financial Services breach.

**2. ShinyHunters — repository/wiki access burst (T1213, `webserver`).** Base match: a successful (HTTP 200/206) request whose URI stem hits an internal collaboration surface (`/_api/`, `/sites/`, `/wiki/`, `/confluence/`). Correlation: the same URI stem hit more than 10 times within 10 minutes — high-volume automated scraping of an internal wiki/SharePoint/Confluence instance, as opposed to a human's ordinary browsing pattern. ShinyHunters is one of the most consequential extortion actors in this corpus's citation set: tied to the AT&T (73M customers), Snowflake-adjacent, and Instructure breaches, and the subject of a named federal criminal charge (DOJ, Seattle-area defendant) plus an FBI PSA (I-051526-PSA, 2026-05-15).

**3. ShadowByt3$, 4. Shai-Hulud (npm worm) T1071, and 6. TeamPCP/UNC6780 — identical C2-beaconing signature (`network_connection`).** All three share byte-identical base logic: a scripting-capable process (`powershell.exe`, `cmd.exe`, `wscript.exe`, `mshta.exe`, `rundll32.exe`) making an outbound connection on a common web port (80, 443, 8080, 8443) — a deliberately broad, low-specificity pattern (any of these five interpreters reaching any of these four ports covers an enormous amount of both malicious C2 traffic AND completely ordinary automation/RMM/update-checking behavior). The rules differ only in correlation window/threshold: ShadowByt3$ fires at 30+ connections to the same `DestinationHostname` within 30 minutes; Shai-Hulud's and TeamPCP/UNC6780's variants both fire at 31+ in the same window — functionally the same cutoff. ShadowByt3$ is a less-documented ransomware group (Barricade Cyber CTI report, ransomware.live profile, including Syngenta/Crop Wise as a named victim); the Shai-Hulud rule is the campaign's C2-beaconing-stage signature (see `nx-shai-hulud-npm-worm-cluster-detection-2026-09-04.md` for the rest of that cluster). TeamPCP/UNC6780 (added 2026-09-04) is this corpus's most heavily-cited actor by reference count (18 sources) — tied to the Megalodon mass GitHub Actions supply-chain attack (5,561+ repositories, StepSecurity/TheRegister/SecurityWeek/CyberNews coverage), the Mini Shai-Hulud npm worm's resurgence, and a supply-chain compromise of security-tooling projects (Trivy, Checkmarx, KICS, LiteLLM per Kaspersky/SANS/Arctic Wolf) — level: critical, the highest severity in this note, reflecting that documented breadth. This rule's own `level: critical` is a genuine outlier worth flagging: unlike the T1567/T1486 clusters where severity mostly tracked citation volume, here the SAME weak/broad C2-beacon signature carries `informational` (ShadowByt3$), `high` (Shai-Hulud), and `critical` (TeamPCP/UNC6780) across three actors — a reminder that this note's opening caveat (byte-identical detection, level reflects the actor's track record not the signal's strength) applies with unusual force to this specific trio.

**5. SafePay — external remote-service logon burst (T1133, `security` service).** Base match: a successful logon (`EventID 4624`, `LogonType 10` — RemoteInteractive/RDP) from a source IP that is NOT in a private range (`10.`, `172.`, `192.168.`, or a blank `-` placeholder are excluded). Correlation: more than 5 such non-internal RDP logons from the SAME source IP within 10 minutes — repeated successful external RDP access from one address, consistent with a remote-access foothold being established or an already-compromised external account being used repeatedly. SafePay is documented via Bitdefender, Infosecurity Magazine, and Check Point's own dedicated TTP writeup, with a specific citation to the 2025 Ingram Micro breach (42,000 people affected).

## Known limitations (per rule)

**Medusa (T1005)** cannot distinguish this pattern from IT/backup staff running scheduled archive-and-backup jobs against user document directories — named explicitly in its own falsepositives field; deploying this without excluding known backup-service accounts/processes will generate routine noise.

**ShinyHunters (T1213)** will alias against normal high-volume internal collaboration traffic during business hours (a SharePoint/Confluence instance under ordinary heavy use) — its own falsepositives field says so directly; this rule needs baseline tuning against your own environment's typical access volume before the 10-in-10-minutes threshold is meaningful.

**ShadowByt3$/Shai-Hulud/TeamPCP-UNC6780 (T1071)** share the weakest, broadest signature in this whole note — RMM tooling, update checkers, telemetry agents, and any legitimate automation making frequent HTTPS calls from a scripting host will cross a 30-in-30-minutes threshold routinely in many environments. The falsepositives fields name "legitimate RMM or automation tooling" explicitly. Treat a hit here as a starting point for investigation, not a high-confidence verdict — correlate with other signals before escalating, and be aware TeamPCP/UNC6780's `level: critical` reflects that ACTOR's documented severity, not this particular signal's precision (see note above).

**SafePay (T1133)** cannot distinguish this from legitimate remote employees connecting via VPN/RDS gateway from residential ISPs — explicitly named in its own falsepositives field. An environment with a large remote workforce using direct RDP (rather than a VPN concentrator that would appear as internal-range traffic) will see this rule fire on ordinary business use until a known-remote-user or known-gateway allowlist is applied locally.

## What to do with a hit

1. **Medusa/ShinyHunters** are both collection-stage signals — a hit means data is likely being staged or scraped for exfiltration; correlate with this session's exfil-host-burst cluster (T1567 note) for a fuller picture of an in-progress breach.
2. **ShadowByt3$/Shai-Hulud/TeamPCP-UNC6780 T1071** are the weakest, noisiest signals in this note — deploy them only if you can tune out your own environment's legitimate RMM/automation traffic first, or expect this to be your highest-volume, lowest-precision alert source; do not let TeamPCP/UNC6780's `critical` label override that assessment for this specific signal.
3. **SafePay** is a strong signal if your environment's RDP exposure is genuinely meant to be internal-only — build the source-IP allowlist for known remote-access infrastructure BEFORE deploying, not after the first alert storm.
4. Deploy all six against the log sources each requires (process_creation, webserver, network_connection ×3, security).

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection across six named-actor techniques. References: [CISA AA25-071A (Medusa)](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a), [FBI IC3 CSA 250312 (Medusa)](https://www.ic3.gov/CSA/2025/250312.pdf), [FBI PSA I-051526-PSA (ShinyHunters)](https://www.ic3.gov/PSA/2026/PSA260515), [Barricade Cyber: ShadowByt3$ CTI Report](https://barricadecyber.com/cti-report-shadowbyt3-ransomware-group/), [Bitdefender: SafePay Ransomware Attacks TTPs](https://www.bitdefender.com/en-us/blog/businessinsights/safepay-ransomware-attacks-ttps), [Check Point: SafePay Ransomware](https://www.checkpoint.com/cyber-hub/threat-prevention/ransomware/safepay-ransomware/), [StepSecurity: binding.gyp npm supply chain attack](https://www.stepsecurity.io/blog/binding-gyp-npm-supply-chain-attack-spreads-like-worm), [StepSecurity: Megalodon mass GitHub Actions secret exfiltration](https://www.stepsecurity.io/blog/megalodon-mass-github-actions-secret-exfiltration-across-5-500-public-repositories), [Kaspersky: Trivy/LiteLLM/Checkmarx supply chain attack](https://www.kaspersky.com/blog/critical-supply-chain-attack-trivy-litellm-checkmarx-teampcp/55510/).*
