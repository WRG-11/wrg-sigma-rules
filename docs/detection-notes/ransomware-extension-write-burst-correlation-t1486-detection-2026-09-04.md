<!--
Companion detection note covering SEVEN sibling Sigma rules, all sharing ONE generic detection
signature (a known-ransomware-extension write burst correlation) attributed to seven different named
actors:
- resources/examples/impact/observed_genesis_t1486.yml
- resources/examples/impact/observed_global_secret_group_t1486.yml
- resources/examples/impact/observed_lockbit_t1486.yml
- resources/examples/impact/observed_panzer_t1486.yml
- resources/examples/impact/observed_securotrop_t1486.yml
- resources/examples/impact/observed_blackwater_t1486.yml (added 2026-09-04, from sigma_rule_farmer's queue)
- resources/examples/impact/observed_crpxo_t1486.yml (added 2026-09-04, from sigma_rule_farmer's queue)
All seven are Sigma correlation pairs (a `status: test` base event-match rule + a `type: event_count`
correlation document).
Detection/defense only, no exploit/PoC reproduced.
-->

# Seven "Actor-Specific" Rules, One Shared Signature: Ransomware File-Extension Write Burst

Same pattern as this session's T1567 exfil-host cluster note: read one of these seven rules' `detection:` block and you have read all seven — identical field, identical modifier, identical eight-item extension list. This is the corpus's generic ransomware-encryption-in-progress signature, mechanically attributed to seven named actors rather than encoding anything actor-specific.

## The shared detection logic (identical across all seven)

**Base rule** (`file_event` logsource): a single file write whose `TargetFilename` ends with one of eight known ransomware-appended extensions — `.encrypted`, `.locked`, `.enc`, `.crypto`, `.lockbit`, `.alphv`, `.akira`, `.clop`. One such write, alone, is not the alert (encryption tooling, archival software, and other legitimate processes can produce a single file with one of these extensions).

**Correlation rule**: the alert fires only when the SAME `Image` (the process doing the writing) produces this pattern repeatedly within a **5-minute window** — threshold is `gte: 21` for five of the seven (Genesis, Global Secret Group, Panzer, Securotrop, Blackwater, Crpxo) and `gt: 20` for LockBit (functionally identical: 21-or-more). A high bar deliberately — mass, rapid, same-process file renaming at this volume is what actual ransomware encryption looks like; a handful of files is not.

## What differs between the seven rules

Only the actor name, `date`/`references`, and `level` (ranges `low` through `high`) vary — same shape as the T1567 cluster: severity reflects each actor's own documented track record, not anything about this specific detection's strength.

## Per-actor attribution

- **Genesis** — same actor as this note's T1567 sibling; 9 claimed breaches, 2 observed incidents in this corpus.
- **Global Secret Group** — Macofin Hellas S.A. breach (2026-08).
- **LockBit** — the corpus's oldest entry in this cluster (dated 2023-02-23, predating the "WRG Breach Intel — Phase 6" templated-authoring era the other four rules share), citing the **Royal Mail** breach (BBC, BleepingComputer) and MITRE's own LockBit software profile (S1202). Notably its extension list is a superset placeholder covering OTHER actors' extensions too (`.alphv`, `.akira`, `.clop` alongside `.lockbit`) — this rule doesn't only fire on LockBit's own extension, it fires on any of the eight.
- **Panzer** — Minor Food Group breach (2026-08).
- **Securotrop** — Structural Component Systems breach; sourced partly from a direct interview with the group (suspectfile.com).
- **Blackwater** (added 2026-09-04) — Shenzhen Gongjin Electronics breach (2026-04), via galaxywarden.com + SOCRadar + ransomware.live.
- **CRPxO** (added 2026-09-04) — Hyundai Turkey breach claim, via SOCRadar + cyberpress.org + SC Media (notable for an "OnlyFans lure" social-engineering angle reported alongside the ransomware campaign) + ransomware.live.

## Known limitations (shared across all five)

**The extension list only covers historical/documented families.** Modern ransomware frequently uses randomized or per-victim-unique extensions specifically to evade static extension-based detection like this — a well-resourced or simply newer operator whose extension isn't one of these eight (including the four actors named here whose OWN group could easily rotate to a new extension on their next campaign) will not trigger this rule at all.

**The 21-in-5-minutes threshold can be evaded by throttling** — an attacker aware of volume-based detection (or simply encrypting a smaller, higher-value subset of files rather than a bulk sweep) stays under threshold trivially. It can also be evaded by using MULTIPLE processes to spread the write volume across several `Image` values, since the correlation groups by `Image` specifically, not by host or user.

**False-positive surface**: legitimate encryption/compression tooling (BitLocker-adjacent utilities, some backup/archival software, or IT re-encrypting a large directory as part of routine data-protection work) that happens to use one of these eight extensions and processes many files quickly from one process could cross threshold. This is explicitly named in LockBit's own falsepositives field ("Backup or archival software writing container files with an unusual extension into user directories").

**Attribution confidence varies far more than the rules themselves suggest** — same caveat as the T1567 note: a `level: high` Genesis/LockBit hit and a `level: informational` Global Secret Group/Panzer hit encode identical underlying evidence; the level reflects the actor's own documented history, not this detection's strength.

## What to do with a hit

1. Treat any hit as "mass file-extension-changing activity by one process occurred" — this is a strong signal of active ransomware encryption regardless of which (if any) of these five actor labels is attached; do not wait for actor confirmation before initiating incident response.
2. This is a LAGGING indicator — by the time 21+ files have been renamed in 5 minutes, encryption is already well underway. Pair with earlier-stage signals (this corpus's LSASS-dump, exfil-host-burst, and initial-access rules) for detection BEFORE the impact stage, not only at it.
3. Extend the extension list locally with any newer ransomware family extensions relevant to your threat landscape — eight hardcoded strings will not keep pace with an evolving ransomware ecosystem on their own.
4. As with the T1567 cluster, there is no elevenfold (here, sevenfold) detection value in deploying all seven separately — the shared logic fires once per actual event regardless of which actor-labeled copy processes it; the separate files exist for per-actor reporting/tagging.

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of a generic, actor-attributed ransomware-impact signature. Per-actor references are listed above; MITRE ATT&CK: [T1486](https://attack.mitre.org/techniques/T1486/).*
