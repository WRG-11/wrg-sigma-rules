<!--
Companion detection note for ONE shared Sigma rule that carries seven actor tags:
- resources/examples/impact/observed_shared_t1486_ransom_extension_write_burst.yml (shared rule; merged 2026-09-30 from single-actor files)
Until 2026-09-30 the same logic lived in seven single-actor files (observed_blackwater_t1486,
observed_crpxo_t1486, observed_genesis_t1486, observed_global_secret_group_t1486,
observed_lockbit_t1486, observed_panzer_t1486, observed_securotrop_t1486). They were merged into
the shared rule; its `related` field lists their ids with `type: merged`. The rule is a Sigma
correlation pair (a `status: test` base event-match rule + a `type: event_count` correlation
document).
Detection/defense only, no exploit/PoC reproduced.
-->

# One Shared Signature, Seven Actors: Ransomware File-Extension Write Burst

Same pattern as the T1567 exfil-host note: this corpus used to ship this signature as seven single-actor rules with an identical field, identical modifier and identical eight-item extension list. On 2026-09-30 they were merged into one shared rule that carries all seven actor tags. It is the corpus's generic ransomware-encryption-in-progress signature, mechanically attributed to seven named actors rather than encoding anything actor-specific.

## The shared detection logic

**Base rule** (`file_event` logsource): a single file write whose `TargetFilename` ends with one of eight known ransomware-appended extensions — `.encrypted`, `.locked`, `.enc`, `.crypto`, `.lockbit`, `.alphv`, `.akira`, `.clop`. One such write, alone, is not the alert (encryption tooling, archival software, and other legitimate processes can produce a single file with one of these extensions).

**Correlation rule**: the alert fires only when the SAME `Image` (the process doing the writing) produces this pattern at least 21 times (`gte: 21`) within a **5-minute window**. LockBit's file wrote the threshold as `gt: 20`; for an integer event count that selects exactly the same groups, so it merged into the same rule. A high bar deliberately — mass, rapid, same-process file renaming at this volume is what actual ransomware encryption looks like; a handful of files is not.

## What used to differ between the seven files

Only the actor name, `date`/`references`, and `level` (ranged `informational` through `high`) varied — same shape as the T1567 note: severity reflected each actor's own documented track record, not this detection's strength. The shared rule keeps every actor's references and the highest member level (`high`).

## Per-actor attribution

- **Genesis** — same actor as this note's T1567 sibling; 9 claimed breaches, 2 observed incidents in this corpus.
- **Global Secret Group** — Macofin Hellas S.A. breach (2026-08).
- **LockBit** — the corpus's oldest entry in this cluster (dated 2023-02-23, predating the templated authoring of the other files), citing the **Royal Mail** breach (BBC, BleepingComputer) and MITRE's own LockBit software profile (S1202). Its extension list covered OTHER actors' extensions too (`.alphv`, `.akira`, `.clop` alongside `.lockbit`) — the rule never fired only on LockBit's own extension, it fires on any of the eight.
- **Panzer** — Minor Food Group breach (2026-08).
- **Securotrop** — Structural Component Systems breach; sourced partly from a direct interview with the group (suspectfile.com).
- **Blackwater** (added 2026-09-04) — Shenzhen Gongjin Electronics breach (2026-04), via galaxywarden.com + SOCRadar + ransomware.live.
- **CRPxO** (added 2026-09-04) — Hyundai Turkey breach claim, via SOCRadar + cyberpress.org + SC Media (notable for an "OnlyFans lure" social-engineering angle reported alongside the ransomware campaign) + ransomware.live.

## Known limitations

**The extension list only covers historical/documented families.** Modern ransomware frequently uses randomized or per-victim-unique extensions specifically to evade static extension-based detection like this — a well-resourced or simply newer operator whose extension isn't one of these eight (including the actors named here, whose OWN group could easily rotate to a new extension on their next campaign) will not trigger this rule at all.

**The 21-in-5-minutes threshold can be evaded by throttling** — an attacker aware of volume-based detection (or simply encrypting a smaller, higher-value subset of files rather than a bulk sweep) stays under threshold trivially. It can also be evaded by using MULTIPLE processes to spread the write volume across several `Image` values, since the correlation groups by `Image` specifically, not by host or user.

**False-positive surface**: legitimate encryption/compression tooling (BitLocker-adjacent utilities, some backup/archival software, or IT re-encrypting a large directory as part of routine data-protection work) that happens to use one of these eight extensions and processes many files quickly from one process could cross threshold. This is explicitly named in the rule's falsepositives field ("Backup or archival software writing container files with an unusual extension into user directories").

**Attribution confidence varies far more than the rule suggests** — same caveat as the T1567 note: before the merge a Genesis/LockBit hit came from a `level: high` file and a Global Secret Group/Panzer hit from a `level: informational` one, on identical evidence. The shared rule's `high` describes the most severe actor's documented history, not this detection's strength.

## What to do with a hit

1. Treat any hit as "mass file-extension-changing activity by one process occurred" — this is a strong signal of active ransomware encryption regardless of which (if any) of these actor labels is attached; do not wait for actor confirmation before initiating incident response.
2. This is a LAGGING indicator — by the time 21+ files have been renamed in 5 minutes, encryption is already well underway. Pair with earlier-stage signals (this corpus's LSASS-dump, exfil-host-burst, and initial-access rules) for detection BEFORE the impact stage, not only at it.
3. Extend the extension list locally with any newer ransomware family extensions relevant to your threat landscape — eight hardcoded strings will not keep pace with an evolving ransomware ecosystem on their own.
4. Deploy the rule once. The seven separate files it replaced existed for per-actor reporting and tagging, not sevenfold detection value; the actor tags now sit on the one rule.

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of a generic, actor-attributed ransomware-impact signature. Per-actor references are listed above; MITRE ATT&CK: [T1486](https://attack.mitre.org/techniques/T1486/).*
