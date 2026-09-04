<!--
Companion detection note covering FOURTEEN sibling Sigma rules, all sharing ONE generic detection
signature (a known-exfil-hostname burst correlation) attributed to fourteen different named actors:
- resources/examples/exfiltration/observed_barracuda_t1567.yml
- resources/examples/exfiltration/observed_emperador_t1567.yml
- resources/examples/exfiltration/observed_genesis_t1567.yml
- resources/examples/exfiltration/observed_global_secret_group_t1567.yml
- resources/examples/exfiltration/observed_kairos_t1567_002.yml
- resources/examples/exfiltration/observed_krybit_t1567.yml
- resources/examples/exfiltration/observed_ms13_089_t1567.yml
- resources/examples/exfiltration/observed_panzer_t1567.yml
- resources/examples/exfiltration/observed_securotrop_t1567.yml
- resources/examples/exfiltration/observed_shai_hulud_npm_worm_t1567.yml
- resources/examples/exfiltration/observed_worldleaks_t1567.yml
- resources/examples/exfiltration/observed_blackwater_t1567.yml (added 2026-09-04, from sigma_rule_farmer's queue)
- resources/examples/exfiltration/observed_crpxo_t1567.yml (added 2026-09-04, from sigma_rule_farmer's queue)
- resources/examples/exfiltration/observed_unknown_supply_chain_2025_03_t1567.yml (added 2026-09-04, from sigma_rule_farmer's queue)
All fourteen are Sigma correlation pairs (a `status: test` base event-match rule + a `type: event_count`
correlation document). Sources vary per actor (see per-actor list below); this note documents both
the shared mechanism and each actor's own attribution basis honestly, rather than writing as if each
rule encoded actor-specific tradecraft it does not actually contain.
Detection/defense only, no exploit/PoC reproduced.
-->

# Fourteen "Actor-Specific" Rules, One Shared Signature: Known Exfil-Hostname Burst Detection

Read the `detection:` block of any one of these fourteen rules and you have read all fourteen — **identical, byte-for-byte**, down to the exact same five hostnames in the exact same order. This is worth documenting honestly rather than writing fourteen notes that each pretend to describe a unique actor-specific technique: what these rules actually encode is ONE generic exfiltration signature, mechanically attributed to fourteen different ransomware/extortion actors because each actor has at least one documented breach in the corpus this rule set is derived from. The value here is not "this rule detects how Barracuda operates" — it's "this rule detects a common exfil channel, and fourteen named actors happen to be the ones with a citation attached."

## The shared detection logic (identical across all fourteen)

**Base rule** (`network_connection` logsource): a single outbound connection whose `DestinationHostname` contains one of five well-known file-transfer/exfiltration-capable services — `mega.nz`, `anonfiles.com`, `transfer.sh`, `send.bitwarden.com`, `file.io`. On its own, one such connection is not the alert (every rule's base-event description says so explicitly: "a single connection to a listed exfil host, on its own, is not the alert").

**Correlation rule**: the same actor's alert fires only when the SAME `DestinationHostname` is hit repeatedly within a **10-minute window** — the threshold varies slightly by rule: `gte: 4` (nine of the fourteen), `gt: 3` (KryBit, WorldLeaks — functionally the same cutoff, four-or-more), effectively identical across the set.

## What differs between the fourteen rules (the only real differentiator)

Only three things vary rule-to-rule: the actor name, the `date`/`references` fields (each actor's own documented breach and profile links), and `level` (ranges from `informational` through `high`, seemingly reflecting how well-corroborated or severe each actor's documented incident count is — WorldLeaks and Genesis, both citing multiple observed incidents, sit at `high`; single-incident, thinner-sourced entries like Global Secret Group and Panzer sit at `informational`). The detection LOGIC — the actual thing that decides whether a hit fires — does not differ at all.

## Per-actor attribution (what each rule's references actually establish)

- **Barracuda** — dexpose.io + ransomware.live, Micro-Comm Inc breach (2026-08).
- **Emperador** — dexpose.io + malware.news, City Government of Baguio breach (2026-08).
- **Genesis** — Comparitech + sosransomware.com + ransomware.live, 9 claimed data breaches (2025-09), 2 observed incidents in this corpus.
- **Global Secret Group** — dexpose.io + galaxywarden.com + mallory.ai, Macofin Hellas S.A. breach (2026-08).
- **Kairos** — SOCRadar + Malpedia + Security Affairs, notable for a documented **$1M extortion payment by a U.S. government agency**.
- **KryBit** — Halcyon + Infosecurity Magazine, notable for **infighting with a rival group (0mega/0apt) that listed each other as victims** — an unusually well-documented ransomware-ecosystem-dysfunction angle.
- **MS13-089** — RedHotCyber + WatchGuard + hendryadrian.com, a **double-extortion-WITHOUT-encryption** operator (data theft + leak-site pressure only, no ransomware payload) — Virginia Urology and DGP Commercialisti breaches.
- **Panzer** — ransomlook.io + hookphish.com, Minor Food Group breach (2026-08).
- **Securotrop** — suspectfile.com (includes a direct interview with the group) + hookphish.com + ransomware.live, Structural Component Systems breach.
- **Shai-Hulud (npm worm)** — this corpus's own well-documented npm supply-chain worm (see `nx-shai-hulud-npm-worm-cluster-detection-2026-09-04.md`); this specific rule is the campaign's exfiltration-stage signature, sharing the same generic host list as the other ten.
- **WorldLeaks** — CISA AA25-050A + Group-IB + BleepingComputer, the **rebrand of Hunters International** from a ransomware operator to a pure data-extortion (no-encryption) group — the strongest-sourced entry in this set (CISA advisory + 3 documented victim disclosures), and correspondingly the only one whose base description states 3 observed incidents.
- **Blackwater** (added 2026-09-04) — Shenzhen Gongjin Electronics breach (2026-04), via galaxywarden.com + SOCRadar + ransomware.live.
- **CRPxO** (added 2026-09-04) — Hyundai Turkey breach claim, via SOCRadar + cyberpress.org + SC Media (OnlyFans-lure social-engineering angle) + ransomware.live.
- **Unknown (tj-actions/reviewdog GHA Supply-chain 2025-03)** (added 2026-09-04) — this rule shares an actor identity with two other techniques already in this corpus (`observed_unknown_supply_chain_2025_03_t1078.yml`, `observed_unknown_supply_chain_2025_03_t1552.yml`, both added the same day — see this note's own T1078 note and the credential-access quartet note). Sourced from Unit42, Wiz, CISA alert AA25-072A-equivalent, StepSecurity, and two GHSA advisories (`ghsa-mrrh-fwg8-r2c3`, `GHSA-qmg3-hpqr-gqvc`) covering the March 2025 `tj-actions/changed-files` GitHub Action supply-chain compromise (CVE-2025-30066) — one of the best-documented CI/CD supply-chain incidents in this corpus's citation set, unlike the "unknown"-named actor label might suggest.

## Known limitations (shared across all fourteen)

**The hostname list is a coarse, easily-evaded proxy.** `mega.nz`/`anonfiles.com`/`transfer.sh`/`send.bitwarden.com`/`file.io` are five specific, well-known services — any actor (including all fourteen named here) can trivially exfiltrate through literally any OTHER file-sharing/cloud-storage endpoint not on this list and none of these fourteen rules will fire. Treat a non-match as "not detected by THIS narrow signature," never as "no exfiltration occurred."

**The burst threshold (4+ in 10 minutes) can be defeated by throttling.** An operator aware of volume-based correlation detection (or simply exfiltrating a small number of large files rather than many small ones) stays under the threshold trivially.

**False-positive surface is real and shared**: legitimate use of any of these five services (a developer using `transfer.sh` for a large build artifact, an employee using Bitwarden Send for a password rotation, anyone with a personal Mega.nz account syncing files from a work machine) can cross the 4-in-10-minutes threshold during ordinary bursty use (e.g. a folder sync uploading many small files that resolve to repeat connections to the same hostname).

**Attribution confidence varies far more than the rules themselves suggest.** A `level: high` Genesis/WorldLeaks hit and a `level: informational` Global Secret Group/Panzer hit encode the EXACT SAME underlying evidence (a hostname burst) — the level difference reflects how well-sourced the actor's OWN separate breach history is, not anything about the strength of THIS specific detection. Do not read "high severity" here as "this evidence is stronger"; read it as "this actor's overall track record, per the cited sources, is more severe/prolific."

## What to do with a hit

1. Treat any hit from this rule family as "an exfiltration-shaped burst against a known file-sharing service occurred" — full stop. Do NOT treat the specific actor label as an attribution claim; the rule that fired tells you nothing about WHICH of these fourteen (or any other) actor is actually responsible, since all fourteen fire on identical evidence.
2. Extend the hostname list locally to cover file-sharing services actually observed in your own environment's threat landscape (WeTransfer, Dropbox Transfer, GoFile, various paste sites) — the five hardcoded here are a starting point, not a comprehensive list.
3. If you want genuine per-actor detection value from this corpus, look instead at rules with actor-specific, non-generic IOCs (this session's other detection-notes — Miasma, Tortoiseshell, Storm-2949, etc. — all encode signatures unique to their documented campaign, unlike this fourteen-rule cluster).
4. Deploy the single shared detection logic once; there is no value in deploying all fourteen separately if your correlation engine already dedups on identical selection logic — the fourteen separate files exist for per-actor tagging/reporting purposes, not fourteenfold detection coverage.

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of a generic, actor-attributed exfiltration channel signature. Per-actor references are listed above; MITRE ATT&CK: [T1567](https://attack.mitre.org/techniques/T1567/).*
