<!--
Companion detection note for ONE shared Sigma rule that carries fourteen actor tags:
- resources/examples/exfiltration/observed_shared_t1567_file_sharing_host_burst.yml (shared rule; merged 2026-09-30 from single-actor files)
Until 2026-09-30 the same logic lived in fourteen single-actor files (observed_barracuda_t1567,
observed_blackwater_t1567, observed_crpxo_t1567, observed_emperador_t1567, observed_genesis_t1567,
observed_global_secret_group_t1567, observed_kairos_t1567_002, observed_krybit_t1567,
observed_ms13_089_t1567, observed_panzer_t1567, observed_securotrop_t1567,
observed_shai_hulud_npm_worm_t1567, observed_unknown_supply_chain_2025_03_t1567,
observed_worldleaks_t1567). They were merged into the shared rule; its `related` field lists
their ids with `type: merged`. The rule is a Sigma correlation pair (a `status: test` base
event-match rule + a `type: event_count` correlation document). Sources vary per actor (see the
per-actor list below); this note documents both the shared mechanism and each actor's own
attribution basis honestly, rather than writing as if the rule encoded actor-specific tradecraft
it does not contain.
Detection/defense only, no exploit/PoC reproduced.
-->

# One Shared Signature, Fourteen Actors: Known Exfil-Hostname Burst Detection

This corpus used to ship this signature as fourteen single-actor rules whose `detection:` blocks were **identical, byte-for-byte**, down to the exact same five hostnames in the exact same order. On 2026-09-30 they were merged into one shared rule that carries all fourteen actor tags. What the rule encodes is ONE generic exfiltration signature, mechanically attributed to fourteen different ransomware/extortion actors because each actor has at least one documented breach in the corpus this rule set is derived from. The value here is not "this rule detects how Barracuda operates" — it's "this rule detects a common exfil channel, and fourteen named actors happen to be the ones with a citation attached."

## The shared detection logic

**Base rule** (`network_connection` logsource): a single outbound connection whose `DestinationHostname` contains one of five well-known file-transfer/exfiltration-capable services — `mega.nz`, `anonfiles.com`, `transfer.sh`, `send.bitwarden.com`, `file.io`. On its own, one such connection is not the alert; the base document's description says so.

**Correlation rule**: the alert fires only when the SAME `DestinationHostname` is hit at least four times (`gte: 4`) within a **10-minute window**. Two of the merged files (KryBit, WorldLeaks) wrote the threshold as `gt: 3`; for an integer event count that selects exactly the same groups, so they merged into the same rule.

## What used to differ between the fourteen files

Only three things varied file-to-file: the actor name, the `date`/`references` fields (each actor's own documented breach and profile links), and `level` (ranged from `informational` through `high`, seemingly reflecting how well-corroborated or severe each actor's documented incident count is — WorldLeaks and Genesis, both citing multiple observed incidents, sit at `high`; single-incident, thinner-sourced entries like Global Secret Group and Panzer sit at `informational`). The detection LOGIC — the actual thing that decides whether a hit fires — did not differ at all. The shared rule keeps the references of every actor and the highest member level (`high`), so no deployment's alert severity dropped in the merge; the level still describes the most severe actor's record, not the strength of this evidence.

## Per-actor attribution (what each actor's references establish)

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
- **Unknown (tj-actions/reviewdog GHA Supply-chain 2025-03)** (added 2026-09-04) — this rule shares an actor identity with two other techniques already in this corpus (`observed_shared_t1078_remote_logon_burst_per_account.yml`, `observed_shared_t1552_printer_credential_page_burst.yml`, both added the same day — see this note's own T1078 note and the credential-access quartet note). Sourced from Unit42, Wiz, CISA alert AA25-072A-equivalent, StepSecurity, and two GHSA advisories (`ghsa-mrrh-fwg8-r2c3`, `GHSA-qmg3-hpqr-gqvc`) covering the March 2025 `tj-actions/changed-files` GitHub Action supply-chain compromise (CVE-2025-30066) — one of the best-documented CI/CD supply-chain incidents in this corpus's citation set, unlike the "unknown"-named actor label might suggest.

## Known limitations

**The hostname list is a coarse, easily-evaded proxy.** `mega.nz`/`anonfiles.com`/`transfer.sh`/`send.bitwarden.com`/`file.io` are five specific, well-known services — any actor (including all fourteen named here) can trivially exfiltrate through literally any OTHER file-sharing/cloud-storage endpoint not on this list and this rule will not fire. Treat a non-match as "not detected by THIS narrow signature," never as "no exfiltration occurred."

**The burst threshold (4+ in 10 minutes) can be defeated by throttling.** An operator aware of volume-based correlation detection (or simply exfiltrating a small number of large files rather than many small ones) stays under the threshold trivially.

**False-positive surface is real and shared**: legitimate use of any of these five services (a developer using `transfer.sh` for a large build artifact, an employee using Bitwarden Send for a password rotation, anyone with a personal Mega.nz account syncing files from a work machine) can cross the 4-in-10-minutes threshold during ordinary bursty use (e.g. a folder sync uploading many small files that resolve to repeat connections to the same hostname).

**Attribution confidence varies far more than the rule suggests.** Before the merge a Genesis/WorldLeaks hit came from a `level: high` file and a Global Secret Group/Panzer hit from a `level: informational` one, on EXACT SAME underlying evidence (a hostname burst): the level reflected how well-sourced each actor's OWN breach history is, not the strength of THIS detection. The shared rule carries the highest of those levels. Do not read its "high severity" as "this evidence is stronger"; read it as "the most severe actor on the list has that track record, per the cited sources."

## What to do with a hit

1. Treat any hit from this rule as "an exfiltration-shaped burst against a known file-sharing service occurred" — full stop. Do NOT treat the specific actor label as an attribution claim; the rule that fired tells you nothing about WHICH of these fourteen (or any other) actor is actually responsible, since all fourteen share one detection.
2. Extend the hostname list locally to cover file-sharing services actually observed in your own environment's threat landscape (WeTransfer, Dropbox Transfer, GoFile, various paste sites) — the five hardcoded here are a starting point, not a comprehensive list.
3. If you want genuine per-actor detection value from this corpus, look instead at rules with actor-specific, non-generic IOCs (this session's other detection-notes — Miasma, Tortoiseshell, Storm-2949, etc. — all encode signatures unique to their documented campaign, unlike this shared rule).
4. Deploy the rule once. The fourteen separate files it replaced existed for per-actor tagging and reporting, not fourteenfold detection coverage; the actor tags now sit on the one rule.

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of a generic, actor-attributed exfiltration channel signature. Per-actor references are listed above; MITRE ATT&CK: [T1567](https://attack.mitre.org/techniques/T1567/).*
