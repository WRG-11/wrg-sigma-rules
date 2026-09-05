<!--
Companion detection note covering FOUR unrelated named-actor Sigma rules, grouped for authoring
efficiency. Unlike this corpus's CVE/vendor-disclosure rules, these are templated "breach intel
signature" entries: a named threat actor mapped to ONE generic MITRE technique, sourced primarily
from secondary/aggregator threat-intel sites (socradar, ransomware.live, cyberpress) rather than
CISA/first-party-vendor advisories -- the source-quality difference from this corpus's Tier-1 CVE
notes is deliberately called out below, not glossed over.
- resources/examples/execution/observed_crpxo_t1204_002.yml
- resources/examples/impact/observed_coinbase_cartel_t1657.yml
- resources/examples/impact/observed_direwolf_t1490.yml
- resources/examples/impact/observed_nullsec_nigeria_t1491_defacement.yml
Detection/defense only, no exploit/PoC involved -- these are generic technique detections
associated with named actors via breach-catalog attribution, not actor-specific TTP research.
-->

# Four Named-Actor Signatures: CRPxO's Malvertised Downloads, Coinbase Cartel's Mixer Egress, Dire Wolf's Shadow-Copy Wipe, Nullsec Nigeria's Defacement

Four Sigma rules, each attributed to a named threat actor or group, but worth reading with a different expectation than this corpus's CVE-based notes: none of these detect an actor-SPECIFIC exploitation chain the way the vendor-disclosure rules do. Each detects a GENERIC technique (a downloaded-and-executed file, egress to known mixer infrastructure, shadow-copy deletion, web-root file writes) that this actor is documented as using — the actor attribution comes from a breach-catalog association, not a unique behavioral fingerprint only this actor produces. That distinction matters for how much confidence a hit should carry.

## What each rule actually detects

**1. CRPxO — a downloaded executable launched by a browser or mail client (T1204.002).** CRPxO is documented (socradar, cyberpress, SC World) as an actor combining an OnlyFans-themed social-engineering lure with crypto-theft and ransomware delivery, including a claimed Hyundai Turkey breach. The rule itself detects nothing CRPxO-specific — it flags any executable/installer/script launched from a Downloads or browser-temp-cache path with a browser or mail client as the parent process, which is the generic "user downloaded and ran something" pattern any malvertising, phishing, or drive-by campaign produces.

**2. Coinbase Cartel — network egress to known cryptocurrency mixer/exchange infrastructure (T1657).** Coinbase Cartel is documented (Bitdefender, Fortiguard, socradar, Infostealers.com) as an extortion group whose initial access chain runs through infostealer-harvested credentials, with a claimed 100+-company spree. The rule's actual detection logic is a static domain allowlist of known mixer/no-KYC-exchange infrastructure (Tornado Cash, Blender.io, ChipMixer, Wasabi Wallet, and others) — this is the same "known-bad infrastructure" detection shape as this corpus's OFAC-sanctioned-address rules, generalized from a single address to a domain list, and is not specific to Coinbase Cartel's own operations at all; any actor or legitimate researcher reaching the same infrastructure fires identically.

**3. Dire Wolf — Volume Shadow Copy deletion via the standard three tools (T1490).** Dire Wolf is a newer ransomware group (CSOonline reports a Singapore government alert naming it as targeting global tech/manufacturing firms specifically). The detection logic is the textbook `vssadmin`/`wmic`/`wbadmin` shadow-copy-deletion command pattern used by essentially every ransomware family for at least a decade — this is a near-universal ransomware-impact signature, not evidence specific to Dire Wolf.

**4. Nullsec Nigeria — web-root file writes outside the legitimate webserver process (T1491, defacement).** This rule's SOLE source is a single X.com/Twitter post from a dark-web-monitoring account — the weakest sourcing basis of the four rules in this note. The detection logic (a write to a common web-root path ending in a server-executable extension, excluding writes attributed to the webserver process itself) is a reasonable generic defacement-detection pattern, but nothing in the available source material ties a specific technical indicator to Nullsec Nigeria beyond a claimed defacement being reported.

## The detection signals

- **#1 (process_creation):** `Image` under `\Downloads\` or a browser temp-cache path, ending in `.exe`/`.msi`/`.scr`/`.bat`/`.vbs`, with `ParentImage` ending in a browser or mail-client binary (`chrome.exe`, `msedge.exe`, `firefox.exe`, `outlook.exe`, `explorer.exe`).
- **#2 (network_connection):** `DestinationHostname` containing any of a ~14-entry mixer/exchange domain list.
- **#3 (process_creation):** `vssadmin.exe`/`wmic.exe`/`wbadmin.exe` with a command line containing `delete shadows`, `shadowcopy delete`, or `delete catalog`.
- **#4 (file_event):** `TargetFilename` under a common web-root path ending in a server page extension, EXCLUDING writes attributed to `w3wp.exe`/`httpd.exe`/`nginx.exe` themselves.

## Known limitations (per rule — read together, they share one root cause)

All four rules share the same structural limitation: **the detection pattern is generic, the attribution is not.** A hit on any of these rules is evidence that the GENERIC technique occurred — it is not, by itself, evidence that CRPxO/Coinbase Cartel/Dire Wolf/Nullsec Nigeria specifically is responsible. Dozens of unrelated actors (and, in #3's case, essentially every modern ransomware family) produce the identical observable pattern. Treat a hit as "this generic technique fired," and use the corpus's own actor tagging as a hypothesis to investigate, not a conclusion the rule itself proves.

**#1** cannot distinguish a legitimate downloaded-and-run installer (a real IT-sanctioned package, a user's own software purchase) from a malicious one — the false-positive rate on this pattern alone, without file-hash/reputation enrichment, is expected to be high in any environment where users routinely install software.

**#2** will also fire on legitimate blockchain-research, compliance, or OFAC-screening traffic reaching the same mixer infrastructure — same caveat as this corpus's dedicated sanctioned-address rules (see `ofac-sanctioned-crypto-addresses-lazarus-lockbit-detection-2026-09-04.md`).

**#3** is a well-known, heavily-documented pattern; legitimate backup/DR software and IT admins performing scheduled shadow-copy cleanup are a real and common source of noise. Correlate with other impact-stage indicators (mass file rename/encryption, ransom-note drops) before escalating on this alone.

**#4** rests on a single social-media post as its entire evidentiary basis — this is the weakest-sourced rule in this batch. Treat any hit as requiring independent confirmation before attributing it to this specific actor; the underlying defacement-detection LOGIC is sound and reusable regardless of attribution confidence.

## What to do with a hit

1. Do not treat actor attribution from these four rules as confirmed — each detects a generic technique associated with a named group via secondary reporting, not a unique fingerprint.
2. **#1**: enrich with file hash/reputation before escalating; a bare "downloaded file executed by browser" hit is expected background noise in most environments.
3. **#2**: cross-check the destination against your own compliance/research-tooling inventory before treating as an incident.
4. **#3**: correlate with other ransomware-impact-stage signals; do not escalate on shadow-copy deletion alone without corroborating activity.
5. **#4**: given the single-source basis, treat a hit primarily as "unexpected web-root write outside the webserver process" — a real signal worth investigating on its own technical merits, independent of whether Nullsec Nigeria attribution holds up.
6. Deploy all four detection rules against the log sources each requires; expect a higher baseline false-positive rate than this corpus's CVE-based rules, since none of these key on a vendor-confirmed, patch-verifiable indicator.

---

*Detection content from WinstonRedGuard (WRG-11). Generic-technique detections associated with named threat actors via secondary/aggregator sourcing — read alongside this corpus's higher-confidence, vendor/CISA-sourced rules, not as equivalent to them. References: [socradar: CRPxO](https://socradar.io/free-tools/ransomware-intelligence/groups/crpxo), [Bitdefender: Coinbase Cartel](https://businessinsights.bitdefender.com/coinbase-cartel-ransomware-group-extortion-tactics), [CSOonline: Dire Wolf](https://www.csoonline.com/article/4042182/singapore-issues-critical-alert-on-dire-wolf-ransomware-targeting-global-tech-and-manufacturing-firms.html), [X.com/DarkWebInformer status (Nullsec Nigeria)](https://x.com/DarkWebInformer/status/2053566951088103805).*
