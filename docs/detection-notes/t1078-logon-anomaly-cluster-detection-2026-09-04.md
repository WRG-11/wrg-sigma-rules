<!--
Companion detection note covering THREE sibling Sigma rules, all sharing ONE generic detection
signature (a per-user cross-host logon-anomaly burst correlation) attributed to three different named
actors -- added 2026-09-04 from sigma_rule_farmer's queue (these three rules were never previously in
this corpus; unlike most additions today, they are NOT duplicates of anything already shipped):
- resources/examples/initial_access/observed_shinyhunters_t1078.yml
- resources/examples/initial_access/observed_teampcp_unc6780_t1078.yml
- resources/examples/initial_access/observed_unknown_supply_chain_2025_03_t1078.yml
All three are Sigma correlation pairs (a `status: test` base event-match rule + a `type: event_count`
correlation document).
Detection/defense only, no exploit/PoC reproduced.
-->

# Three "Actor-Specific" Rules, One Shared Signature: Per-User Cross-Host Logon-Anomaly Burst

Same shape as this corpus's other generic-template clusters (T1567, T1486, T1110, T1071 already documented in sibling notes) — read one of these three rules' `detection:` block and you have read all three, down to a shared inline authoring comment block. This is worth reading closely, though, because that comment block is unusually informative about how this specific filter came to exist — a rare, direct window into this corpus's own false-positive-fixing history.

## The shared detection logic (identical across all three)

**Base rule** (`security` service logsource): `EventID` 4624 (successful logon) or 4625 (failed logon) with `LogonType` 3 (network) or 10 (RemoteInteractive/RDP), EXCLUDING service accounts (`TargetUserName` starting with `svc_`) AND excluding admin-prefixed interactive RDP (`LogonType: 10` + `TargetUserName` starting with `admin_`).

**Correlation rule**: the alert fires when the SAME `TargetUserName` produces 4+ of these events within a **15-minute window** — the same account logging on/failing to log on across this volume in this window, which the base rule's own filter comment (see below) frames as a cross-host credential-reuse signature.

## An unusually candid inline comment, worth reading directly

All three rules' base-event `detection:` block carries the identical inline authoring comment, attributing the admin-RDP exclusion filter to a specific internal fix cycle:

> "false-positive fix (first tuning cycle): legitimate admin interactive RDP (LogonType 10) tripped the rule). Authorized admin operators routinely access servers via RDP for maintenance; the rule fired on legit_rdp_logon (admin_dave / LogonType 10) ... Known tradeoff (documented for V re-verify + Phase 2 evaluation): this is a SINGLE-EVENT precision narrow. The **lapsus** actor signature is multi-host admin-credential reuse within a short window -- proper detection requires correlation (count() by account across hosts over time). Phase 1b aggregation matcher (V design-prep) will support that pattern; this filter is the Phase 1a stop-gap that keeps precision-on-benign at 1.00."

Two things worth flagging about this comment, read plainly rather than edited into third-person distance: **first**, it names the pattern's ORIGIN as LAPSUS$'s tradecraft specifically (multi-host admin-credential reuse), yet the resulting rule template is now attributed to THREE different actors (ShinyHunters, TeamPCP/UNC6780, and an unnamed 2025-03 supply-chain actor) who have no documented connection to LAPSUS$ — the underlying technique (credential reuse across hosts, detected via a per-account correlation) is genuinely generic enough to apply broadly, but the comment's own framing shows the filter was originally reasoned about for one specific actor's TTP, not derived independently for each of the three it now ships under. **Second**, the comment is explicit that this is a "Phase 1a stop-gap" pending a not-yet-built "Phase 1b aggregation matcher" — this rule family openly documents its own known limitation as a roadmap item, not a hidden gap this note had to discover.

## Per-actor attribution

- **ShinyHunters** (also covered for a different technique, T1110, in this corpus's `credential-access-correlation-quartet-detection-2026-09-04.md`) — one of this corpus's most consequential extortion actors: AT&T (73M customers), Snowflake-adjacent, and Instructure breaches, a named DOJ federal criminal charge, and FBI PSA I-051526-PSA (2026-05-15).
- **TeamPCP/UNC6780** (also covered for T1071 in `misc-correlation-actor-rules-detection-2026-09-04.md`, and for T1195 in this corpus's Tier-1 vendor-CVE singles note) — this corpus's most heavily-cited actor by reference count, tied to the Megalodon mass GitHub Actions supply-chain attack (5,561+ repositories) and the Mini Shai-Hulud npm worm resurgence.
- **Unknown (tj-actions/reviewdog GHA Supply-chain 2025-03)** (also covered for T1552 and T1567 in this corpus's sibling notes) — the well-documented March 2025 `tj-actions/changed-files` GitHub Action supply-chain compromise (CVE-2025-30066), sourced from Unit42, Wiz, CISA, and StepSecurity — one of the best-documented CI/CD supply-chain incidents in this corpus despite the "unknown" actor label.

## Known limitations

**The filter's own documented tradeoff (from the comment above)**: this is explicitly a single-event precision narrow, not the multi-host aggregation the underlying technique actually needs — the correlation groups by `TargetUserName` alone, which catches repeated logon activity for one account but does not distinguish "same account, same host, legitimately busy" from "same account, many DIFFERENT hosts, credential reuse" the way a host-aware correlation would. A legitimate account performing routine cross-application authentication (a service-desk operator touching several systems in sequence, a monitoring tool authenticating to multiple hosts) could cross the 4-in-15-minutes threshold.

**The `svc_`/`admin_` prefix exclusions are naming-convention-dependent** — an environment whose service or admin accounts don't follow these exact prefixes gets no benefit from either filter, and the rules will alias ordinary service-account or admin-RDP activity as anomalous.

**All three actor attributions are borrowed from a shared template originally reasoned about for LAPSUS$'s specific tradecraft** (per the inline comment) — a hit does not indicate the SPECIFIC named actor any more than the T1110/T1071/T1567/T1486 clusters' shared signatures do; treat it as "cross-host credential-reuse-shaped activity for one account," not actor attribution.

## What to do with a hit

1. Treat any hit as "one account authenticated (or failed to) an unusual number of times within 15 minutes" — investigate the account's actual activity across hosts before assuming compromise; this could be legitimate but unusual behavior (an admin doing a multi-server maintenance sweep who isn't prefixed `admin_`) as easily as credential reuse.
2. Verify your own environment's service/admin account naming actually matches the `svc_`/`admin_` prefix assumptions before deploying — adjust the filters to your real naming convention or expect the exclusions to do nothing.
3. If your correlation engine supports it, extend this rule's grouping to include host/`ComputerName` diversity (not just `TargetUserName` volume) to get closer to the cross-host signature the filter's own comment says is the actual goal — this is exactly the "Phase 1b aggregation matcher" the inline comment describes as not-yet-built.
4. Deploy all three against `security`-service Windows logon telemetry (EventID 4624/4625).

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of a generic, actor-attributed logon-anomaly signature. References: [FBI PSA I-051526-PSA (ShinyHunters)](https://www.ic3.gov/PSA/2026/PSA260515), [StepSecurity: Megalodon mass GitHub Actions secret exfiltration](https://www.stepsecurity.io/blog/megalodon-mass-github-actions-secret-exfiltration-across-5-500-public-repositories), [Unit42: GitHub Actions supply chain attack](https://unit42.paloaltonetworks.com/github-actions-supply-chain-attack/), [Wiz: tj-actions/changed-files supply chain attack](https://www.wiz.io/blog/github-action-tj-actions-changed-files-supply-chain-attack-cve-2025-30066), [CISA: tj-actions/changed-files compromise alert](https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-tj-actionschanged-files-cve-2025-30066-and-reviewdogaction).*
