<!--
Companion detection note covering TWO sibling Sigma rules -- a DIFFERENT shape than every other note
in this corpus: these are not vendor-disclosed vulnerabilities, they are static blockchain-address
sanctions matches sourced directly from US Treasury OFAC press releases:
- resources/examples/impact/observed_sigma_rule_lazarus.yml
- resources/examples/impact/observed_sigma_rule_lockbit_btc.yml
Sources: home.treasury.gov press releases JY0768 (Lazarus/Blender.io, 2022-05-06) and JY2114
(LockBit operator BTC, 2024-02-20).
No exploit/PoC involved -- these are compliance/sanctions detections, not vulnerability detections.
-->

# Detecting Interactions with OFAC-Sanctioned Wallets: Lazarus (Blender.io) and LockBit

Two of this corpus's simplest rules by construction, and worth noting as a distinct category from everything else in this repo: they don't detect a vulnerability or an attack technique at all — they detect a wallet transacting with an address the US Treasury has formally sanctioned. The entire detection logic is a single address-equality match; the value of the rule is entirely in the address itself being correct and current, not in any clever detection engineering.

## What each rule flags

**1. `0x098b716b8aaf21512996dc57eb0615e2383e2f96` (Ethereum) — Blender.io / Lazarus Group laundering, OFAC designation dated 2022-05-06 (program DPRK, Treasury press release JY0768).** Blender.io was a bitcoin mixer OFAC sanctioned specifically for laundering funds for the Lazarus Group, North Korea's state-sponsored threat actor. A wallet transacting with this address is transacting with (or through) infrastructure OFAC has formally tied to DPRK-directed laundering.

**2. `bc1qjnt7vjqyzpyjs6ne5xfu44p4uy4xyl0vudr4dp` (Bitcoin) — LockBit ransomware operator wallet, OFAC designation dated 2024-02-20 (program CYBER2, Treasury press release JY2114).** Tied directly to a named LockBit operator as part of the US/UK/international law-enforcement action against the LockBit ransomware-as-a-service operation.

## Why this is a different kind of rule than the rest of this corpus

Every other rule in this corpus detects a TECHNIQUE — a process-creation pattern, a network indicator, an application-log signature — that generalizes to any deployment matching the described conditions. These two rules detect a SPECIFIC, STATIC FACT: this exact address was sanctioned on this exact date for this exact reason. There's no "false positive due to a coincidental pattern match" risk the way a regex-based process-creation rule has — either the counterparty address in the observed transaction IS this literal string, or it isn't. The tradeoff is the opposite kind of fragility: the rule's entire value has a shelf life tied to whether the address stays sanctioned, stays associated with this actor, and stays in active use by anyone the rule's operator would transact with.

## Known limitations (per rule)

**Both** rules' `falsepositives` sections are honest about a real class of legitimate hits, not a hedge: blockchain-analytics and research platforms interact with sanctioned addresses PRECISELY BECAUSE they trace them, and exchange compliance workflows handle seized/frozen funds under legal process. A hit on either rule from a known compliance or research platform's own wallet infrastructure is expected behavior, not an incident.

**Rule 2's `id` field is the literal zero-UUID** (`00000000-0000-0000-0000-000000000000`) rather than a generated UUID — every other rule in this corpus (including its sibling `observed_sigma_rule_lazarus.yml`) uses a properly generated one. This isn't a detection-logic defect, but it means any tooling that assumes rule IDs are unique/non-placeholder (deduplication, rule-ID-keyed lookups) will collide on this rule if a second zero-UUID rule is ever added. Worth a maintenance fix independent of this note's scope.

**Both** rules are single-address static IOCs with no update mechanism described in the rule itself — a sanctioned address that gets added to a broader Treasury list update, or a NEW Lazarus/LockBit-associated address disclosed later, requires a separate rule or a maintained address-list feed; this rule format doesn't express "match against a growing list," only "match against this one literal string."

## What to do with a hit

1. Verify the transaction is not originating from a known compliance/blockchain-analytics/exchange-seizure workflow (the documented false-positive class) before escalating.
2. If genuinely unexpected: this is a sanctions-exposure event, not just a security incident — treat it with the regulatory/legal urgency that implies (OFAC sanctions violations carry strict-liability civil penalty exposure independent of intent), not only an IR playbook.
3. Cross-reference the counterparty address against OFAC's SDN list directly (not just this static rule) if evaluating whether the sanction is still current — Treasury designations can be updated or, rarely, delisted.
4. Consider whether this deployment needs an address-list-driven detection layer (rather than one rule per address) if OFAC-sanctioned-crypto-wallet coverage is meant to be comprehensive rather than these two specific historical designations.

---

*Detection content from WinstonRedGuard (WRG-11). Sanctions/compliance detection, not vulnerability detection. References: [Treasury press release JY0768 (Blender.io/Lazarus)](https://home.treasury.gov/news/press-releases/jy0768), [Treasury press release JY2114 (LockBit operator BTC)](https://home.treasury.gov/news/press-releases/jy2114).*
