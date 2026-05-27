# WRG Canonical Sigma Detection Patterns

5 canonical detection pattern shape definitions distilled from
6+ months of WRG threat-intel corpus + 50+ sigma rule operations.
Each pattern captures a recurring detection shape that recurs across
multiple actors and incidents -- they are the "design patterns" of
sigma rule writing.

Use these patterns when:

- Writing a new sigma rule from a NL incident description (start
  from the closest pattern shape, then specialise).
- Reviewing an existing rule for canonical correctness (does it match
  one of these shapes?).
- Performing MITRE ATT&CK coverage gap analysis (each pattern maps
  to a tactic cluster).

## Pattern overview

| # | Pattern | MITRE coverage | Detection type |
|---|---|---|---|
| 1 | [Command-line encoded payload](./01-command-line-encoded-payload.md) | T1027, T1059.001 | process_creation |
| 2 | [Credential access via OS internals](./02-credential-access-os-internals.md) | T1003.001, T1003.002, T1110 | process_creation + authentication |
| 3 | [Living-off-the-land binary abuse](./03-lolbin-abuse.md) | T1218 family, T1059, T1218.011 | process_creation |
| 4 | [C2 beaconing network signal](./04-c2-beaconing-network-signal.md) | T1071, T1071.001, T1572 | network_connection + dns_query |
| 5 | [Cross-platform supply chain compromise](./05-supply-chain-compromise.md) | T1195 family, T1583 family | process_creation + file_event |

## Why 5 patterns

5 is the curated middle ground. <=3 patterns oversimplify (you lose
the distinct shapes that warrant separate rule scaffolding); >=7
patterns over-fragment (rule writers cannot remember the catalog
without referencing it every time). The 5-pattern surface captures
~80% of the WRG corpus rule distribution while staying memorable.

## Pattern selection heuristic

When asked to draft a rule for a new technique, ask:

1. Does the rule fire on a **command-line string match**? -> Pattern 1.
2. Does the rule fire on **OS internals access** (memory, registry,
   auth subsystem)? -> Pattern 2.
3. Does the rule fire on **trusted-binary abuse** (cert, msbuild,
   regsvr32, rundll32)? -> Pattern 3.
4. Does the rule fire on **network telemetry** (DNS, HTTP, TLS SNI)?
   -> Pattern 4.
5. Does the rule fire on **supply chain pivot** (install-time event,
   foreign dependency, third-party path)? -> Pattern 5.

If the rule fires across multiple categories, pick the **primary
selection** category (the rule's main observable) and add the
secondary as a correlation filter.

## URI access

These canonical patterns are exposed via the plugin's MCP resource
layer at:

- `wrg-sigma://patterns/canonical-5` -- INDEX.md (this file)
- `wrg-sigma://patterns/canonical-5/<pattern_id>` -- Individual
  pattern markdown (`01` through `05`)

See `plugins/wrg-sigma-rules/tools/resources/canonical_patterns_resource.py`
for the URI resource implementation.

## Source attribution

These patterns are distilled from:

- TECHNIQUE_PATTERN_LIBRARY (apps/<wrg-app>/breach/sigma/templates.py)
  -- 37 hand-curated MITRE technique patterns covering ~90% of WRG
  catalog technique-incident mentions.
- 6 observed actor goldens (ALPHV/BlackCat + LAPSUS$ + LockBit + Nullsec
  Nigeria).
- 2 OFAC crypto sanctions goldens (Lazarus + LockBit BTC operator).
- 5 wrg_ai_fingerprint code-review detector goldens.

Total source corpus: 51 sigma rules across 11 ATT&CK tactics.

## License

MIT (matches plugin license).
