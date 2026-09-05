<!--
Companion detection note covering THREE unrelated npm supply-chain worm/campaign Sigma rules, grouped
by shared mechanism (postinstall-hook credential theft + C2/exfil) rather than shared campaign:
- resources/examples/command_and_control/observed_keyv_cacheable_npm_worm_eth_c2_t1195_002.yml
- resources/examples/command_and_control/observed_unc1069_axios_waveshaper_t1195_002.yml
- resources/examples/initial_access/observed_s1ngularity_nx_npm_token_exfil_t1195_002.yml
Sources: Wiz + The Hacker News (Keyv/cacheable, 2026-08-04) / Google Threat Intelligence Group + Tenable
(axios/UNC1069, 2026-03-31) / Docker AI Coding Agent Horror Stories blog (s1ngularity/Nx, 2026-05).
Detection/defense only, no exploit/PoC reproduced beyond what the source disclosures already published.
-->

# Three npm Supply-Chain Worms, Three Different Trust-Abuse Vectors: Keyv/Cacheable, Axios/UNC1069, s1ngularity/Nx

Three independent npm supply-chain compromises, each initiated through a different form of trust abuse — a compromised maintainer GitHub account, a fabricated social-engineering relationship, and a compromised CLI installer — but converging on the same downstream pattern: a postinstall hook harvesting credentials, followed by C2/exfiltration.

## What each campaign actually does

**1. Keyv/cacheable — maintainer-account compromise, valid-provenance releases, on-chain C2 (2026-08-04).** Attacker compromised the GitHub account of the maintainer behind `keyv` (127M weekly npm downloads) and their other packages (`cacheable`, `flat-cache`, `file-entry-cache`) — pushed malicious commits directly to `main` and cut new releases with valid GitHub-Actions-signed provenance, so the poisoned versions carry a legitimate-looking supply-chain attestation. Spread to 400+ packages as of disclosure. Malicious releases add a preinstall hook that downloads the Bun runtime and runs an obfuscated stealer targeting `.npmrc`/GitHub-CLI/AWS/Vault/Kubernetes credentials, crypto wallets, and AI-tool config files (Claude, OpenAI, Cursor, Gemini) — self-propagating via stolen credentials. C2 mechanism: rather than embedding domains directly, the payload resolves its C2 domain via an on-chain `eth_call` lookup against an Ethereum smart contract (`StringListStore`, address independently confirmed by a second source), currently returning `npm-cache.com` — allowing infrastructure rotation without a payload update.

**2. Axios (UNC1069/WAVESHAPER.V2) — ~two weeks of AI-deepfake social engineering to obtain publish rights (2026-03-31, GTIG disclosure).** North Korea-nexus threat actor UNC1069 (financially motivated, active since ≥2018) injected a malicious dependency `plain-crypto-js` (published ~22 minutes before the malicious axios release) into axios releases v1.14.1/v0.30.4 (100M+/83M+ weekly downloads). The dependency's postinstall hook deploys WAVESHAPER.V2, an updated variant of a backdoor previously attributed to UNC1069, across Windows/macOS/Linux. Attribution basis: backdoor variant match + infrastructure overlap with prior UNC1069 operations + VPN node connections. Notably, initial access to the axios maintainer's publish rights was obtained via video calls and a fabricated collaborative-code-review pretext — not a technical exploit at all.

**3. s1ngularity/Nx — compromised CLI installer, part of a documented 4-vector campaign cluster (2026-05, Docker disclosure).** Compromised Nx CLI installer (`npm install -g nx` in the affected version range) triggers a postinstall hook with elevated developer-machine privileges; sweeps known token locations (`~/.npmrc`, GitHub PAT files, `~/.aws/credentials`, `NPM_TOKEN`/`GITHUB_TOKEN`/`AWS_ACCESS_KEY` env vars); bulk-exfiltrates over HTTPS POST with batching to avoid single-request size telemetry; persists via modified `package-lock.json` plus worm propagation to downstream project npm scripts. 1000+ developer tokens exfiltrated. Part of a broader 4-vector Nx campaign cluster this corpus tracks alongside Mini Shai-Hulud npm, ClawHavoc Claude Skills, and the nx-console VS Code extension — this rule's own description explicitly cross-references the sibling rules for campaign-wide coverage.

## The shared lesson

Three different initial-access vectors — account takeover, fabricated human trust, compromised tooling — converge on the identical downstream shape: postinstall-hook credential harvest, then C2/exfil. Provenance/signing (Keyv's valid GitHub-Actions attestation) does NOT stop this class, because the compromise happens upstream of the signing step, not to the signature itself. If your supply-chain defense stops at "is this package's provenance attestation valid," these three campaigns are all cases where the answer was yes and the package was still malicious.

## The detection signals

- **#1 (dns logsource):** a DNS query for `npm-cache.com`, optionally correlated with an npm-family process-lineage parent (the domain alone is sufficient given how specific it is; the process correlation just adds confidence).
- **#2 (dns/network logsource):** a DNS query for `sfrclak.com` OR a network connection to `142.11.206.73:8000`, optionally correlated with an npm-family process-lineage parent.
- **#3 (process_creation logsource):** an npm-family install targeting the Nx package family, followed by post-install child processes that either touch credential files (`.npmrc`, `.aws/credentials`, token env-var names, `.ssh/id_`) OR egress via `curl`/`wget`/`Invoke-WebRequest`/`Invoke-RestMethod` with `-X POST`.

## Known limitations (per rule)

**#1 and #2** both list the identical, honest false-positive class: threat-intel enrichment tooling or a sandbox resolving the indicator domain during analysis, and the security team's own verification lookups after the rule fires — a DNS-based IOC rule cannot distinguish "victim machine querying the C2" from "analyst machine querying the C2 to check it's still live."

**#2**'s verification discipline is explicit about what it deliberately excluded: the source blog also reports exact file hashes and additional file-path artifacts, left out because the second source (Tenable) did not independently corroborate them — this rule covers only the network indicators both sources agree on, not the full IOC set either source published alone.

**#3** needs to pin the vulnerable Nx version range against Docker's published indicators of compromise and exclude known-safe versions to avoid flagging ordinary new-project bootstrap; a build pipeline reading `.npmrc`/`GITHUB_TOKEN` as part of normal CI is also expected noise unless combined with the egress selection.

All three: any DNS/IP-based rule is inherently reactive to a specific, currently-known C2 endpoint — for #1, the entire point of the on-chain-resolved-domain mechanism is to make the endpoint itself rotatable without a payload update, so treat these hits as "matches TODAY's known infrastructure," not a durable signature of the underlying technique.

## What to do right now

1. All three: audit dependency trees for the specific compromised package/version ranges each disclosure names, independent of whether this rule has fired.
2. Provenance/signature verification is necessary but not sufficient — #1 is a direct counterexample to "signed release = trusted release" when the compromise is upstream of signing.
3. For #2's initial-access lesson specifically: maintainer-trust social engineering (including AI-deepfake-assisted) is now a demonstrated path to legitimate publish rights — this is an organizational/process control question (how does your org's maintainers verify who they're actually talking to), not something any Sigma rule can detect.
4. Deploy all three detection rules against DNS/network and process-creation log sources as available; none require exotic logging beyond what most EDR/DNS-monitoring already captures.

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of three active npm supply-chain campaigns. References: [Wiz: Keyv and cacheable npm supply chain attack](https://www.wiz.io/blog/keyv-and-cacheable-npm-supply-chain-attack), [The Hacker News: Keyv-linked npm worm](https://thehackernews.com/2026/08/keyv-linked-npm-worm-poisons-hundreds.html), [Google Cloud GTIG: North Korea threat actor targets axios npm package](https://cloud.google.com/blog/topics/threat-intelligence/north-korea-threat-actor-targets-axios-npm-package), [Tenable FAQ: axios npm supply chain attack](https://www.tenable.com/blog/faq-about-the-axios-npm-supply-chain-attack-by-north-korea-nexus-threat-actor-unc1069), [Docker: AI Coding Agent Horror Stories](https://www.docker.com/blog/ai-coding-agent-horror-stories-security-risks).*
