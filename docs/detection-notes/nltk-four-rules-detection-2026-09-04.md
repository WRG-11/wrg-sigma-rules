<!--
Companion detection note covering FOUR sibling Sigma rules against the same project (nltk/nltk):
- resources/examples/initial_access/observed_nltk_pathsec_dns_rebind_ssrf_bypass_t1190.yml
- resources/examples/collection/observed_nltk_framenet_corpus_reader_path_traversal_t1005.yml
- resources/examples/collection/observed_nltk_nkjp_corpus_reader_path_traversal_t1005.yml
- resources/examples/impact/observed_nltk_reviews_corpus_reader_redos_t1499.yml
Advisory sources: GHSA-qvv7-cg9c-w4x3 / GHSA-xh95-f55m-82fw / GHSA-6hm5-jgcp-p838 / GHSA-fg7f-2386-8897,
all fetched via `gh api repos/nltk/nltk/security-advisories/<id>`.
RESOLVED freshness note (2026-09-04): each corpus rule's description originally stated "not yet fixed
at time of publication" (rules dated 2026-08-11). Live verification confirmed `patched_versions:
">=3.10.0"` for all four, with the exact fix PR identified per rule via NLTK's own GitHub release
changelog (framenet: PR #3581, nkjp: PR #3579, reviews-ReDoS: PR #3583, pathsec-DNS-rebind: PR #3582)
-- all four rules' `description:` fields were corrected accordingly the same day.
Detection/defense only, no exploit/PoC reproduced beyond what the vendor advisories already published.
-->

# Detecting Four NLTK Vulnerabilities: When a Documented Security Boundary Has a Side Door (CVSS 7.5-8.6)

NLTK ships a documented security mechanism, `nltk.pathsec`, specifically so downstream applications can safely load corpora and data from less-trusted sources. Four CVEs disclosed together show the same failure repeated three different ways: the mechanism is real, it is documented, and specific code paths simply don't go through it.

**Freshness note before anything else**: all four corpus rules originally described these as unpatched at authoring time (2026-08-11). Live verification confirmed `patched_versions: ">=3.10.0"` for all four, and the rules' descriptions were corrected accordingly (2026-09-04) — a deployment confirmed at NLTK 3.10.0+ now correctly reads as fixed.

## What each flaw actually does

**1. DNS rebinding defeats the SSRF filter even under strict mode (CVE-2026-12075, CVSS 8.6).** `nltk.pathsec.urlopen()` resolves a URL's hostname, checks the IPs against loopback/private/link-local ranges, then hands the RAW hostname to `urllib`, which resolves it AGAIN independently at connect time. The two resolutions share no cache and no state. An attacker with a TTL-0 DNS rebinding record serves a public IP to the validation lookup and an internal/loopback IP to the connection lookup — the IP that passed validation is never the IP actually connected to. This works even with `ENFORCE = True`, the strict mode NLTK's own security documentation recommends. A `lru_cache` decorator on the resolver's docstring *claims* to mitigate rebinding; it only memoizes the validation-side lookup and provides no protection at all.

**2 & 3. Two corpus readers that never call the sandbox (CVE-2026-12074, CVSS 7.5 / CVE-2026-12072, CVSS 7.5).** `NKJPCorpusReader.add_root()` builds file paths by plain string concatenation with no `..` stripping, and opens the result with the builtin `open()` rather than `PathPointer.open()` — so `pathsec`'s validation sentinel is never invoked, and `ENFORCE = True` provides no protection at all for this reader. `FramenetCorpusReader.frame_by_name` has the identical structural bug in a distinct code path — the fix for one reader class does not extend to the other. Both let a caller-supplied path component (`fileids` for NKJP, a frame name for Framenet) reach a file outside the intended corpus root via `../` traversal.

**4. An unbounded regex explodes on the absence of what it's looking for (CVE-2026-12061, CVSS 7.5).** `ReviewsCorpusReader`'s `FEATURES` regex extracts feature annotations (a label followed by a bracketed signed digit) using an unbounded, unanchored label sub-pattern. On a long line with NO bracket at all, the regex engine greedily extends the label candidate from every one of the line's *n* starting positions, fails each time, and backtracks the whole way — O(n²) total work. A single ~100,000-word bracket-less line hangs the reader for tens of seconds to minutes, with no authentication needed beyond the ability to supply a reviews corpus.

## The shared lesson

`nltk.pathsec` is real and does what it claims — for the code paths that actually call it. Three separate reader classes (urlopen's connection-time resolution, NKJP, Framenet) reach the filesystem or network through a path that never routes through the documented protection. If you rely on a library's stated security boundary, the actionable question these three raise is not "does this protection exist" but "does the SPECIFIC code path I'm calling actually route through it" — a security promise in `SECURITY.md` does not automatically extend to every function that touches the same resource class.

## The detection signals

- **#1 (network-connection logsource):** two DNS resolutions for the same hostname within a short window returning different IP address classes (public, then private/loopback/link-local), immediately preceding an `nltk.pathsec.urlopen`/`nltk.download` call.
- **#2 (application logsource):** a `FramenetCorpusReader` invocation whose frame-name argument contains `../`.
- **#3 (application logsource):** an `NKJPCorpusReader` invocation whose `fileids` argument contains `../`.
- **#4 (application logsource):** a `ReviewsCorpusReader` invocation correlated with an observable timeout — this rule flags the STALL itself, not a pre-hang signature, since precisely detecting the offending line before it hangs would need raw corpus content logging most sources don't capture.

## Known limitations (per rule)

**#1** requires DNS telemetry correlated with the requesting process across two independent resolutions within one request lifecycle — most infrastructure log sources don't capture this. It also won't fire on a legitimate CDN/load-balancer hostname with genuinely short TTLs, since the rule specifically requires the SECOND answer to be private/loopback/link-local, which a normal multi-IP public service doesn't produce.

**#2 and #3** need application-level logging of the specific argument (frame name / fileids) passed to the reader — and neither covers every reachable variant: #2's own advisory names two additional string-path code paths (`doc()`, the lexical-unit loader) reachable only through a malicious corpus INDEX rather than a direct caller argument, which this rule does not detect.

**#4** only fires once pathological CPU time has already been consumed — it detects the outcome (a stall), not the input before it causes one.

## What to do right now

1. **Check your NLTK version against 3.10.0** — see the freshness note above before assuming these are still unpatched.
2. If you cannot upgrade immediately: for #1, pin resolved IPs at validation time and reuse them for the connection rather than re-resolving; for #2/#3, avoid passing untrusted input as corpus reader arguments (frame names, fileids) until confirmed patched; for #4, cap input line length before it reaches `ReviewsCorpusReader`.
3. If you use NLTK's `pathsec` module as a security boundary for untrusted input anywhere in your own code, audit every reader/loader class you actually call — this disclosure batch shows the boundary is per-code-path, not blanket.
4. Deploy the four detection rules above against the log source each requires.

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of four vendor-disclosed, now-patched (per current advisory data) vulnerabilities. References: [nltk/nltk GHSA-qvv7-cg9c-w4x3](https://github.com/nltk/nltk/security/advisories/GHSA-qvv7-cg9c-w4x3), [GHSA-xh95-f55m-82fw](https://github.com/nltk/nltk/security/advisories/GHSA-xh95-f55m-82fw), [GHSA-6hm5-jgcp-p838](https://github.com/nltk/nltk/security/advisories/GHSA-6hm5-jgcp-p838), [GHSA-fg7f-2386-8897](https://github.com/nltk/nltk/security/advisories/GHSA-fg7f-2386-8897).*
