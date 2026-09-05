<!--
Companion detection note covering THREE sibling Sigma rules against open-webui/open-webui, all
whole-instance-DoS bugs sharing one root cause: unbounded computation on the shared asyncio event loop.
- resources/examples/impact/observed_open_webui_automation_recurrence_dos_t1499.yml
- resources/examples/impact/observed_open_webui_knowledge_search_catastrophic_backtrack_dos_t1499.yml
- resources/examples/impact/observed_open_webui_skill_mention_regex_redos_t1499.yml
Advisory sources: GHSA-73cq-mcgh-379c / GHSA-2f54-p244-32q6 / GHSA-ffpj-xv5c-p3gw, all fetched via
`gh api repos/open-webui/open-webui/security-advisories/<id>` (CVSS 6.5 confirmed live for all three).
Detection/defense only, no exploit/PoC reproduced beyond what the vendor advisories already published.
-->

# Detecting Three Open WebUI Whole-Instance DoS Bugs (CVSS 6.5 each)

Three Open WebUI vulnerabilities, all CVSS 6.5, share the same blast-radius property that makes them worth grouping regardless of their individually-moderate severity: none of them is a per-request DoS. Because Open WebUI's Python backend runs on a shared `asyncio` event loop, one crafted request from ANY authenticated user blocks the server for EVERY other user, not just the requester.

## What each flaw actually does

**1. A fixed epoch turns a minutely rule into a quarter-century walk (CVE-2026-70489).** Automation recurrence parsing anchored MINUTELY/HOURLY rules at a fixed epoch of `2000-01-01` and walked forward one interval at a time to find the next run relative to now. A single `FREQ=MINUTELY` automation enumerates roughly 25 years of occurrences, one minute at a time, synchronously — and the scheduler recomputes this same walk for every claimed row on EVERY poll cycle, not once.

**2. A default-enabled tool with no timeout on user-supplied regex (CVE-2026-70493).** The built-in `grep_knowledge_files` tool treats any caller-supplied pattern containing regex metacharacters as a regex, compiles it with Python's backtracking `re` engine, and runs it over every line of every reachable file with no time limit anywhere on the path. A pattern like `(x|x)*y` grows exponentially with subject length — the advisory's own measured numbers: 24 characters takes 1.2s, 28 takes 19s, 30 takes 74s.

**3. Overlapping quantifiers in a chat-parsing regex (CVE-2026-59220).** `SKILL_MENTION_RE`/`strip_re` parse `<$skillId|label>` skill-mention syntax using overlapping quantifiers. A chat message containing `<$` with no closing `>` triggers quadratic-or-worse backtracking — processed on the same shared event loop as everything else.

## The shared lesson

All three are the same root cause in three different features: user-controlled input reaches an unbounded computation (a distant-epoch time walk, an uncompiled/untimed regex, an overlapping-quantifier regex) that runs SYNCHRONOUSLY on a shared event loop with no timeout anywhere in the path. None of these is a memory-safety bug or a logic bug — they're availability bugs that exist purely because nothing bounded the computation's worst case. If you run any single-threaded/event-loop-based service (`asyncio`, Node.js, similar), the audit habit these three reinforce: any code path that compiles or evaluates user-supplied patterns, walks time ranges, or otherwise has unbounded worst-case complexity needs an explicit timeout or complexity bound BEFORE it reaches the shared loop — "it usually finishes fast" is not a bound.

## The detection signals

- **#1 (application logsource):** an automation-creation event with `FREQ=MINUTELY` or `FREQ=HOURLY`.
- **#2 (application logsource):** a `grep_knowledge_files` tool call whose pattern argument matches an alternation-with-repetition shape (e.g. `(x|x)*`).
- **#3 (application logsource):** a chat message containing `<$` with no closing `>` within a reasonable span.

## Known limitations (shared)

**#1** is closer to a configuration-risk signal than an attack-only one: on an unpatched deployment, EVERY minutely/hourly automation is expensive by construction, not only malicious ones — this rule cannot distinguish intent from recurrence granularity alone.

**#2** cannot confirm actual catastrophic cost from the pattern shape alone — not every alternation-plus-quantifier pattern is exponential against every subject line; correlate with sustained high CPU on the serving worker to confirm real impact rather than treating every match as a successful attack.

**#3** is narrow in practice (a legitimate message containing literal `<$` is rare outside code/markup discussion) but application-level chat-content logging is required for any of these three, which most infrastructure log sources don't capture by default.

All three: on a deployment upgraded past its fix (#1 and #2: 0.11.0+, #3: 0.10.0+), a matching event no longer causes the described stall.

## What to do right now

1. **Upgrade**: #1 and #2 to 0.11.0+; #3 to 0.10.0+.
2. If your deployment cannot upgrade immediately, the compensating control is the same for all three: rate-limit or restrict which users can create automations, invoke the knowledge-search tool, or send messages with skill-mention syntax — reducing the population that can trigger any of these to trusted users only.
3. Deploy the three detection rules above against application-level content logging.
4. If you build any event-loop-based service, audit for the general pattern: user input reaching an unbounded time-walk or regex-compile/match with no timeout — this batch is a concrete, sourced example set for what to search for.

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of three vendor-disclosed, now-patched vulnerabilities. References: [open-webui/open-webui GHSA-73cq-mcgh-379c](https://github.com/open-webui/open-webui/security/advisories/GHSA-73cq-mcgh-379c), [GHSA-2f54-p244-32q6](https://github.com/open-webui/open-webui/security/advisories/GHSA-2f54-p244-32q6), [GHSA-ffpj-xv5c-p3gw](https://github.com/open-webui/open-webui/security/advisories/GHSA-ffpj-xv5c-p3gw).*
