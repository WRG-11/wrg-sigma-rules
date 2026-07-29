# Contributing rules to this corpus

Sigma rule contributions are welcome. The technical bar is easy to state and
easy to check. The sourcing bar is the one that actually decides whether a
rule belongs here, and it is stricter than "the YAML validates".

## Why the sourcing bar exists

This project submitted three rules upstream to
[SigmaHQ/sigma](https://github.com/SigmaHQ/sigma). All three closed without
merging:

| PR | Closed | What went wrong |
|---|---|---|
| [#6039](https://github.com/SigmaHQ/sigma/pull/6039) | 2026-06-25 | The telemetry the rule needed was not established to exist in the cited source |
| [#6053](https://github.com/SigmaHQ/sigma/pull/6053) | 2026-06-11 | Detection logic was developed against synthetic logs, not a real capture |
| [#6087](https://github.com/SigmaHQ/sigma/pull/6087) | 2026-06-30 | The cited report did not attribute the described activity to the named actor, and the one documented instance ran on a different platform than the rule targeted |

Each rule was YAML-valid, pySigma-clean, and looked professional. None of
that was the problem. The problem was the distance between what the cited
source actually said and what the rule claimed it said — and in every case
that distance survived review right up until someone read the source
sentence by sentence.

#6087 is the instructive one. It carried a real IOC
(`generativelanguage.googleapis.com`) taken from a real threat-intel report.
The IOC being genuine did not make the rule grounded: the attribution around
it, the platform it ran on, and the way it would manifest in telemetry were
each unsupported by the cited document. A true fact inside an unsupported
frame is still an unsupported rule.

## The three matches

Before writing detection logic for an `observed_*` rule, open the cited
source and establish all three. If you cannot, the rule is not ready — and
neither "it is probably true" nor "the technique is well known" substitutes
for any of them.

**1. Attribution.** Does the source attribute *this activity* to *this
actor or campaign*? A report that discusses an actor and separately
discusses a malware family does not thereby connect them. Quote the sentence
that makes the link. If you are quoting two sentences and inferring the
link between them, you are inferring, not citing.

**2. Platform.** Does the documented activity run on the platform your
logsource targets? A behaviour observed on Android does not justify a
`product: windows` rule, however similar the network signature looks.
Match `logsource` to the platform the source actually describes.

**3. Manifestation.** Does the source document how the activity appears in
the telemetry you are matching on? "The malware contacts a Google API" does
not establish "a DNS query for that host originates from a scripting host".
The second is a claim about observable telemetry; if the source does not
make it, you are designing the artifact rather than detecting it.

## Checklist

Rules that make claims about the world:

- [ ] Cited source is a specific document, linked in `references:` — not a
      vendor blog summarising another blog
- [ ] Attribution match established (quote the sentence)
- [ ] Platform match established (`logsource` matches the documented platform)
- [ ] Manifestation match established (the telemetry claim is in the source)
- [ ] Detection logic developed against a real capture, not a synthetic log
      you wrote to match the rule you already had in mind
- [ ] `falsepositives:` names concrete benign scenarios, not "unknown"

Every rule:

- [ ] Filed under `resources/examples/<tactic>/`
- [ ] `observed_*` prefix for incident-specific rules, `template_*` for
      canonical pattern templates — the prefix is a claim about provenance,
      so do not label a generic pattern `observed_`
- [ ] ATT&CK technique in `tags:` (e.g. `attack.t1071`); the coverage
      resource ignores rules without one
- [ ] Passes `validate_rule` (pySigma round-trip + linter)
- [ ] `resources/examples/INDEX.json` updated, and `python readme_stamp.py`
      run so the README counts match
- [ ] `python -m pytest -q` green

## Rules that do not claim to be observed

A `template_*` rule describes a canonical detection shape rather than a
specific incident, so the three matches do not apply to it in the same way.
The corresponding honesty requirement is the label itself: if a rule was
built from a generic technique description, it is a template, and calling it
`observed_` misrepresents where it came from. Three rules in this corpus were
relabelled `template_` for exactly that reason.

## On volume

More rules is not the goal. A corpus grows in value through rules that
someone can trace back to a source and trust; it loses value through rules
that look plausible and cite nothing checkable. If a submission cannot clear
the bar above, the correct outcome is not to lower the bar.
