<!--
Rule submissions: read CONTRIBUTING.md first. The checklist below mirrors it
so a reviewer doesn't have to cross-reference a second document.
-->

## What this changes

## Rule submission checklist (delete this section if not a rule PR)

Rules that make claims about the world (`observed_*`):

- [ ] Cited source is a specific document, linked in `references:` — not a
      vendor blog summarising another blog
- [ ] Attribution match established (quote the sentence)
- [ ] Platform match established (`logsource` matches the documented platform)
- [ ] Manifestation match established (the telemetry claim is in the source)
- [ ] Detection logic developed against a real capture, not a synthetic log
- [ ] `falsepositives:` names concrete benign scenarios, not "unknown"

Every rule:

- [ ] Filed under `resources/examples/<tactic>/`
- [ ] `observed_*` / `template_*` prefix matches actual provenance
- [ ] ATT&CK technique in `tags:`
- [ ] Passes `validate_rule`
- [ ] `resources/examples/INDEX.json` updated, `python readme_stamp.py` run
- [ ] `python -m pytest -q` green

## Non-rule changes

- [ ] `python -m pytest -q` green
- [ ] `python readme_stamp.py --check` clean (if README-visible counts changed)
