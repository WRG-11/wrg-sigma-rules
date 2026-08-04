# prompts/

Reserved for reusable prompt templates (e.g. Claude Code slash commands) that
would sit alongside `skills/` rather than inside a single skill's own prompt
logic. Empty for now — the plugin's current prompt surface lives inside each
skill's own `SKILL.md`, which has been sufficient so far.

Already in scope for security reports regardless of contents: see
[`SECURITY.md`](../SECURITY.md)'s "Skills and prompts" scope entry
(prompt-injection vectors apply to a template file the moment one exists
here, not only once the directory stops being empty).
