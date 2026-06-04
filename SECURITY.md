# Security Policy

## Reporting a Vulnerability

Please report suspected vulnerabilities **privately** via GitHub Security Advisories:

**[Report a vulnerability](https://github.com/WRG-11/wrg-sigma-rules/security/advisories/new)**

Please do **not** open a public issue or pull request for security reports — that
discloses the problem before a fix is available.

- Initial response: within **7 days** (best effort)
- Coordinated disclosure: fix first, then public advisory

## Scope

Anything in this repository, including:

- **Detection rules** (`resources/examples/`) and canonical patterns
  (`resources/canonical-patterns/`) — e.g. a rule that can be trivially bypassed in a
  way its title claims to cover, or ReDoS-prone regex inside a rule.
- **MCP server and tooling** (`server.py`, `tools/`, `scripts/`) — e.g. injection or
  unsafe handling of untrusted rule/log content.
- **Skills and prompts** (`skills/`, `prompts/`) — e.g. prompt-injection vectors.

Ordinary rule false positives / false negatives without a security impact are regular
bugs — please use [issues](https://github.com/WRG-11/wrg-sigma-rules/issues) for those.

## Supported Versions

Only the latest release and the `main` branch receive security fixes.

| Version                  | Supported |
| ------------------------ | --------- |
| Latest release + `main`  | ✅        |
| Older releases           | ❌        |
