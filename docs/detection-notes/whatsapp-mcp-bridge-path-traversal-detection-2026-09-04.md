<!--
Companion detection note for the WhatsApp MCP bridge unauthenticated media_path traversal Sigma rule.
Accuracy source: resources/examples/collection/observed_whatsapp_mcp_bridge_path_traversal_t1005.yml
Advisory source: https://github.com/verygoodplugins/whatsapp-mcp/security/advisories/GHSA-7jj9-4qqq-4xc4
(fetched via `gh api repos/verygoodplugins/whatsapp-mcp/security-advisories/GHSA-7jj9-4qqq-4xc4`; CVSS 7.7
confirmed live).
Detection/defense only, no exploit/PoC reproduced beyond what the vendor advisory already published.
-->

# Detecting the WhatsApp MCP Bridge Local File Exfiltration (CVE-2026-46555, CVSS 7.7)

`whatsapp-mcp` lets Claude read and send WhatsApp messages. Before 0.2.1, its local bridge had no authentication and no path confinement — a combination that turned "send a WhatsApp attachment" into "read any file the user's account can access, and exfiltrate it as a WhatsApp document."

## What the flaw actually does

The `whatsapp-bridge` HTTP API listened on `127.0.0.1:8080` with no authentication and no Host-header validation. Its `/api/send` endpoint accepted an absolute `media_path` parameter without confining it to a safe directory. The advisory is specific about who counts as "local" here: an unauthenticated local caller "extends beyond processes the user explicitly launched" to sibling MCP servers, IDE extensions, and tool-triggered flows sharing the session — meaning the practical attacker isn't necessarily a human at the keyboard, it's any code running in the user's session that can make a loopback HTTP request. That caller could read SSH private keys, browser session data, source code, or dotfiles, and exfiltrate them as WhatsApp document attachments to the paired account. The missing Host-header check compounds this: it additionally lets a REMOTE attacker trigger the same request via DNS rebinding from a webpage the victim merely visits — "local-only" (127.0.0.1 bind) turned out not to mean "only locally reachable."

## The detection signal

The corpus rule flags a `POST /api/send` request whose `media_path` field is an absolute path (or contains a `..` traversal segment) rather than a filename confined to the bridge's own media directory — the fix specifically introduces path confinement, so a request the fixed version would reject is the discriminator.

## Known limitation

Correlate with the response status code where your log source captures it — a fixed (0.2.1+) deployment answers with an error rather than a successful send, which is a cleaner way to distinguish a blocked probe from actual file exfiltration than request content alone. Legitimate local automation passing an absolute path to an already-patched, correctly-scoped bridge instance is otherwise indistinguishable from an attack attempt by this rule.

## What to do right now

1. **Upgrade to whatsapp-mcp 0.2.1 or later.**
2. This bug is a useful general reminder: a `127.0.0.1`-bound service is not automatically safe from remote reach — a missing Host-header check turns a "local-only" bind into something a malicious webpage can trigger via DNS rebinding. If you run any local bridge/agent service bound to loopback, verify it validates the Host header, not just the bind address.
3. Deploy the detection rule above against proxy/access logs in front of the WhatsApp bridge, correlated with response status where available.

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of a vendor-disclosed, now-patched vulnerability. Reference: [verygoodplugins/whatsapp-mcp Security Advisory GHSA-7jj9-4qqq-4xc4](https://github.com/verygoodplugins/whatsapp-mcp/security/advisories/GHSA-7jj9-4qqq-4xc4).*
