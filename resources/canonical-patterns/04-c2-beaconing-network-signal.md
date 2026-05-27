# Pattern 4 -- C2 beaconing network signal

**MITRE coverage**: T1071 (Application Layer Protocol), T1071.001
(HTTP/HTTPS), T1572 (Protocol Tunneling), T1090 (Proxy), T1567
(Exfiltration Over Web Service).

**Detection type**: `network_connection` + `dns_query` +
`webserver` / `proxy` logs.

## What it detects

Command-and-control beaconing patterns: regular-interval outbound
connections to attacker infrastructure, DNS tunneling (high-volume
TXT/CNAME records, lookalike domains), and jitter-modulated beacon
patterns designed to evade time-window-based correlation.

## Canonical detection shape

```yaml
logsource:
  category: network_connection
  product: windows
detection:
  selection_c2_http:
    DestinationPort:
    - 80
    - 443
    - 8080
    - 8443
    Image|endswith:
    - '\powershell.exe'
    - '\cmd.exe'
    - '\wscript.exe'
    - '\mshta.exe'
    - '\rundll32.exe'
    - '\regsvr32.exe'
  selection_dns_tunnel:
    EventID: 22   # Sysmon DnsQuery
    QueryName|re: '.*\.[a-z0-9]{32,}\.[a-z]{2,5}'   # long subdomain pattern
  selection_lookalike_domain:
    cs-host|re: '.*(microsoft|google|amazon|apple|github)-[a-z0-9]{6,}\.[a-z]+'
  filter_known_safe:
    cs-host|endswith:
    - '.windowsupdate.microsoft.com'
    - '.github.com'
    - '.googleapis.com'
  condition: |
    (selection_c2_http or selection_dns_tunnel or selection_lookalike_domain)
    and not filter_known_safe
```

## Why it works

- **C2 HTTP selection** ties outbound HTTPS to specific high-risk
  process parents (scripting interpreters + LOLBins). Most legitimate
  HTTPS traffic comes from browsers + signed apps; these process
  parents are anomalous.
- **DNS tunnel selection** uses a regex on QueryName to detect the
  long-subdomain pattern typical of DNS tunneling
  (`<base64-data>.attacker.tld`). The `>=32 chars` threshold filters
  out legitimate-but-long DNS labels.
- **Lookalike domain selection** catches typosquatted brand domains
  used in phishing + C2 hosting. Combine with parental process
  filter to reduce false positives.
- **Aggregation** (not shown in the basic shape): add
  `count() by DestinationHostname > 30 in 30m` to fire only on
  beacon-like burst patterns rather than single connections.

## False positives

- **Browser update checks**: legitimate browser components beacon to
  update servers (Chrome, Firefox, Edge). Whitelist by signed binary
  + known update host.
- **Telemetry agents**: APM + crash-reporter agents beacon home.
  Whitelist by user-agent / known telemetry host.
- **CDN provisioning**: cloud workloads pull configuration from CDN
  hosts that look subdomain-encoded. Whitelist by signed binary +
  cloud-provider FQDN suffix.

## Reference rules from corpus

- `command_and_control/template_t1071_application_layer_protocol_c2_over_http_https.yml`
- `exfiltration/template_t1567_exfiltration_over_web_service_mega_anonfiles_host.yml`
- `impact/template_t1657_financial_theft_extortion_crypto_mixer_payout.yml`
- `resource_development/template_t1583_acquire_infrastructure_newly_registered_domain_query.yml`
- `resource_development/template_t1583_001_acquire_infrastructure_domains_lookalike_domain.yml`

## Specialisations

- **Cobalt Strike beacon detection**: pivot to specific beacon
  jitter pattern (e.g., 60s +/- 15% interval) using a custom
  correlation rule.
- **DNS-over-HTTPS C2**: replace `selection_c2_http` with TLS-SNI-
  layer detection on DoH provider hosts.
- **Tor exit node beaconing**: pivot to known Tor exit IP list as
  a dynamic selection.

## Severity guidance

C2 beaconing is typically **high** to **critical** -- it is a
late-kill-chain signal indicating successful initial access +
persistence. Lower to **medium** for single connections without
aggregation; raise to **critical** when correlated with a recent
file-event signal (Pattern 1 or Pattern 2).
