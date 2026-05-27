# Pattern 2 -- Credential access via OS internals

**MITRE coverage**: T1003 (OS Credential Dumping), T1003.001
(LSASS memory), T1003.002 (SAM registry hive), T1110 (Brute Force),
T1555 (Credentials from Password Stores), T1556 (Modify
Authentication Process).

**Detection type**: `process_creation` + `authentication` +
`registry_event`.

## What it detects

Adversary access to credential material at the OS-internals layer:
LSASS memory access, SAM registry hive extraction, Kerberos
ticket-granting service requests, MFA modification, and high-volume
authentication failure patterns.

## Canonical detection shape

```yaml
logsource:
  category: process_creation
  product: windows
detection:
  selection_lsass:
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess:
    - '0x1010'
    - '0x1410'
    - '0x1438'
  selection_sam:
    TargetFilename|contains:
    - '\Windows\System32\config\SAM'
    - '\Windows\System32\config\SECURITY'
  selection_brute_force:
    EventID: 4625
    LogonType: [2, 3, 10]
  filter_known_security_tools:
    Image|endswith:
    - '\procdump.exe'
    - '\Sysinternals\dumpfile.exe'
  condition: |
    (selection_lsass or selection_sam or selection_brute_force)
    and not filter_known_security_tools
```

## Why it works

- **LSASS handle access selection** catches the canonical mimikatz /
  comsvcs.dll / built-in MiniDump flow. The three `GrantedAccess`
  values (`0x1010` / `0x1410` / `0x1438`) cover the documented
  process-access masks an attacker needs to dump LSASS memory.
- **SAM hive read selection** catches offline credential extraction
  paths (vssadmin shadow copy + extract SAM/SYSTEM/SECURITY hives,
  then run `secretsdump.py` offline).
- **Brute force selection** catches credential stuffing via the
  EventID 4625 (failed logon) + LogonType filter (network logon +
  remote interactive). Add **inline aggregation** to fire only on
  high-volume bursts (`>10 in 10m` per SourceIP).
- **Security tools filter** suppresses legitimate IT incident-response
  tooling that mimics the adversary signal.

## False positives

- **Endpoint security agents**: AV/EDR products legitimately access
  LSASS for memory scanning. Whitelist signed AV binaries by hash.
- **Backup tools**: VSS-based backup tools touch SAM/SYSTEM/SECURITY
  hives during system backups. Filter by parent process being a
  backup agent.
- **Password reset workflows**: high failed-logon counts can come
  from misconfigured service accounts hitting password rotation.
  Filter by `TargetUserName|startswith: 'svc_'`.

## Reference rules from corpus

- `credential_access/template_t1003_os_credential_dumping_lsass_access_mimikatz.yml`
- `credential_access/template_t1110_brute_force_high_volume_failed_logons.yml`
- `credential_access/template_t1555_credentials_from_password_stores_browser_cred_files.yml`
- `credential_access/template_t1556_modify_authentication_process_mfa_fatigue_adfs.yml`
- `credential_access/observed_lapsus_t1110_correlation.yml`

## Specialisations

- **Kerberoasting (T1558.003)**: pivot to TGS request volume + SPN
  enumeration -- `EventID 4769` filtered by `TicketEncryptionType 0x17`.
- **MFA fatigue (T1556 sub-variant)**: focus on rapid-burst
  authentication-modification events (`EventID 4670`/`4738`) targeting
  MFA-related objects.
- **Browser password store extraction (T1555 sub-variant)**: replace
  LSASS selection with browser credential store file access -- 
  `\Google\Chrome\User Data\*\Login Data`, `\Mozilla\Firefox\Profiles\
  *\logins.json`, etc.

## Severity guidance

LSASS / SAM access patterns are almost always **high** or **critical**
-- they are post-compromise credential-pivot signals with high
fidelity. Brute force is typically **medium** unless the volume
threshold is exceeded (then **high**).
