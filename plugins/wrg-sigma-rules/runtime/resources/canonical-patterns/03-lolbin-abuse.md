# Pattern 3 -- Living-off-the-land binary abuse

**MITRE coverage**: T1218 family (Signed Binary Proxy Execution),
T1218.011 (rundll32), T1218.010 (regsvr32), T1059 (Command and
Scripting Interpreter), T1036.005 (Masquerading: Match Legitimate
Name).

**Detection type**: `process_creation`.

## What it detects

Adversary use of legitimate signed Windows / Linux binaries to
execute malicious code -- "living off the land". Common LOLBins
include `certutil.exe` (download), `mshta.exe` (script execution),
`regsvr32.exe` (squiblydoo COM hijack), `rundll32.exe` (COM scriptlet
execution), `installutil.exe` (.NET payload execution), and the
`csript`/`wscript` family.

## Canonical detection shape

```yaml
logsource:
  category: process_creation
  product: windows
detection:
  selection_lolbin_image:
    Image|endswith:
    - '\certutil.exe'
    - '\mshta.exe'
    - '\regsvr32.exe'
    - '\rundll32.exe'
    - '\installutil.exe'
    - '\msbuild.exe'
    - '\cscript.exe'
    - '\wscript.exe'
  selection_suspicious_args:
    CommandLine|contains:
    - '-urlcache'
    - '-decode'
    - 'javascript:'
    - 'vbscript:'
    - 'scrobj.dll'
    - 'http://'
    - 'https://'
  filter_canonical_path:
    Image|startswith:
    - 'C:\Windows\System32\'
    - 'C:\Windows\SysWOW64\'
  condition: |
    selection_lolbin_image and selection_suspicious_args
    and filter_canonical_path
```

## Why it works

- **LOLBin image selection** enumerates the most-abused signed binaries.
  The `endswith` match catches both 32-bit and 64-bit copies plus
  any masqueraded copy (see Pattern 2 / T1036.005).
- **Suspicious args selection** filters for the specific argument
  patterns that turn a legitimate LOLBin invocation into a malicious
  one. `-urlcache` + `-decode` are signature certutil download flags;
  `javascript:` / `vbscript:` are mshta script-protocol triggers;
  `scrobj.dll` is the regsvr32 squiblydoo signature.
- **Canonical path filter** keeps the rule firing only on legitimate
  signed copies in `System32` / `SysWOW64`. A masqueraded
  `certutil.exe` running from `C:\Users\<user>\AppData\` will fail
  this filter and be caught by Pattern 2 (Masquerading) instead.

## False positives

- **IT automation scripts**: `certutil` legitimately downloads CRLs
  + intermediate certificates as part of TLS validation. Filter by
  parent process being a known service / scheduled task.
- **Patch management**: `msbuild.exe` is used by Visual Studio + dev
  tools; filter by parent process if developer workstations are in
  scope.
- **Office macros**: `wscript.exe` / `cscript.exe` legitimately run
  from Office automation. Whitelist by parent process pattern.

## Reference rules from corpus

- `defense_evasion/template_t1036_005_masquerading_match_legitimate_name_anomalous_path.yml`
- `execution/template_t1059_command_and_scripting_interpreter_generic_shell_spawn.yml`
- `execution/template_t1204_001_user_execution_malicious_link_click_follow_through.yml`

## Specialisations

- **Squiblydoo (T1218.010)**: focus on `regsvr32.exe` +
  `/s /u /i:http://...` + `scrobj.dll` co-occurrence as a single
  selection clause.
- **HTA execution (T1218.005)**: focus on `mshta.exe` with `.hta`
  file argument from a non-Office parent.
- **InstallUtil .NET payload (T1218.004)**: focus on
  `installutil.exe` + `/logfile=` + `/U` flag pattern.

## Severity guidance

LOLBin abuse is typically **medium** to **high**. The fidelity
depends on the specific binary + argument pattern combination:
`certutil -urlcache -split -f http://...` is **high** (almost
exclusively malicious); `rundll32` with no arguments is **low**
(too common in legitimate Windows operation).
