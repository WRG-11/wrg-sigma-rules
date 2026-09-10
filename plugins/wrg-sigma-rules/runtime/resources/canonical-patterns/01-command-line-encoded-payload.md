# Pattern 1 -- Command-line encoded payload

**MITRE coverage**: T1027 (Obfuscated Files or Information),
T1059.001 (PowerShell), T1059.006 (Python).

**Detection type**: `process_creation` (Windows + Linux).

## What it detects

Process invocations carrying an encoded payload on the command line.
This pattern captures the common adversary trick of base64-encoding
or hex-encoding a malicious script body so it bypasses simple
command-line string-match defenses, then decoding + executing at
runtime.

## Canonical detection shape

```yaml
logsource:
  category: process_creation
  product: windows  # or linux
detection:
  selection_interpreter:
    Image|endswith:
    - '\powershell.exe'
    - '\pwsh.exe'
    - '\cmd.exe'
    - '/bash'
    - '/python'
  selection_encoding_flag:
    CommandLine|contains:
    - ' -enc '
    - ' -EncodedCommand '
    - ' -e '
    - ' base64 -d '
  selection_long_base64_blob:
    CommandLine|re: '[A-Za-z0-9+/]{200,}={0,2}'
  condition: selection_interpreter and (selection_encoding_flag or selection_long_base64_blob)
```

## Why it works

- **Encoding flag selection** catches the most common case --
  explicit `-enc` / `-EncodedCommand` / `-e` flags on PowerShell, or
  `base64 -d` piped on Linux. High-precision, low false-positive.
- **Long base64 blob regex** catches the case where an actor avoids
  the explicit flag (e.g., by using `[System.Convert]::FromBase64String`
  inline) but still emits a recognisable base64 string on the command
  line. Width threshold `>=200` filters out incidental base64 strings
  that legitimately appear (e.g., GUID encodes).
- **Interpreter selection** ensures the rule only fires on actual
  command interpreters, not on every process that happens to have a
  base64 substring in its argv.

## False positives

- **Build tools**: MSBuild + CMake + npm sometimes pass base64-encoded
  arguments to scripts. Filter on `ParentImage|endswith` for known
  build-tool parents.
- **Telemetry encoders**: APM agents may pass base64-encoded
  configuration. Filter on signed binary status.
- **Compressed Powershell launchers**: legitimate IT scripts
  occasionally use `-enc` for cross-OS portability. Whitelist by
  PowerShell script hash if available.

## Reference rules from corpus

- `defense_evasion/template_t1027_obfuscated_files_or_information_encoded_payload.yml`
- `defense_evasion/observed_alphv_t1027_obfuscation.yml`
- `execution/template_t1059_001_powershell_encoded_command_execution.yml`
- `execution/observed_alphv_t1059_001.yml`

## Specialisations

- **PowerShell-only variant**: drop the `cmd.exe`/`bash`/`python`
  entries from `selection_interpreter`.
- **Sub-technique T1059.006 (Python)**: pivot to Python-specific
  encoding patterns -- `python -c "exec(...)"` + `__import__('base64')`.
- **Sub-technique T1218.011 (rundll32)**: pivot to rundll32 with
  COM-server-launch + base64 PowerShell trail; see Pattern 3.

## Severity guidance

Most often **high** -- encoded payloads on the command line are a
strong adversary signal. Drop to **medium** if your environment has
significant legitimate use of `-enc` (build pipelines, scheduled
tasks).
