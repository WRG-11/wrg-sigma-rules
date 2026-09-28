<!--
Companion detection note for three observed rules:
- resources/examples/persistence/observed_crypto24_t1543_003.yml
- resources/examples/impact/observed_crypto24_t1486.yml
- resources/examples/impact/observed_doommageddon_t1486.yml
Source review records: docs/source-reviews/2026-09-28-crypto24-doommageddon.yml
Detection/defense only, no exploit/PoC reproduced.
-->

# Crypto24 and Doommageddon: Family-Specific Host Artefacts

These three rules differ from the corpus's generic ransomware signatures in one
respect: each matches a string that a cited source documents for one specific
family, instead of a behaviour every ransomware group shares.

## Crypto24 -- masqueraded service creation (T1543.003)

Trend Micro's analysis of Crypto24 intrusions shows the operators creating two
services with `sc.exe` on victim Windows hosts, one for a keylogger and one for
the ransomware:

- `sc create WinMainSvc type= share start= auto binPath= "C:\Windows\System32\scvhost.exe -k WinMainSvc"`
- `sc create MSRuntime type= share start= auto binpath= "C:\Windows\System32\svchost.exe -k MSRuntime" displayname= "Microsoft Runtime Manager"`

The rule fires on an `sc.exe ... create` command line that either points at the
typosquatted host `scvhost.exe` or uses one of the two documented service
groups. The typosquatted path alone is a high-confidence signal: no legitimate
Windows service is hosted by `scvhost.exe`.

## Crypto24 -- `.crypto24` extension (T1486)

The same report states that files are renamed during encryption by appending
`.crypto24`. A single write with that suffix is enough to alert.

## Doommageddon -- `.doomag` extension (T1486)

PCrisk ran a Doommageddon sample obtained from VirusTotal and observed files
renamed from `1.jpg` to `1.jpg.doomag`. CYFIRMA reports that the ransomware
primarily affects Windows. The ransom note name, `README_DECRYPT.txt`, is not
part of the rule: several unrelated families use the same name.

## Known limitations

- **Static strings.** All three rules match strings an operator can change on
  the next build. They detect these documented builds, not the families in
  general.
- **Lagging for T1486.** The two extension rules fire once encryption is
  already running. Pair them with earlier-stage signals such as the corpus's
  service-creation, shadow-copy deletion (T1490) and security-tool
  tampering (T1562.001) templates.
- **A hit is not attribution.** A match shows the documented artefact is
  present. It does not by itself establish who deployed it.

## What to do with a hit

1. Treat a `.crypto24` or `.doomag` write as active encryption: isolate the
   host before confirming the family.
2. For the service rule, inspect the created service's binary path and DLL,
   and look for the matching keylogger or ransomware service on other hosts.
3. Review the source-review records above before citing a hit as actor
   evidence in a report.

---

*Detection content from WinstonRedGuard (WRG-11). References: [Trend Micro -- Crypto24](https://www.trendmicro.com/en_us/research/25/h/crypto24-ransomware-stealth-attacks.html), [PCrisk -- Doommageddon](https://www.pcrisk.com/removal-guides/35523-doommageddon-ransomware), [CYFIRMA weekly report, 10 Jul 2026](https://www.cyfirma.com/news/weekly-intelligence-report-10-jul-2026/). MITRE ATT&CK: [T1543.003](https://attack.mitre.org/techniques/T1543/003/), [T1486](https://attack.mitre.org/techniques/T1486/).*
