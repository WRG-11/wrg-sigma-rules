<!--
Companion detection note covering FOUR unrelated Sigma rules -- three ransomware/RaaS groups plus one
actively-exploited CVE, each with its own independent vendor/CISA sourcing:
- resources/examples/initial_access/observed_inc_ransom_t1566_001.yml
- resources/examples/initial_access/observed_interlock_t1189.yml
- resources/examples/lateral_movement/observed_anubis_ransomware_t1021_001.yml
- resources/examples/initial_access/observed_sharepoint_cve_2026_58644_w3wp_shell_spawn_t1190.yml
Sources: BleepingComputer + Microsoft Security blog (INC Ransom) / BleepingComputer + Sekoia (Interlock) /
BleepingComputer + TrendMicro (Anubis) / CISA KEV + Microsoft's own advisory + Rapid7 (SharePoint CVE-2026-58644).
Detection/defense only, no exploit/PoC reproduced beyond what the sources already published.
-->

# Four More Threats: INC Ransom's Macro-Enabled Office Docs, Interlock's Fake-IT-Tool ClickFix Lures, Anubis's RDP Lateral Movement, and SharePoint's Actively-Exploited Zero-Day

Four independently-sourced threats — three ransomware operations and one CVSS-9.8 actively-exploited-as-zero-day SharePoint vulnerability — each targeting a different stage of the intrusion chain (phishing delivery, drive-by payload fetch, lateral movement, remote code execution).

## What each threat actually does

**1. INC Ransom (BleepingComputer + Microsoft Security blog, targeting healthcare).** A double-extortion ransomware operation Microsoft's own advisory ties to healthcare-sector targeting (NHS Scotland among the publicly reported victims per BleepingComputer), gaining initial access via phishing emails carrying macro-enabled Office documents that, once a victim enables macros, shell out to a script interpreter to fetch the next stage.

**2. Interlock (BleepingComputer + Sekoia, ClickFix fake-IT-tool lures).** Distinctive initial-access method: rather than a conventional phishing attachment, Interlock lures victims into running what appears to be a legitimate IT support tool download — the payload is served to a browser still running outdated Java/Flash/Silverlight plugin runtimes, a signal both sources tie to the campaign's targeting of under-patched endpoints specifically.

**3. Anubis ransomware (BleepingComputer + TrendMicro, wiper-equipped).** An emerging ransomware operation TrendMicro's research (cited in this rule's references) profiles as adding a WIPER capability that destroys files beyond recovery even after a ransom payment — a distinct risk profile from ransomware operations that merely encrypt (the affected files are unrecoverable regardless of payment, mapped separately to T1486 in this rule's own tags). This rule's detection logic targets the lateral-movement stage (RDP-based, per both sources), the same underlying TTP shape as the Akira rule in this corpus's companion batch1 note — worth reading together as the same convergent technique appearing in yet another, unrelated group.

**4. SharePoint Server CVE-2026-58644 (CISA KEV + Microsoft's own advisory + Rapid7, CVSS 9.8).** A real, actively-exploited-as-a-zero-day on-premises SharePoint Server deserialization RCE, confirmed by Microsoft's own advisory and added to CISA's KEV catalog 2026-07-16 with a 3-day remediation deadline for federal agencies — signaling active, urgent exploitation at disclosure time. Post-exploitation activity documented in Microsoft's and CISA's advisories includes IIS machine-key theft and malware deployment. Verification discipline worth noting: this rule's own description explicitly flags that secondary sources DISAGREE on the exact vulnerable endpoint path and webshell filenames — several match the well-known 2025 "ToolShell" SharePoint chain and may be conflated with it rather than confirmed for this specific CVE — and those specifics are deliberately NOT encoded in the detection logic. What IS independently corroborated, and is also simply how this CVE class mechanically works (the deserialization payload executes inside the IIS worker process), is `w3wp.exe` spawning a shell or script-interpreter child, particularly PowerShell with an encoded/obfuscated command flag — a legitimate SharePoint worker process has no normal reason to do either.

## The detection signals

- **#1 (process_creation logsource):** an Office application (`winword.exe`, `excel.exe`, `powerpnt.exe`, `outlook.exe`) spawning a shell/script-interpreter child (`cmd.exe`, `powershell.exe`, `wscript.exe`, `mshta.exe`) — the classic macro-enabled-document-shells-out pattern.
- **#2 (proxy logsource):** a request carrying a legacy-plugin User-Agent string (`Java/1.`, `Java/6`, `Java/7`, `Shockwave Flash`, `Silverlight`) AND fetching a payload-shaped URI (`.exe`, `.jar`, `.hta`, `.js`, `.vbs`) — the combination is the discriminator, since either condition alone is common browsing noise.
- **#3 (Windows security logsource):** `EventID: 4624` + `LogonType: 10` (any successful interactive/RDP logon) — deliberately broad, same shape as this corpus's Akira rule (see companion batch1 note), since the advisory's point is that Anubis affiliates use ordinary RDP for lateral movement.
- **#4 (process_creation logsource):** `w3wp.exe` as parent spawning a shell/interpreter child, OR `w3wp.exe` as parent with a command line containing an encoded-PowerShell flag (`-EncodedCommand`, `-enc `, `-ec `) — either condition alone is sufficient.

## Known limitations (per rule)

**#1** cannot distinguish this from a signed, macro-enabled internal business template that legitimately shells out to a script for document automation — a real source of noise in environments that still use VBA-based automation workflows.

**#2** assumes the log source captures User-Agent strings at the proxy layer; a legacy internal application still running an outdated runtime that legitimately downloads a signed installer or script during a scheduled update is the documented false-positive class — narrow but not impossible in environments with legacy dependencies.

**#3** flags every interactive RDP logon, not just malicious ones — same limitation and same mitigation path as this corpus's Akira rule (correlate with account/host context, see companion batch1 note for the same discussion).

**#4** deliberately does NOT encode the specific vulnerable endpoint path or webshell filenames some secondary sources report, because this rule's own sourcing found those details unconfirmed/possibly conflated with a prior, different SharePoint exploit chain — a real limitation is that this rule therefore cannot distinguish CVE-2026-58644 exploitation specifically from any other exploitation chain that also reaches code execution through the IIS worker process (including the 2025 ToolShell chain this rule's own description warns may be conflated in other write-ups). SharePoint farm administration scripts or approved third-party web parts that legitimately shell out from the IIS worker process are a documented, if rare, false-positive class — confirm against a known baseline before dismissing a hit as benign, and EDR agents injecting monitoring child processes under IIS worker processes are a similar source of noise.

## What to do right now

1. **#4 is the most urgent item in this note**: CVE-2026-58644 was added to CISA KEV with a 3-day remediation deadline — patch per Microsoft's advisory immediately if not already applied, independent of whether this rule has fired, since KEV listing means opportunistic scanning against this CVE should be assumed ongoing.
2. **#1**: if your org still relies on macro-enabled Office automation, verify a signing/allowlist policy exists to distinguish legitimate templates from phishing payloads — this is the root tuning question for reducing #1's noise.
3. **#2**: audit for browsers/endpoints still running legacy Java/Flash/Silverlight runtimes independent of whether this rule fires — their mere presence is the underlying exposure Interlock's campaign specifically targets.
4. **#3's general lesson** (shared with Akira in the companion note): if RDP-based lateral movement is a real risk in your environment, invest in the account/host correlation layer both this rule and the Akira rule's own documentation say is the actual fix, not just the single-event signal either rule currently provides.
5. Deploy all four detection rules against the log sources each requires.

---

*Detection content from WinstonRedGuard (WRG-11). Defensive detection of three ransomware operations and one actively-exploited CVE. References: [BleepingComputer: INC Ransom](https://www.bleepingcomputer.com/news/security/new-inc-ransom-ransomware-gang-threatens-victims-with-data-leaks/), [Microsoft Security: INC ransomware targeting healthcare](https://www.microsoft.com/en-us/security/blog/2024/10/28/inc-ransomware-targeting-healthcare/), [BleepingComputer: Interlock ClickFix](https://www.bleepingcomputer.com/news/security/interlock-ransomware-gang-pushes-fake-it-tools-in-clickfix-attacks/), [Sekoia: Interlock ransomware](https://www.sekoia.io/en/blog/interlock-ransomware-evolving-under-the-radar/), [BleepingComputer: Anubis wiper](https://www.bleepingcomputer.com/news/security/anubis-ransomware-adds-wiper-to-destroy-files-beyond-recovery/), [TrendMicro: Anubis ransomware](https://www.trendmicro.com/en_us/research/25/f/anubis-a-closer-look-at-an-emerging-ransomware.html), [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [Rapid7: CVE-2026-58644](https://www.rapid7.com/blog/post/etr-cve-2026-58644-microsoft-sharepoint-server-unauthenticated-remote-code-execution-vulnerability-exploited-in-the-wild/).*
