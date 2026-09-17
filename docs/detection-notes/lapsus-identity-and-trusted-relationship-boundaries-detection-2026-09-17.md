<!--
Companion detection note covering two LAPSUS$-labelled Sigma rules. The cited
Microsoft report documents the actor's identity-centric access tradecraft, but
does NOT establish either rule's Windows Security EventID selection or its
correlation threshold. These remain test-tier review hypotheses, not actor
attribution on a hit.
- resources/examples/credential_access/observed_lapsus_t1556.yml
- resources/examples/initial_access/observed_lapsus_t1199.yml
Primary source: https://www.microsoft.com/en-us/security/blog/2022/03/22/dev-0537-criminal-actor-targeting-organizations-for-data-exfiltration-and-destruction/
No exploit or PoC involved; defensive documentation only.
-->

# LAPSUS$ Identity and Trusted-Relationship Rules: Evidentiary Boundaries

Microsoft tracks DEV-0537 as LAPSUS$ and reports identity-centred activity:
credential and MFA-approval acquisition, compromised credentials used against
VPN, RDP, VDI and identity providers, and access obtained through employees,
suppliers or business partners. That is useful actor and technique context. It
is not evidence that an individual Windows Security event identifies LAPSUS$.

## What the rules actually detect

**`observed_lapsus_t1556.yml`** matches Windows Security event IDs 4670, 4738
or 4720 whose `ObjectName` contains an MFA-related string, then its second
document alerts when four such matches share an object name within one minute.
This is a generic burst heuristic for suspicious identity-administration
activity. The source describes MFA-prompt abuse, account recovery and help-desk
password resets; it does not map those behaviours to these event IDs, object
names or the four-per-minute threshold.

**`observed_lapsus_t1199.yml`** matches a successful Kerberos Windows logon
(4624, type 3 or 10) except a workstation beginning `INT-`. This is a generic
remote-logon heuristic. The source documents supplier and partner access as one
possible route, but it does not show that the resulting sign-in is Kerberos,
appears as this Windows event, or can be distinguished from ordinary employee
and vendor access using the supplied `INT-` filter.

## What the source supports — and what it does not

The source supports treating unusual MFA administration, account-recovery
activity and third-party access as investigation context when other evidence
already points to this actor. It does not supply a Windows capture, field
mapping, baseline, threshold rationale or an actor-specific indicator for
either rule. MITRE ATT&CK technique labels provide taxonomy, not telemetry
proof.

Accordingly, neither rule should be used for attribution. A hit means only
that the local environment saw the generic condition described above. Keep the
rules at `status: test` until a source-backed telemetry manifestation and a
real-environment tuning result exist.

## Triage guidance

1. For MFA or account changes, identify the initiating identity, approval
   record, help-desk ticket and normal administration workflow before treating
   the event as suspicious.
2. For remote logons, compare the account, source, device posture and expected
   vendor-access path against local identity-provider and VPN/VDI logs; a
   Windows 4624 alone cannot establish a trusted-relationship intrusion.
3. Escalate only when independent context corroborates compromise. Do not add
   the actor name to an incident solely because one of these rules matched.

---

*Detection content from WinstonRedGuard (WRG-11). Sources: [Microsoft Threat
Intelligence: DEV-0537 criminal actor targeting organizations for data
exfiltration and destruction](https://www.microsoft.com/en-us/security/blog/2022/03/22/dev-0537-criminal-actor-targeting-organizations-for-data-exfiltration-and-destruction/),
[MITRE ATT&CK: LAPSUS$](https://attack.mitre.org/groups/G1004/), [MITRE ATT&CK:
T1556](https://attack.mitre.org/techniques/T1556/) and [MITRE ATT&CK:
T1199](https://attack.mitre.org/techniques/T1199/).*
