# SimSpace LiveFire — Incident Response Portfolio
**Analyst:** Ty | **School:** Metro State University | **Platform:** SimSpace LiveFire

This repository contains incident response write-ups from SimSpace LiveFire exercises conducted as part of cybersecurity training at Metro State University. Each exercise involves a real simulated attack investigated using Splunk, Sysmon, and Windows Event Logs.

---

## IR Exercises

| # | Date | Threat Actor | Scenario | Report |
|---|------|-------------|----------|--------|
| 1 | April 2, 2026 | Silk Typhoon | RAT Compromise & Exchange Exfiltration | [View write-up](#exercise-1--silk-typhoon--rat-compromise--exchange-exfiltration) |
| 2 | April 14, 2026 | APT28 / Fancy Bear | Spearphishing, C2, Data Exfiltration | [View write-up](#exercise-2--apt28--spearphishing-c2-and-data-exfiltration) |

---

## Exercise 1 — Silk Typhoon — RAT Compromise & Exchange Exfiltration
**Date:** April 2, 2026  
**Analyst:** Ty  
**Environment:** SimSpace LiveFire (Metro State University)  
**Threat Actor:** Silk Typhoon  

### Overview

On April 2nd, our team participated in a live incident response exercise on SimSpace. This writeup documents the full investigation conducted in real time using Splunk, covering everything from initial detection through credential theft, lateral movement, persistence, and confirmed email exfiltration.

### Attack Summary

| Field | Value |
|-------|-------|
| Exercise | SimSpace LiveFire — IR Scenario |
| Date | April 2, 2026 |
| Patient Zero | 172.16.4.101 — Charley Fritz workstation |
| Hosts Compromised | 3 confirmed |
| Severity | Critical |

### Attack Overview

A workstation was compromised via a custom RAT (`procdump.exe`) dropped in `C:\Users\Public\`. The malware established C2 communications, downloaded Mimikatz in memory, sprayed passwords to pivot to a second machine, installed SSH backdoors, and exfiltrated a user's Exchange mailbox — all within 15 minutes of the user logging in.

### Attack Chain

```
[8:00 AM] Charley Fritz logs in → workstation 172.16.4.101
         |
[8:55 AM] procdump.exe executes from C:\Users\Public\
         |-- Beacons to estonine.com every ~20s (port 80)
         |-- Registers: GET /register/br-win10-1/windows
         └-- Receives ~10KB command payloads each cycle
         |
[8:50 AM] Password spray → \\dev-win10-2
         |-- 100 random passwords attempted via net use
         |-- Fallback: hardcoded Simspace1!Simspace1!
         └-- SUCCESS at 8:59:29 AM
         |
[9:00 AM] Mimikatz → LSASS dump
         |-- sekurlsa::logonpasswords
         └-- NTLM hashes extracted
         |
[9:05 AM] Lateral movement → dev-win10-2 (172.16.5.102)
         |-- PsExec / net use with stolen creds
         └-- procdump.exe dropped in C:\Users\Public\
         |
[9:10 AM] SSH backdoor installed on dev-win10-2
         |-- OpenSSH for Windows installed silently
         └-- Listening on port 22
         |
[9:15 AM] Exchange mailbox exfiltration
         └-- charley.fritz@site.lan mailbox exported via PowerShell
```

### Key IOCs (Exercise 1)

| Type | Value |
|------|-------|
| Malicious binary | `C:\Users\Public\procdump.exe` |
| C2 server | `estonine.com` (port 80) |
| Patient zero | 172.16.4.101 (Charley Fritz) |
| Lateral movement target | 172.16.5.102 (dev-win10-2) |
| Hardcoded creds | `Simspace1!Simspace1!` |
| Exfil target | `charley.fritz@site.lan` Exchange mailbox |

### MITRE ATT&CK (Exercise 1)

| ID | Tactic | Technique |
|----|--------|-----------|
| T1059.001 | Execution | PowerShell |
| T1078 | Privilege Escalation | Valid Accounts |
| T1110.001 | Credential Access | Password Spraying |
| T1003.001 | Credential Access | LSASS Memory Dump |
| T1021.002 | Lateral Movement | SMB/Windows Admin Shares |
| T1098 | Persistence | SSH Backdoor |
| T1114.002 | Exfiltration | Remote Email Collection |

> Full IOCs and Splunk queries in `iocs.md` and `splunk-queries.md`
>
> ---
>
> > # APT28 Incident Response — SimSpace LiveFire Lab
**Date:** April 14, 2026  
**Analyst:** Ty  
**Environment:** SimSpace LiveFire (Metro State University)  
**Threat Actor:** APT28 / Fancy Bear  

---

## Overview

This repository documents a full incident response exercise conducted in a SimSpace LiveFire environment. A simulated APT28 campaign was detected and investigated using Splunk. The attack chain was traced from initial access through exfiltration using Sysmon logs, Windows Event Logs, and pre-built Splunk alerts.

---

## Attack Summary

| Field | Value |
|-------|-------|
| Initial Access | Spearphishing link — drive-by download of `photos.exe` |
| Affected Host | `dev-win10-3` (172.16.5.73) |
| Compromised User | `site\thomas.michael` |
| C2 Server | `172.16.2.6:8080` (site-proxy.site.lan) |
| Exfil Destination | `http://fastdataexchange.org/` |
| Red Team C2 | `210.210.210.70` (Chimera) |

---

## Attack Timeline

| Time (ET) | Event |
|-----------|-------|
| 19:57 | `photos.exe` executed by thomas.michael via explorer.exe |
| 19:58 | Process, peripheral, and file/directory discovery begins |
| 20:00 | PowerShell enumerates Office and PDF docs across `C:\Users` |
| 20:01 | Screenshots captured via PowerShell PrintScreen automation |
| 20:02 | Hardcoded admin credentials used to escalate to Administrator |
| 20:08 | `help_win_x86.exe` downloaded from `hostsvenet.com` |
| 20:08 | Persistence via registry run key and logon script |
| 20:08 | Files hidden with `attrib +h`, timestamps stomped to 01/01/1969 |
| 20:08 | Data exfiltrated via HTTP POST to `fastdataexchange.org` |
| 20:08 | Application and System event logs cleared |
| 20:10 | Staged files deleted after exfiltration |
| 20:14 | Exchange logs cleared on `site-mail.site.lan` |

---

## Splunk Queries Used

### Hunt for execution from C:\Users\Public
```spl
index=* Image="*\\Users\\Public\\*"
| stats count min(_time) as first_seen max(_time) as last_seen
  by host, User, Image, ParentImage, CommandLine
| sort - last_seen
```

### Network connections to/from suspicious IP
```spl
index=* (src_ip="172.16.5.73" OR dest_ip="172.16.5.73")
| table _time, host, User, src_ip, dest_ip, dest_port, Image
| sort - _time
```

### All hosts beaconing to C2
```spl
index=* dst_ip="172.16.2.6" dst_port=8080
| stats count min(_time) as first_seen max(_time) as last_seen
  by src_host_name, process_path, user_name
| sort - first_seen
```

### File creation in C:\Users\Public
```spl
index=* EventCode=11 TargetFilename="*\\Users\\Public\\*"
| table _time, host, user_name, Image, TargetFilename
```

### PowerShell spawned by photos.exe
```spl
index=* host="dev-win10-3" EventCode=1 Image="*powershell.exe"
| table _time, host, user_name, Image, ParentImage, ParentCommandLine, CommandLine
| sort - _time
```

### Full post-exploitation command map
```spl
index=* ParentImage="*\\photos.exe"
| stats min(_time) as start_time values(Image) as child_processes
  values(CommandLine) as commands_executed
  by host, User, ParentImage
| convert ctime(start_time)
```

### Confirm exfiltration
```spl
index=* "fastdataexchange.org"
| table _time, host, user_name, process_path, CommandLine
```

### Log clearing events
```spl
index=* EventCode=1102 OR EventCode=104
| table _time, host, user_name, Message
```

---

## Indicators of Compromise

| Type | Value |
|------|-------|
| Malicious binary | `C:\Users\Public\photos.exe` |
| Second payload | `C:\Users\Public\help_win_x86.exe` |
| Staging directory | `C:\Users\Public\Downloads\-temp482` |
| Screenshot dump | `C:\Windows\Tasks\temp482\` |
| C2 relay (internal) | `172.16.2.6:8080` |
| Exfil server | `http://fastdataexchange.org/` |
| Payload source | `hostsvenet.com` |
| Red team C2 | `210.210.210.70` (Chimera) |
| Compromised user | `site\thomas.michael` |
| Hardcoded creds | `Administrator@site / Simspace1!Simspace1!` |
| Persistence key | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` (BackgroundColor) |

---

## MITRE ATT&CK Mapping

| ID | Tactic | Technique |
|----|--------|-----------|
| T1566.002 | Initial Access | Spearphishing Link |
| T1204.002 | Execution | User Execution: Malicious File |
| T1059.001 | Execution | PowerShell |
| T1547.001 | Persistence | Registry Run Key |
| T1037.001 | Persistence | Logon Script |
| T1078 | Privilege Escalation | Valid Accounts |
| T1036 | Defense Evasion | Masquerading |
| T1070.001 | Defense Evasion | Log Clearing |
| T1070.006 | Defense Evasion | Timestomping |
| T1564.001 | Defense Evasion | Hidden Files and Directories |
| T1083 | Discovery | File and Directory Discovery |
| T1120 | Discovery | Peripheral Device Discovery |
| T1057 | Discovery | Process Discovery |
| T1074 | Collection | Data Staged |
| T1113 | Collection | Screen Capture |
| T1071 | C2 | Standard Application Layer Protocol |
| T1105 | C2 | Ingress Tool Transfer |
| T1041 | Exfiltration | Exfiltration Over C2 Channel |

---

## Report

Full IR report available in the [report/](report/) folder.

---

## Tools Used

- **Splunk** — log aggregation and threat hunting
- - **Sysmon** — endpoint telemetry (EventCodes 1, 3, 11)
  - - **SimSpace LiveFire** — lab environment and attack simulation
    - - **MITRE ATT&CK** — TTP mapping
