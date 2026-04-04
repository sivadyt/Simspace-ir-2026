# Splunk Queries — IR Reference
### April 2, 2026 — SimSpace LiveFire Exercise

All queries used during the live investigation, organized by phase.

---

## Phase 1 — Initial Detection

```spl
# All outbound traffic from patient zero
index=* src_ip="172.16.4.101" | table _time, src_ip, dest_ip, url, bytes_out | sort _time

# Broad keyword search (when field names are unknown)
index=* 172.16.4.101

# Sort oldest to newest
index=* 172.16.4.101 | sort _time
```

---

## Phase 2 — C2 Identification

```spl
# All requests to estonine.com
index=* url="*estonine*" | table _time, src_ip, dest_ip, url, bytes_out | sort _time

# All machines that registered with C2
index=* url="*estonine*/register*" | table _time, src_ip, url | sort _time

# Check beaconing interval (timechart)
index=* dest_ip="211.56.98.146" | timechart span=1m count by src_ip

# Any C2 traffic after user pause at 10 AM
index=* dest_ip="211.56.98.146" earliest="04/02/2026:10:00:00" | stats count by src_ip, _time | sort _time

# All machines that hit C2
index=* url="*estonine*" | stats count by src_ip | sort -count
```

---

## Phase 3 — Malware Analysis

```spl
# PowerShell activity on compromised host (primary query)
index="windows" host="br-win10-1" powershell earliest=-4h

# Find malware files
index=* "procduwp" | stats count by host | sort -count

# File creation in Public folder
index="windows" "C:\\Users\\Public\\" earliest="04/02/2026:08:00:00" | table _time, host, CommandLine | sort _time

# out.txt access history (key artifact)
index="windows" "C:\\Users\\Public\\out" | table _time, host, CommandLine | sort _time
```

---

## Phase 4 — Credential Theft

```spl
# Mimikatz download via proxy
index=* url="*simonxu*" OR url="*mimi.txt*" | stats count by src_ip

# Full Mimikatz traffic details
index=* url="*simonxu*" | table _time, src_ip, dest_ip, bytes_out, url | sort _time

# Check if Mimikatz ran on other hosts
index=* ("Mimikatz" OR "mimi.txt" OR "sekurlsa" OR "logonpasswords") | stats count by host | sort -count
```

---

## Phase 5 — Lateral Movement

```spl
# Explicit credential logon events
index=* EventCode=4648 earliest="04/02/2026:00:00:00" | table _time, host, AccountName | sort _time

# SMB lateral movement
index=* src_ip="172.16.4.101" dest_port=445 earliest="04/02/2026:08:00:00" | table _time, src_ip, dest_ip | sort _time

# Password spray evidence
index="windows" "net use" "\\\\*" "/user:administrator" earliest="04/02/2026:08:00:00" | table _time, host, CommandLine | sort _time

# Successful password stored in out.txt
index="windows" "out.txt" earliest="04/02/2026:08:55:00" | table _time, host, CommandLine | sort _time
```

---

## Phase 6 — Persistence

```spl
# Backdoor account creation
index=* EventCode=4720 earliest="04/02/2026:00:00:00" | table _time, host, AccountName, SubjectUserName | sort _time

# Account added to admin group
index=* EventCode=4732 earliest="04/02/2026:00:00:00" | table _time, host, AccountName, MemberName | sort _time

# New service installed (sshd)
index=* EventCode=7045 earliest="04/02/2026:00:00:00" | table _time, host, ServiceName, ServiceFileName | sort _time

# Search for backdoor accounts across all hosts
index=* ("b-admin0" OR "i-admin0" OR "o-admin0" OR "r-admin0") | stats count by host

# SSH connections to br-win10-1
index=* host="br-win10-1" dest_port=22 OR src_port=22 earliest="04/02/2026:09:00:00" | table _time, src_ip, dest_ip | sort _time
```

---

## Phase 7 — Anti-Forensics

```spl
# Log clearing events — all hosts
index=* EventCode=1102 earliest="04/02/2026:00:00:00" | table _time, host, user | sort _time

# All log clearing today
index=* EventCode=1102 | stats count by host, _time
```

---

## Phase 8 — Exfiltration

```spl
# Exchange mailbox export
index=* "MailboxExportRequest" earliest="04/02/2026:00:00:00" | table _time, host, Message, CommandLine | sort _time

# backup.pst references
index=* "backup.pst" earliest="04/02/2026:00:00:00" | table _time, host, CommandLine | sort _time

# jefferson.livingston references
index=* sourcetype="WinEventLog*" "jefferson.livingston" earliest="04/02/2026:00:00:00" | table _time, host, Message | sort _time

# Data volume by destination — exfil detection
index=* (src_ip="172.16.4.101" OR src_ip="172.16.5.102") earliest="04/02/2026:08:55:00" | stats sum(bytes_out) as total_bytes by dest_ip | sort -total_bytes

# File harvesting script
index="windows" "gci C:\\Users" earliest="04/02/2026:08:55:00" | table _time, host, CommandLine | sort _time

# Staging folder activity
index=* "C:\\Windows\\Tasks\\" earliest="04/02/2026:00:00:00" | table _time, host, CommandLine | sort _time
```

---

## Phase 9 — Containment Verification

```spl
# Any activity from infected hosts after 10 AM pause
index=* src_ip="172.16.4.101" earliest="04/02/2026:10:00:00" | sort _time

# Any C2 beaconing after pause
index=* dest_ip="211.56.98.146" earliest="04/02/2026:10:00:00" | table _time, src_ip | sort _time

# Who accessed out.txt at 12:46 PM
index="windows" host="br-win10-1" earliest="04/02/2026:12:44:00" latest="04/02/2026:12:50:00" | table _time, AccountName, CommandLine, ProcessName | sort _time

# Logons to br-win10-1 post-pause
index=* EventCode=4624 host="br-win10-1" earliest="04/02/2026:10:00:00" | table _time, AccountName, IpAddress, LogonType | sort _time

# Check if attacker still active (most recent 20 events)
index="windows" host="br-win10-1" earliest="04/02/2026:12:00:00" | table _time, AccountName, CommandLine | sort -_time | head 20
```
