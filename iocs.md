# Indicators of Compromise
### IR-2026-0402 — SimSpace LiveFire Exercise

---

## Network IOCs

| Type | Value | Context |
|---|---|---|
| IP | `211.56.98.146` | Primary C2 server — South Korea — **BLOCK** |
| IP | `104.250.191.110` | Mimikatz delivery server — **BLOCK** |
| Domain | `estonine.com` | C2 domain — **BLOCK at DNS/proxy** |
| Domain | `proxy.east2south.simonxu.cc` | Mimikatz payload host — **BLOCK** |
| Domain | `simonxu.cc` | Parent domain — **BLOCK** |
| URL | `http://estonine.com/update` | C2 heartbeat (305 bytes returned) |
| URL | `http://estonine.com/update/3` | C2 command retrieval (~10.9KB) |
| URL | `http://estonine.com/update/4` | C2 command retrieval (~10.7KB) |
| URL | `http://estonine.com/update/5` | C2 command retrieval (second host) |
| URL | `http://estonine.com/register/{hostname}/windows` | Machine registration pattern |
| URL | `http://proxy.east2south.simonxu.cc/mimi.txt` | Mimikatz payload — 3.5MB |
| Port | `80` (HTTP) | All C2 traffic unencrypted |

---

## Host IOCs

| Type | Value | Context |
|---|---|---|
| File | `C:\Users\Public\procduwp.exe` | Malware binary — created 8:55 AM |
| File | `C:\Users\Public\out` | Credential dump / password spray output |
| File | `C:\Users\Public\out.txt` | Successful password written here |
| File | `C:\Windows\Tasks\eml.log` | Staged email log |
| File | `\\mailserver\C$\backup.pst` | Exfiltrated Exchange mailbox |
| MD5 | `8A2122E8162DBEF04694B9C3E0B6CDEE` | procduwp.exe |
| SHA256 | `B99D61D874728EDC0918CA0EB10EAB93D381E7367E377406E65963366C874450` | procduwp.exe |
| Path | `C:\Windows\Tasks\{username}\` | Per-user staging directories created by malware |

---

## Credentials

| Type | Value | Status |
|---|---|---|
| Account | `administrator@site` | **BURNED — disable immediately** |
| Password | `Simspace1!Simspace1!` | Hardcoded in malware — known to attacker pre-deployment |

---

## Backdoor Accounts

| Account | Host | Type | Action |
|---|---|---|---|
| `b-admin0` | `br-win10-1` | Local Administrator | **DELETE** |
| `i-admin0` | `br-win10-1` | Local Administrator | **DELETE** |
| `o-admin0` | `br-win10-1` | Local Administrator | **DELETE** |
| `r-admin0` | `br-win10-1` | Local Administrator | **DELETE** |
| `sshd` | `br-win10-1` | SSH service account | **DELETE + remove SSH** |

---

## Windows Event IDs

| Event ID | Description | Timestamp | Host |
|---|---|---|---|
| `1102` | Security audit log cleared | 9:02:45 AM | `br-win10-1` |
| `4648` | Logon with explicit credentials (lateral movement) | 9:03:29 AM | `br-win10-1` |
| `4720` | User account created (×5 backdoor accounts) | ~9:04 AM | `br-win10-1` |
| `4732` | User added to administrators group | ~9:04 AM | `br-win10-1` |
| `7045` | New service installed (sshd) | ~9:04 AM | `br-win10-1` |

---

## Compromised Hosts

| Host | IP | Status |
|---|---|---|
| Charley Fritz workstation | `172.16.4.101` | Compromised — patient zero |
| `br-win10-1.site.lan` | (internal) | Compromised — backdoors + SSH active |
| `dev-win10-2` | `172.16.5.102` | Compromised — via password spray |

---

## Exfiltrated Data

| Data | Method | Destination |
|---|---|---|
| `jefferson.livingston` Exchange mailbox | Exchange PowerShell remoting → PST export | `\\mailserver\C$\backup.pst` |
| File inventory (.txt, .csv, .dat paths) | Recursive `gci`, Base64 encoded | C2 via HTTP |
| All LSASS credentials on `br-win10-1` | Mimikatz `sekurlsa::logonpasswords` | C2 via HTTP |
