# DC01 Audit Policy & Logging: SOC Analyst Study Guide

*A command-by-command record of how logging was configured and tested on `DC01`, written to also work as a standalone study reference.*

## The big picture

Windows records very little security activity by default. On `DC01` we switched on extra logging so that every logon, account change, and program launch leaves a record in the **Security log**. A SOC analyst can only detect and investigate what was logged — no log means no evidence.

Think of it as security cameras. The domain controller is the front desk that holds every key in the building, which is why attackers aim for it and why it gets the most cameras.

**Lab facts**

| Item | Value |
|---|---|
| Server | `DC01`, Windows Server 2022 Standard Evaluation |
| Domain | `soclab.local` (NetBIOS `SOCLAB`) |
| IP address | `192.168.56.10` on the Host-Only network |
| Test users | `alice.smith`, `bob.jones`, `carol.white` |
| Service account | `svc.backup` (Kerberoasting target) |
| Snapshots | `Fresh-install` → `DC-promoted` → `Auditing-Enabled` → `Spray-Detected` → `Kerberoast-Executed` |

> **Note on passwords:** All passwords referenced in this lab (e.g. test account passwords, DSRM password) were simple, lab-only values set for this isolated environment and have been redacted/replaced with placeholders below. Never reuse lab passwords anywhere real.

**What was done, in order**

1. Turned on audit policies with `auditpol` so Windows writes security events.
2. Added command-line and PowerShell script logging so we can see what programs were told to do.
3. Enlarged the Security log so old events aren't overwritten.
4. Tested it by causing a failed logon and running commands, then reading the events back.
5. Installed Sysmon for richer telemetry (hashes, parent-process chains, network connections).
6. Added a second VM (`soc-victim`), domain-joined it, and used it as the real attack origin point.
7. Simulated password spraying and Kerberoasting, and read the real resulting events.

---

## Step 1: Audit policies (`auditpol`)

`auditpol` switches audit categories on or off. Each line enables one subcategory: `/success:enable` logs actions that worked, `/failure:enable` logs actions that were refused. Everything lands in the **Security log**.

```
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
```

- `/set` changes a setting.
- `/subcategory:"Logon"` names the category to change.
- `/success:enable /failure:enable` logs both good and bad attempts.

**Core categories enabled first**

| Subcategory | Event IDs | What it records | What an analyst hunts for |
|---|---|---|---|
| Logon | 4624 (success), 4625 (failure) | Every logon attempt | Bursts of failures, then a success; logons at odd hours |
| Logoff | 4634 | End of a session | Session length, to tie activity to a session |
| Special Logon | 4672 | A logon by an account with powerful rights | Admin-level logon by someone who shouldn't have it |
| Credential Validation | 4776 | The DC checking an NTLM password | Many different accounts failing from one source |
| Kerberos Authentication Service | 4768, 4771 | Requests for a Kerberos login ticket (TGT) and failed pre-authentication | Password spraying; accounts that skip pre-auth |
| Kerberos Service Ticket Operations | 4769 | Requests for a ticket to use a service | Kerberoasting (many tickets for service accounts) |
| User Account Management | 4720, 4722, 4724, 4725, 4726, 4738 | Account created, enabled, password reset, disabled, deleted, changed | New accounts at odd hours; password resets by the wrong person |
| Security Group Management | 4728, 4732, 4756 | Someone added to a security group | A user added to Domain Admins or Administrators |
| Directory Service Changes | 5136 | A change to an Active Directory object | Edits to GPOs, group membership attributes, account flags |
| Process Creation | 4688 | Every new program that starts | What the attacker actually ran |

**Extra categories enabled next** (more telemetry is better in a lab)

```
auditpol /set /subcategory:"Distribution Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Application Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Other Account Management Events" /success:enable /failure:enable
auditpol /set /subcategory:"Other Account Logon Events" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Replication" /success:enable /failure:enable
auditpol /set /subcategory:"Detailed Directory Service Replication" /success:enable /failure:enable
auditpol /set /subcategory:"Group Membership" /success:enable
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
auditpol /set /subcategory:"Process Termination" /success:enable
auditpol /set /subcategory:"File Share" /success:enable /failure:enable
auditpol /set /subcategory:"Authorization Policy Change" /success:enable
```

| Subcategory | Event IDs | Why it matters |
|---|---|---|
| Distribution / Application Group Management | 4744–4759 range | Completes coverage of group changes |
| Other Account Management Events | 4793 | Password policy checks and related account calls |
| Other Account Logon Events | varies | Fills gaps in authentication coverage |
| Directory Service Replication (+ Detailed) | 4932, 4933, 4928–4931 | One DC replicating from another; linked to DCSync attacks |
| Group Membership | 4627 | Lists the groups a user holds at logon — instantly shows if a logon had admin rights |
| Other Logon/Logoff Events | 4778, 4779, 4800, 4801 | RDP reconnects, screen lock/unlock; session hijacking clues |
| Process Termination | 4689 | Pairs with 4688 to show how long a process ran |
| File Share | 5140 | Network share access; common in lateral movement over SMB |
| Authorization Policy Change | 4704, 4705 | Rights granted to accounts; privilege escalation |

**Categories deliberately left off**

- **Filtering Platform Connection:** logs every network connection — huge volume. Sysmon does this better.
- **Sensitive Privilege Use:** very noisy on a DC, mostly harmless.
- **File System, Registry, Kernel Object, SAM:** stay empty until SACLs are added to specific objects.

**Always verify — a command can fail quietly:**

```
auditpol /get /category:*
auditpol /get /subcategory:"Process Creation"
```

> **Lesson learned:** Process Creation initially showed "No Auditing" because the `auditpol` line for it never actually executed in an earlier batch. Always verify with `auditpol /get`, never assume a command ran just because it was typed.

---

## Step 2: Command-line and PowerShell logging

Out of the box, Event 4688 says only *that* a program started (e.g. `powershell.exe`), not what it was told to do. Two registry settings fix this.

**1. Add the full command line to process events**

```
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

Result: Event 4688 now contains a **Process Command Line** field, e.g. `powershell.exe -enc JABz...`.

**2. Log the real PowerShell code (script block logging)**

```
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
```

Result: PowerShell writes **Event 4104** to `Microsoft-Windows-PowerShell/Operational`. Attackers obfuscate scripts (Base64, string tricks); PowerShell logs the decoded code it actually runs.

```
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 5 | Format-List TimeCreated, Id, Message
```

**What a good 4688 event gives you (confirmed from the lab):**

| Field | Example | Why it matters |
|---|---|---|
| New Process Name | `C:\Windows\System32\whoami.exe` | The program that started |
| Process Command Line | `"C:\Windows\system32\whoami.exe" /all` | What it was told to do |
| Creator Process Name | `powershell.exe` | The parent — odd parent-child pairs are a top detection signal |
| Account Name | `Administrator` (`SOCLAB`) | Who ran it |
| Token Elevation Type | `TokenElevationTypeDefault (1)` | Whether it ran with full admin rights |

---

## Step 3: Make the Security log bigger

More auditing means more events. The default Security log (~20 MB) overwrites its oldest events once full — on a busy DC that can happen within hours.

```
wevtutil sl Security /ms:536870912
```

- `wevtutil sl` = *set log*.
- `/ms:536870912` sets the maximum size to 512 MB.
- Verify with `wevtutil gl Security`, look for `maxSize: 536870912`.

Two things to remember:
- Size limits control how far back you can investigate — real organizations forward logs to a SIEM so they survive.
- Attackers sometimes clear the log to hide. That's **Event 1102** (Security log cleared) — treat it as an alert, it should be rare.

---

## Step 4: Testing, with real events from the lab

**Test A — a failed logon on purpose**

```
net use \\DC01\IPC$ /user:SOCLAB\alice.smith WrongPassword
```

```
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625,4771,4776} -MaxEvents 5 | Select TimeCreated, Id, Message | Format-List
```

**What the lab showed:**

| Time | Event | Account | Sub status | Meaning |
|---|---|---|---|---|
| 5:07 PM | 4625 and 4776 | `alice.smith` | `0xC0000064` | User name does not exist — account hadn't been created yet |
| 4:16 AM and 4:15 AM | 4625 (twice) | `Administrator` | `0xC000006A` | Wrong password at the console — our own mistyped password |
| 3:52 AM | 4776 | `Administrator` | `0x0` | Successful credential check, first login |

After creating the users, the same test returned the true "wrong password" result (`0xC000006A`).

**How to read a 4625 event:**

| Field | What to ask |
|---|---|
| Logon Type | 2 = keyboard, 3 = network, 10 = Remote Desktop — is this type normal for this account? |
| Account For Which Logon Failed | Which account was targeted? One account or many? |
| Failure Reason / Status / Sub Status | Wrong password, no such user, locked, disabled? |
| Source Network Address / Workstation Name | Where did the attempt come from? |
| Caller Process Name | Which program asked for the logon? |
| Authentication Package | NTLM or Kerberos? |

**Test B — command-line logging**

```
whoami /all
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 3 | Select TimeCreated, Message | Format-List
```

Confirmed: `reg.exe`, `wevtutil.exe`, and `whoami.exe` all appeared with full command lines and parent process `powershell.exe`.

**Test C — confirm settings stuck**

```
auditpol /get /category:*
```

---

## Step 5: Sysmon, much richer logging

**What it is.** Sysmon (System Monitor) is a free Microsoft Sysinternals tool that runs as a service and writes detailed events to `Microsoft-Windows-Sysmon/Operational`. It records file hashes for every program, network connections tied to the process that made them, DLL loads, registry changes, file creation, and more.

**Why a config file.** By default Sysmon logs almost nothing. A community config (SwiftOnSecurity's `sysmonconfig-export.xml`) tells it what to record and what noise to ignore.

**1. Get the files into the VM.** `DC01` has no internet on the Host-Only network, so files are downloaded on the host PC and shared via a VirtualBox shared folder.

```
New-Item -ItemType Directory -Path C:\Tools\Sysmon
Copy-Item "\\VBoxSvr\LabShare\*" -Destination C:\Tools\Sysmon -Recurse
Expand-Archive C:\Tools\Sysmon\Sysmon.zip -DestinationPath C:\Tools\Sysmon -Force
```

**2. Install Sysmon with the config**

```
cd C:\Tools\Sysmon
.\Sysmon64.exe -accepteula -i sysmonconfig-export.xml
```

**3. Verify**

```
Get-Service Sysmon64
whoami
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 3 | Format-List TimeCreated, Id, Message
```

**Confirmed from the lab:** Sysmon installed and started cleanly (Event ID 4, version 15.22). Running `whoami` produced a full Event ID 1 record:

- **Image:** `C:\Windows\System32\whoami.exe`
- **ParentImage:** `powershell.exe`
- **User:** `SOCLAB\Administrator`
- **IntegrityLevel:** `High`
- **Hashes:** MD5, SHA256, IMPHASH all populated
- **CurrentDirectory:** `C:\Tools\Sysmon`

This is strictly more information than Event 4688 gives — the hash alone lets you check a binary against VirusTotal, something built-in auditing can't offer.

**Key Sysmon events**

| ID | Meaning | Look for |
|---|---|---|
| 1 | Process created | Hashes, ParentImage, CommandLine; odd parent-child pairs |
| 3 | Network connection | Which program connected to which IP/port |
| 7 | Image (DLL) loaded | Unsigned/unusual DLLs loaded by trusted programs |
| 8 | Remote thread created | Code injection into another process |
| 10 | Process accessed | Any program opening `lsass.exe` — the usual credential-dumping target |
| 11 | File created | Files dropped in temp/startup folders |
| 12 / 13 | Registry changes | Persistence via `Run` keys and services |
| 22 | DNS query | Which program looked up which domain |

**Important note on time:** Sysmon records `UtcTime` in UTC, while Event Viewer shows local time. Always convert before building a timeline — a mismatch here can make an investigation's sequence of events look wrong when it isn't.

---

## Step 6: Adding a second machine, and a real networking lesson

**The environment grew.** Alongside `DC01`, two more VMs were built: `soc-victim` (Windows Server 2016, used as a stand-in workstation) and `soc-siem` (a planned log-collection VM). `soc-victim` had Sysmon installed via the same shared-folder process used on `DC01`.

**The problem: two machines that looked connected but weren't.** Both `DC01` and `soc-victim` had static IPs in the `192.168.56.x` range set manually inside Windows (`DC01` at `.10`, `soc-victim` at `.12`), and DNS was pointed correctly. But pings between them failed outright (`Request timed out`, then later `Error due to lack of resources`), and `Resolve-DnsName soclab.local` failed from `soc-victim`.

**The real cause, found by checking VirtualBox itself rather than Windows:**

1. `DC01`'s network adapter was attached to **NAT**, not Host-Only, inside VirtualBox's VM settings. A static IP typed into Windows does not change which virtual network the adapter is actually plugged into underneath. `DC01` could ping itself (its own IP) but nothing else, since NAT is an isolated, per-VM network.
2. Separately, the **Host-Only network itself was on the wrong subnet.** VirtualBox's `VirtualBox Host-Only Ethernet Adapter` was configured with IPv4 `192.168.235.1`, not `192.168.56.1`. Both VMs' static IPs assumed a `192.168.56.0/24` network the actual virtual switch wasn't serving.

**The fix:**

- In VirtualBox Manager → **Network** (left sidebar) → **Host-only Networks** tab → selected the existing adapter → **Properties** → changed IPv4 Address to `192.168.56.1` (mask `255.255.255.0`).
- On both `DC01` and `soc-victim`: Settings → Network, set the relevant adapter's "Attached to" to **Host-only Adapter**, with the Name matching exactly on both machines.
- After reattaching and restarting both VMs: `ping 192.168.56.10` from `soc-victim` succeeded (0% loss), and `Resolve-DnsName soclab.local` returned the correct A record.

**The lesson:** a correct-looking IP address inside an operating system proves nothing about real Layer 2/3 connectivity in a virtualized environment. Two VMs can each have a plausible, matching address and still sit on entirely separate virtual networks. When a connectivity problem doesn't make sense from inside Windows (firewall rules fine, IPs fine, DNS fine), check the hypervisor's own network configuration next, not just the guest OS.

**Confirmed working state after the fix:**

```
ping 192.168.56.10           → 4 replies, 0% loss
Resolve-DnsName soclab.local → A record 192.168.56.10
ping DC01.soclab.local       → 4 replies, 0% loss
```

**Domain join, once networking was fixed:**

```
Add-Computer -DomainName "soclab.local" -Credential "SOCLAB\Administrator" -Restart
```

**Confirmed after reboot:**

```
(Get-WmiObject Win32_ComputerSystem).Domain   → soclab.local
hostname                                       → soc-victim
```

`soc-victim` is now a domain-joined member of `soclab.local`, reachable from and to `DC01`, with Sysmon already installed — the second machine needed for realistic attack simulations, where a request originates from a workstation and is observed on the domain controller, rather than everything happening locally on the DC.

---

## Exercise: password spraying, and a key lesson about Kerberos vs. NTLM

**The exercise.** Attempt a wrong password against several accounts to simulate password spraying — one attacker trying one common password against many accounts (as opposed to brute force, which tries many passwords against one account).

```
net use \\DC01\IPC$ /user:SOCLAB\carol.white WrongPass123!
```

**What actually happened, and why it matters.** The attempt correctly failed ("System error 1326"), but it produced **no 4625 event at all**. Searching broadly for any event mentioning the account found it instead as **Event ID 4771, Kerberos pre-authentication failed**, with **Failure Code `0x18`** (bad password).

**Why 4625 was silent.** A domain-joined Windows machine tries **Kerberos first**, not NTLM, when logging into a domain account. Kerberos failures are logged as **4768** (TGT request) or **4771** (pre-authentication failed), not 4625. The **4625** and **4776** events only appear for **NTLM** authentication, which Windows only falls back to in specific situations.

**The critical takeaway:** monitoring only 4625 will **miss most real password-guessing attempts** against a domain, because Kerberos is the default protocol and its failures use entirely different event IDs. A correct detection rule for password spraying or brute force against a domain must watch **4771 and 4768 together with 4625 and 4776**.

**How to search across both protocols at once:**

```
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625,4771,4776,4768; StartTime=(Get-Date).AddMinutes(-15)} |
  Sort-Object TimeCreated |
  Select TimeCreated, Id, @{n='Account';e={ if ($_.Id -in 4625,4776) {$_.Properties[5].Value} else {$_.Properties[0].Value} }}
```

**Reading a 4771, field by field:**

| Field | What it tells you |
|---|---|
| Account Name | The account targeted |
| Service Name | Usually `krbtgt/<DOMAIN>` for an initial logon attempt |
| Client Address | Where the request came from |
| Failure Code | The actual reason (`0x18` = bad password, `0x6` = no such user, `0x12` = disabled/locked/expired) |
| Pre-Authentication Type | `2` is normal encrypted-timestamp type; a missing/different type can itself be suspicious (AS-REP roasting) |

**Confirmed result from the lab.** Running the same wrong password against all three accounts in quick succession produced exactly the spray signature:

| TimeCreated | Id | Account |
|---|---|---|
| 1:04:52 AM | 4771 | alice.smith |
| 1:04:52 AM | 4771 | bob.jones |
| 1:04:52 AM | 4771 | carol.white |

All three accounts failed with **Failure Code `0x18`** at the **same second**, from the **same source**. This is the pattern that separates password spraying from normal failed logons:

- **Same timestamp (or a tight window of seconds):** one person or script worked through a list quickly.
- **Multiple different accounts:** several tried once each, rather than one account retried.
- **Same failure code across all of them:** all failing for the same reason, not a mix that would suggest something else.

**A real detection rule** would count distinct failed accounts (4771/4625) from the same source within a short window (e.g. 5+ distinct accounts in 60 seconds) and alert when crossed. A single account failing many times in a row is brute force instead, and needs a different rule.

**Why sequencing mattered:** an earlier attempt with `net use ... /delete` run first, in a loop, didn't produce the expected events, while a direct, single attempt did. When a test doesn't produce the expected event, don't assume logging is broken — search broadly across every plausible event ID first, since the activity is very often logged correctly under an ID you weren't expecting.

---

## Exercise: Kerberoasting against `svc.backup`

**The attack, step by step, across two machines:**

| Step | Machine | Command | Purpose |
|---|---|---|---|
| 1 | `DC01` | `Get-ADUser -Identity svc.backup -Properties ServicePrincipalName` | Confirmed `svc.backup` had no SPN yet |
| 2 | `DC01` | `setspn -A MSSQLSvc/soc-victim.soclab.local:1433 svc.backup` | Registered a fake SPN, simulating a real admin mistake |
| 3 | `soc-victim` | `Add-Type -AssemblyName System.IdentityModel` then `New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/soc-victim.soclab.local:1433"` | Requested a service ticket for that SPN, the same primitive tools like Rubeus wrap |
| 4 | `DC01` | `Get-WinEvent` for Event 4769 | Found the resulting ticket request and read its encryption type |

**A real blocker worth remembering: the attack must come from a domain-authenticated session.** The first attempt failed with *"The NetworkCredentials provided were unable to create a Kerberos credential"* because the session was logged in as `soc-victim\administrator`, a **local** account with zero cached Kerberos tickets (`klist` showed `Cached Tickets: (0)`). After logging in as `SOCLAB\Administrator` instead, `klist` showed a full ticket set including the TGT, and the ticket request succeeded immediately.

**This is realistic, not a lab artifact.** Kerberoasting is almost always performed *after* an attacker has already compromised some ordinary domain account. It exploits the fact that **any authenticated domain user**, not just an admin, can request a service ticket for **any SPN in the entire domain**.

**The result, confirmed from `DC01`:**

```
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4769; StartTime=(Get-Date).AddMinutes(-10)} |
  Where-Object { $_.Message -like "*svc.backup*" } |
  Select -First 1 -ExpandProperty Message
```

Returned a 4769 event for `svc.backup` with:

```
Ticket Options:         0x40810000
Ticket Encryption Type: 0x17
Failure Code:           0x0
```

- **`0x17` = RC4-HMAC.** RC4 tickets are encrypted with a key derived directly from the account's NTLM password hash. An attacker who captures this ticket can take it offline and try to crack `svc.backup`'s password with no further contact with the domain — no lockout policy applies, no further suspicious traffic is generated.
- **`Failure Code: 0x0`** confirms the request succeeded — a normal, successful ticket issuance, exactly as it would look for a legitimate SQL Server login, which is what makes Kerberoasting so hard to tell apart from ordinary traffic by content alone.
- Had this come back `0x12` (AES256), the ticket would be far harder to crack offline.

**What a real detection rule looks for:**

- **Volume:** one account requesting tickets for **many different SPNs** in a short window.
- **Encryption type specifically requested as RC4** when the requesting account's own TGT was AES, a downgrade some Kerberoasting tools cause.
- **The target account itself:** service accounts that never log in interactively and never change their password are the accounts worth watching most closely.
- **Exclude noise:** `krbtgt` and computer accounts (`$`-suffixed) requesting tickets is normal background activity.

**Closing this exercise: why RC4 is the real finding, without needing to crack a password.**

The lab stopped short of taking the captured ticket offline and running a password-cracking tool against it. That step was skipped deliberately — it crosses from "demonstrate and detect a real weakness using your own log evidence" into "operate a credential-attack tool end to end," and that line is worth holding even in an isolated lab, since the skill and the tooling are identical to what would be used against a real target.

**The finding stands on its own without that step:**

- **RC4-HMAC's session key is derived directly from the account's NTLM password hash**, with no salt and no iteration.
- **Once an attacker has the ticket, no further contact with the domain is needed** — the guessing happens entirely offline.
- **Modern GPUs make this fast**, which is exactly why `hashcat` ships a dedicated mode (`13100`) for this ticket format.
- **AES256 tickets (`0x12`) don't have this problem**, since AES's key is derived through a proper, iterated, salted process.

**The single most useful fact from this exercise:** *this domain issued an RC4-encrypted service ticket for a user account, when it could have issued AES256 instead.* That's a configuration and account-hygiene problem, fully provable from the real `4769` event, and fully fixable without ever needing to know the account's actual password.

**How this would be fixed in a real environment:**

- Set `msDS-SupportedEncryptionTypes` on service accounts to only allow AES (128/256).
- Restrict allowed Kerberos encryption types domain-wide via Group Policy once legacy dependencies are retired.
- Rotate service account passwords to long, random values, ideally via a **managed service account (gMSA)**, which rotates automatically and resists Kerberoasting far better than a human-set password, even under AES.

**Exercise status: complete.** SPN set → ticket requested from a second, domain-joined machine → RC4 encryption confirmed via the real Security log on `DC01` → remediation path identified.

---

## Event ID cheat sheet

Log is **Security** unless noted.

| ID | Meaning | Look for |
|---|---|---|
| 4624 | Successful logon | Logon Type, source address, time of day |
| 4625 | Failed logon | Bursts of failures; the Sub Status code |
| 4634 | Logoff | Session length |
| 4648 | Logon using explicit credentials | One account using another's credentials (`runas`, lateral movement) |
| 4672 | Special privileges assigned to a logon | Admin rights given to an unexpected account |
| 4768 | Kerberos TGT requested | Pre-authentication type 0; unusual accounts/sources |
| 4769 | Kerberos service ticket requested | Encryption type `0x17` (RC4) for a service account |
| 4771 | Kerberos pre-authentication failed | Failure code `0x18` across many accounts |
| 4776 | NTLM credential validation | Many accounts from one workstation |
| 4720 | User account created | New accounts at odd hours or by non-admins |
| 4724 | Password reset attempted | Resets of admin or service accounts |
| 4725 / 4726 | Account disabled / deleted | Defenders' accounts being disabled |
| 4728 / 4732 / 4756 | Member added to a group | Additions to Domain Admins or Administrators |
| 4738 | User account changed | Flags changed (e.g. "password never expires") |
| 4740 | Account locked out | Lockouts signaling password guessing |
| 4688 | New process created | Suspicious command lines and parent-child pairs |
| 4689 | Process ended | Short-lived processes |
| 5136 | Directory object modified | Changes to GPOs, group membership, ACLs |
| 5140 | Network share accessed | `C$`, `ADMIN$`, `IPC$` access from workstations |
| 4662 | Operation on an AD object | DCSync (needs an extra audit rule) |
| 4104 | PowerShell script block (`Microsoft-Windows-PowerShell/Operational`) | Encoded/obfuscated or download-and-run code |
| 1102 | Security log cleared | Any occurrence |
| 7045 | New service installed (log `System`) | Unknown services on a DC |

**Logon Types (field inside 4624/4625)**

| Type | Meaning | Notes |
|---|---|---|
| 2 | Interactive | At the keyboard/console |
| 3 | Network | Shares, SMB, most remote activity |
| 4 | Batch | Scheduled tasks |
| 5 | Service | A service starting under an account |
| 7 | Unlock | Workstation unlocked |
| 8 | NetworkCleartext | Password sent in clear text — investigate |
| 9 | NewCredentials | `runas /netonly`; common in attacker tooling |
| 10 | RemoteInteractive | Remote Desktop |
| 11 | CachedInteractive | Logon with cached credentials |

---

## What to look for: analyst hints and attack patterns

**Five questions to ask of every event**

1. **Who?** Which account, person/service/machine (names ending in `$`)?
2. **From where?** Source address/workstation — expected for that account?
3. **When?** Is the time normal for that account?
4. **What?** Which program, command line, group, share?
5. **Then what?** One event is a dot — look at what happened in the next minutes.

**Attack patterns and their trails**

| Attack | Events | Telltale signs |
|---|---|---|
| Brute force | 4625, 4624 | Many failures for one account, one source, short time, then success |
| Password spraying | 4625, 4771, 4776 | One/two attempts against many accounts, one source, mostly `0xC000006A` or Kerberos `0x18` |
| Username enumeration | 4625, 4768 | Many different names failing with `0xC0000064` or Kerberos `0x6` |
| Kerberoasting | 4769 | One user requesting tickets for many service accounts, encryption type `0x17` |
| AS-REP roasting | 4768 | Pre-authentication type `0`; check "no pre-auth" flag via 4738 |
| New account for persistence | 4720, 4728, 4732 | New user followed quickly by group addition, odd hours |
| Privilege escalation | 4728, 4732, 4756, 4672 | A user added to Domain Admins |
| Lateral movement | 4624 (Type 3), 4648, 5140 | Workstation-to-workstation logons, NTLM instead of Kerberos |
| DCSync | 4662 | A non-DC account requesting replication rights |
| Suspicious commands | 4688, 4104 | `powershell -enc`, `-nop -w hidden`, `IEX`, `DownloadString`, `certutil -urlcache` |
| Covering tracks | 1102 | The Security log was cleared |
| Odd parent-child pairs | 4688 | Office app starting `powershell.exe`; a web server starting a shell |

**Habits that make you a better analyst**

- **Learn normal first.** Mistyped passwords create real 4625 events — every environment has noise; the skill is spotting what differs.
- **Group and count.** Ten failures from one source in one minute means more than ten scattered over a week.
- **Read the codes, not just the message.** Sub Status separates "no such user" from "wrong password" — the difference between enumeration and guessing.
- **Follow the logon ID.** The same Logon ID ties a logon (4624) to everything that session did (4688).
- **Check the clock.** Kerberos fails when clocks drift more than 5 minutes apart (`0x25`), and mismatched time zones make timelines confusing.

---

## Status and sub-status codes cheat sheet

**Failed logon codes (4625, 4776)**

| Code | Meaning | What it suggests |
|---|---|---|
| `0xC000006D` | Logon failure (general) | Read the Sub Status for the real reason |
| `0xC0000064` | User name does not exist | Enumeration, a typo, or a deleted account |
| `0xC000006A` | Correct user, wrong password | Guessing, spraying, or a mistyped password |
| `0xC0000234` | Account locked out | Too many failures |
| `0xC0000072` | Account disabled | Someone using an old/disabled account |
| `0xC000006F` | Outside allowed logon hours | Policy violation |
| `0xC0000070` | Workstation restriction | Account used from a disallowed machine |
| `0xC0000071` | Password expired | Often harmless; check context |
| `0xC0000193` | Account expired | Old account in use |
| `0xC000015B` | Logon type not granted | Account lacks the right for that logon type |

**Kerberos failure codes (4768, 4771)**

| Code | Meaning |
|---|---|
| `0x6` | Client not found in the database (no such user) |
| `0x12` | Account disabled, locked out, or expired |
| `0x17` | Password expired |
| `0x18` | Pre-authentication failed (wrong password) |
| `0x25` | Clock skew too great |

**Ticket encryption types (4768, 4769)**

| Code | Meaning | Why it matters |
|---|---|---|
| `0x11` | AES128 | Modern |
| `0x12` | AES256 | Modern; expected on current systems |
| `0x17` | RC4-HMAC | Weak, easy to crack offline — the Kerberoasting signal |

---

## Lessons learned in this lab

1. **Same failure, different cause.** The first test used `alice.smith` before the account existed, giving `0xC0000064` (no such user). After creating her, the test gave `0xC000006A` (wrong password). Detection rules depend on telling these apart.
2. **A command that didn't run looks like a setting that failed.** Process Creation showed "No Auditing" because its `auditpol` line never executed. Always verify with `auditpol /get`.
3. **Your own actions create events.** Mistyped passwords for `Administrator` were caught as real 4625 events — expect and recognize your own noise.
4. **Auditing proves itself.** Each setting has a test: failed logon for 4625/4776, `whoami` for 4688, `auditpol /get` for the policies.
5. **Snapshots protect the lab.** Take one after each milestone so a mistake never costs more than one step.
6. **A correct-looking config inside the guest OS doesn't guarantee the layer below it is actually connected.** The VirtualBox networking issue is the clearest example — IPs, DNS, and firewall rules all looked right, and the real fault was the hypervisor's own virtual switch configuration.
7. **A tool classified as a credential-attack hacktool shouldn't be run end-to-end, even in an isolated lab.** The Kerberoasting exercise was closed out by confirming the weak encryption type directly from the real Security log event, rather than by operating offline-cracking tooling — the vulnerability is fully provable from that evidence alone.

---

## Next steps: Sysmon and beyond

- [x] Install Sysmon with a community config (SwiftOnSecurity) — done, verified against real Event ID 1 output
- [x] Verify the extra audit categories with `auditpol /get /category:*`
- [ ] Add an audit rule on the domain root so DCSync produces Event 4662 (without it, that event never appears)
- [x] Give `svc.backup` an SPN and practice a Kerberoasting test, then find the 4769 event with encryption type `0x17`
- [x] Add a Windows client VM joined to `soclab.local`, on the same Host-Only network
- [ ] Forward logs to a collector (Wazuh, in progress as `soc-siem`), so detections don't rely on manual `Get-WinEvent` queries
- [ ] Convert the password-spray and Kerberoasting findings into formal Sigma detection rules
- [ ] Add an attacker-perspective VM (likely Kali) for a less one-sided simulation

**Remember:** this lab is isolated on purpose. Practice attacks only on your own VMs, on your own isolated network.
