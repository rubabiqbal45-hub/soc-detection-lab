# Centralized Detection with Splunk: From Design Decision to Live Alert

## Why Splunk, and why it's running on the host, not in a VM

The original plan was a three-VM lab: a domain controller, an attack-origin workstation, and a dedicated Ubuntu VM running Wazuh as the SIEM. That ran into a real hardware constraint — Wazuh's indexer (OpenSearch under the hood) needed more memory than a 16GB laptop could spare once split three ways across VMs, and on an unsupported host configuration its footprint grew to roughly 11GB on its own. Trimming the VM's RAM down instead just stalled the indexer on startup.

Rather than keep fighting a resource-constrained VM, I made a deliberate call: delete that VM (reclaiming ~42GB of disk) and install **Splunk Enterprise directly on the host machine** instead. This gets the same architectural outcome — a centralized log collector independent of the domain controller and workstation — without a third guest OS competing for RAM. It's also arguably a more realistic pattern: plenty of small environments run their log collector on dedicated hardware rather than virtualized alongside everything else.

**Install notes, since none of this went smoothly on the first try:**
- The Windows installer silently hung during driver installation. Fixed by forcing `DoNotInstallDrivers=1` during setup.
- Hit an **Error 1310** partway through install — turned out to be 360 Total Security's filter driver interfering with file writes. Paused the antivirus for the install and whitelisted the install directory afterward.
- After install, the Security log showed zero events even with the forwarder apparently running — the forwarder service needs to run as **LocalSystem**, not a lesser account, to have permission to read the Security event log at all.
- No `inputs.conf` was generated from the MSI's install-time properties, so it had to be written manually to actually tell the forwarder which logs to watch.

## Architecture

```
DC01 (192.168.56.10) ──┐
                        ├──> Universal Forwarder ──> 192.168.56.1:9997 ──> Splunk Enterprise (host, localhost:8000)
soc-victim (192.168.56.12) ┘
```

The host sits on the same VirtualBox Host-Only network as both VMs (at `192.168.56.1`, the virtual adapter VirtualBox creates automatically), so no NAT or internet access was needed to wire this up — consistent with the rest of the lab staying air-gapped.

## The detection: catching my own Kerberoasting attempt live

Reusing the exact attack from the original exercise — requesting a Kerberos service ticket for `svc.backup`'s registered SPN from a non-admin domain session on `soc-victim`:

```powershell
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/soc-victim.soclab.local:1433"
```

This produced a real Event 4769 on `DC01`, forwarded and indexed into Splunk within seconds:

```
Account Name:    Administrator@SOCLAB.LOCAL
Service Name:    svc.backup
Ticket Options:  0x40810000
Ticket Encryption Type: 0x17
Failure Code:    0x0
```

`0x17` is RC4-HMAC — the same weak, unsalted encryption type identified in the original manual exercise, now caught through an actual SIEM pipeline instead of a one-off `Get-WinEvent` query.

### Detection search

```spl
index=* EventCode=4769 Service_Name=svc.backup Ticket_Encryption_Type=0x17
```

Splunk's automatic key-value field extraction turns the raw Windows event text (`Service Name:`, `Ticket Encryption Type:`) directly into searchable fields (`Service_Name`, `Ticket_Encryption_Type`), so the search can target the exact ticket characteristics rather than grepping raw text.

### Saved as a working alert

Converted the search into a scheduled Splunk alert:

| Setting | Value |
|---|---|
| Trigger condition | Number of results > 0 |
| Schedule | Cron, every 5 minutes (`*/5 * * * *`) |
| Search window | Last 15 minutes |
| Action | Add to Triggered Alerts |

Re-ran the Kerberoasting ticket request and confirmed the alert fired on its next scheduled check, with the real event visible in Triggered Alerts → View Results.

*(Screenshots: alert definition, trigger history, and the fired event's raw detail — see `screenshots/` in this repo.)*

**Takeaway:** the earlier finding (RC4 encryption type as the signal, not the crack) didn't change — what changed is that it's now operationalized. The difference between "I found this once by querying logs manually" and "I have a scheduled detection that fires automatically" is exactly the gap between a one-off finding and production-style detection engineering.

## Next

- Rebuild the password-spray detection (multiple distinct 4771 failures, same source, short window) as a Splunk search and alert, following the same pattern
- Tune alert thresholds to reduce false-positive risk (e.g., legitimate RC4 usage by legacy services shouldn't alone trigger — revisit the original finding's takeaway about pairing RC4 with SPN-request volume)
- Build a dashboard surfacing both detections together
