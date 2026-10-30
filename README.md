# CCDC Scripts

This repository publishes Windows PowerShell scripts to use and test on Windows machines during CCDC competitions. It includes current firewall scripts plus older, previous, and untested versions kept for reference.

## Repository layout

- `scripts/current/ad-default-firewalls/` — current configurable AD firewall revisions.
- `scripts/current/dc-firewalls-barebones/` — current automatic-subnet barebones revisions.
- `archive/older-scripts/` — earlier general CCDC scripts.
- `archive/previous-versions/` — previous AD firewall versions.
- `archive/untested/` — scripts not yet validated for regular use.

## Barebones scripts

The barebones script detects whether the machine is a Domain Controller or Client. Version 3.3.1 enables all firewall profiles, sets default inbound to Block and outbound to Allow, verifies those settings, then runs the appropriate workflow. All TXT firewall reports include only rules whose Enabled state is True.

### Barebones parameters

- No parameters: set and verify the firewall baseline, then detect the Windows role. DCs run the full setup using `LocalSubnet4`; other roles use the Client workflow.
- `-ClientNetworks`: optionally supply one or more IPv4 addresses or scopes, comma-separated. In a full DC run, these replace the default `LocalSubnet4` scope.
- `-Modify`: update only the remote-address scope on existing enabled local barebones rules. Must be used with `-ClientNetworks` on a detected DC; it skips the full setup and cleanup workflow and saves before and after `.wfw` backups, plus a `.txt` before-to-after report in `C:\CCDC\FirewallBackups\`.
- `-Role DC` or `-Role Client`: optionally state the expected workflow. The script checks it against the detected machine type and stops if they do not match. When omitted, the role is detected automatically.
- `-Export`: write a timestamped TXT report of all enabled effective firewall rules and exit without changing firewall settings. It cannot be combined with `-Modify`, `-Role`, or `-ClientNetworks`.

DomainRole values 4 and 5 use the same DC workflow. The script first enables Domain, Private, and Public profiles, sets default inbound to Block and outbound to Allow, verifies those settings, and creates the initial `.wfw` and enabled-rule TXT backup. It then detects the role, creates and verifies the AD rules on a DC, disables other enabled local inbound rules, verifies the resulting state, and takes a fresh final `.wfw` and enabled-rule TXT export. With no `-ClientNetworks`, the AD rules use `LocalSubnet4`; explicit `-ClientNetworks` values remain available for other subnets. Values 0–3 use the Client workflow: verify the baseline, make no rule changes, then take the final export.

Backup and report filenames include the computer name and `HHmm-MMddyyyy` timestamp. If a name already exists from another run during the same minute, a numeric suffix is added.

PowerShell — download and run:

```powershell
$u='https://raw.githubusercontent.com/Enhan540/CCDCTesting/main/scripts/current/dc-firewalls-barebones/dc-firewalls-barebones-v3.3.1.ps1'; Invoke-WebRequest $u -OutFile .\dc-firewalls-barebones-v3.3.1.ps1; PowerShell.exe -ExecutionPolicy Bypass -File .\dc-firewalls-barebones-v3.3.1.ps1
```

Full setup with explicit addresses instead of the detected subnet:

```powershell
PowerShell.exe -ExecutionPolicy Bypass -File .\dc-firewalls-barebones-v3.3.1.ps1 -ClientNetworks 192.168.5.10,192.168.5.11
```

Modify existing enabled barebones rules and save before/after backups:

```powershell
PowerShell.exe -ExecutionPolicy Bypass -File .\dc-firewalls-barebones-v3.3.1.ps1 -ClientNetworks 192.168.5.10,192.168.5.11 -Modify
```

Export only, without changing firewall settings:

```powershell
PowerShell.exe -ExecutionPolicy Bypass -File .\dc-firewalls-barebones-v3.3.1.ps1 -Export
```

### Restoring Firewall from Backup
To restore firewall settings, use a `.wfw` file from `C:\CCDC\FirewallBackups\`. A full DC run and `-Modify` each create before and after backups; the Client workflow creates an original backup. For example:
```powershell
netsh advfirewall import 'C:\CCDC\FirewallBackups\firewall-after-DC02-1435-10292026.wfw'
```

## Configurable AD firewall scripts

The configurable script creates scoped AD service rules using supplied client networks, supports selected optional services and cleanup, and creates firewall backups. Version 11.3 includes aligned, port-sorted TXT reports and automatically requests Administrator elevation when needed.

PowerShell — download and run:

```powershell
$u='https://raw.githubusercontent.com/Enhan540/CCDCTesting/main/scripts/current/ad-default-firewalls/ad-default-firewalls-v11.3.ps1'; Invoke-WebRequest $u -OutFile .\ad-default-firewalls-v11.3.ps1; PowerShell.exe -ExecutionPolicy Bypass -File .\ad-default-firewalls-v11.3.ps1 -ClientNetworks 192.168.5.0/24
```

## Quick guide

Run the commands in Windows PowerShell. The scripts request elevation when needed. Keep console or out-of-band access; the DC workflow disables other local inbound rules only after all baseline rules pass verification.

The configurable script requires `-ClientNetworks`. The barebones script detects the machine role automatically. Use `-Export` for a report-only run, `-ClientNetworks` to provide remote scopes, or `-Modify` to update existing enabled barebones rules on a DC.

## Included files

- `scripts/current/ad-default-firewalls/` — `ad-default-firewalls-v11.ps1` through `ad-default-firewalls-v11.3.ps1`.
- `scripts/current/dc-firewalls-barebones/` — current barebones revision `dc-firewalls-barebones-v3.3.1.ps1`; earlier revisions remain in this folder.
- `archive/older-scripts/`, `archive/previous-versions/`, and `archive/untested/` — retained reference material.

The `.1` versions change the TXT report layout only. They use aligned fixed-width tables, sort rules by local port, and shorten displayed rule names; they do not intentionally change firewall behavior.
