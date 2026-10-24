# CCDC Scripts

This repository publishes Windows PowerShell scripts to use and test on Windows machines during CCDC competitions. It includes current firewall scripts plus older, previous, and untested versions kept for reference.

## Repository layout

- `scripts/current/ad-default-firewalls/` — current configurable AD firewall revisions.
- `scripts/current/dc-firewalls-barebones/` — current automatic-subnet barebones revisions.
- `archive/older-scripts/` — earlier general CCDC scripts.
- `archive/previous-versions/` — previous AD firewall versions.
- `archive/untested/` — scripts not yet validated for regular use.

## Barebones scripts

The barebones script automatically detects the machine's primary IPv4 subnet when `-ClientNetworks` is omitted. It creates or reuses a minimal AD firewall policy, verifies the rules, disables other local inbound rules, and creates before/after backups. Version 2.8 accepts `-ClientNetworks` with comma-separated IPv4 addresses or scopes. Adding `-Modify` updates only currently enabled local barebones rules and requires `-ClientNetworks`.

PowerShell — download and run:

```powershell
$u='https://raw.githubusercontent.com/Enhan540/CCDCTesting/main/scripts/current/dc-firewalls-barebones/dc-firewalls-barebones-v2.8.ps1'; Invoke-WebRequest $u -OutFile .\dc-firewalls-barebones-v2.8.ps1; PowerShell.exe -ExecutionPolicy Bypass -File .\dc-firewalls-barebones-v2.8.ps1
```

cmd — download and run:

```cmd
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest 'https://raw.githubusercontent.com/Enhan540/CCDCTesting/main/scripts/current/dc-firewalls-barebones/dc-firewalls-barebones-v2.8.ps1' -OutFile '.\dc-firewalls-barebones-v2.8.ps1'; & '.\dc-firewalls-barebones-v2.8.ps1'"
```

To run the full workflow with explicit addresses instead of the detected subnet:

```powershell
PowerShell.exe -ExecutionPolicy Bypass -File .\dc-firewalls-barebones-v2.8.ps1 -ClientNetworks 192.168.5.10,192.168.5.11
```

To modify only the existing enabled barebones rules:

```powershell
PowerShell.exe -ExecutionPolicy Bypass -File .\dc-firewalls-barebones-v2.8.ps1 -ClientNetworks 192.168.5.10,192.168.5.11 -Modify
```

## Configurable AD firewall scripts

The configurable script creates scoped AD service rules using supplied client networks, supports selected optional services and cleanup, and creates firewall backups. Version 11.3 includes aligned, port-sorted TXT reports and automatically requests Administrator elevation when needed.

PowerShell — download and run:

```powershell
$u='https://raw.githubusercontent.com/Enhan540/CCDCTesting/main/scripts/current/ad-default-firewalls/ad-default-firewalls-v11.3.ps1'; Invoke-WebRequest $u -OutFile .\ad-default-firewalls-v11.3.ps1; PowerShell.exe -ExecutionPolicy Bypass -File .\ad-default-firewalls-v11.3.ps1 -ClientNetworks 192.168.5.0/24
```

cmd — download and run:

```cmd
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest 'https://raw.githubusercontent.com/Enhan540/CCDCTesting/main/scripts/current/ad-default-firewalls/ad-default-firewalls-v11.3.ps1' -OutFile '.\ad-default-firewalls-v11.3.ps1'; & '.\ad-default-firewalls-v11.3.ps1' -ClientNetworks '192.168.5.0/24'"
```

## Quick guide

Run the commands from Windows PowerShell or cmd. The scripts request elevation when needed. Keep console or out-of-band access; barebones v2.8 writes its original backup before changing the firewall and then disables other local inbound rules automatically after verification.

The configurable script requires `-ClientNetworks`. The barebones script requires no parameters for automatic subnet detection, or accepts `-ClientNetworks` for explicit addresses/scopes. Add `-Modify` to update only enabled local barebones rules; this mode requires `-ClientNetworks`.

## Included files

- `scripts/current/ad-default-firewalls/` — `ad-default-firewalls-v11.ps1` through `ad-default-firewalls-v11.3.ps1`.
- `scripts/current/dc-firewalls-barebones/` — current barebones revision `dc-firewalls-barebones-v2.8.ps1`; earlier revisions remain in this folder.
- `archive/older-scripts/`, `archive/previous-versions/`, and `archive/untested/` — retained reference material.

The `.1` versions change the TXT report layout only. They use aligned fixed-width tables, sort rules by local port, and shorten displayed rule names; they do not intentionally change firewall behavior.
