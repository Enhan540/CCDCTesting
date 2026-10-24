# CCDC Scripts

This repository publishes Windows PowerShell scripts to use and test on Windows machines during CCDC competitions. It includes current firewall scripts plus older, previous, and untested versions kept for reference.

## Repository layout

- `scripts/current/ad-default-firewalls/` — current configurable AD firewall revisions.
- `scripts/current/dc-firewalls-barebones/` — current automatic-subnet barebones revisions.
- `archive/older-scripts/` — earlier general CCDC scripts.
- `archive/previous-versions/` — previous AD firewall versions.
- `archive/untested/` — scripts not yet validated for regular use.

## Barebones scripts

The barebones script automatically detects the machine's primary IPv4 subnet, creates or reuses a minimal AD firewall policy, verifies the rules, disables other local inbound rules, and creates before/after backups. Version 2.5 runs without script prompts. Its TXT reports include enabled effective rules and their policy source.

PowerShell — download and run:

```powershell
$u='https://raw.githubusercontent.com/Enhan540/CCDCTesting/main/scripts/current/dc-firewalls-barebones/dc-firewalls-barebones-v2.5.ps1'; Invoke-WebRequest $u -OutFile .\dc-firewalls-barebones-v2.5.ps1; PowerShell.exe -ExecutionPolicy Bypass -File .\dc-firewalls-barebones-v2.5.ps1
```

cmd — download and run:

```cmd
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest 'https://raw.githubusercontent.com/Enhan540/CCDCTesting/main/scripts/current/dc-firewalls-barebones/dc-firewalls-barebones-v2.5.ps1' -OutFile '.\dc-firewalls-barebones-v2.5.ps1'; & '.\dc-firewalls-barebones-v2.5.ps1'"
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

Run the commands from Windows PowerShell or cmd. The scripts request elevation when needed. Keep console or out-of-band access; barebones v2.5 writes its original backup before changing the firewall and then disables other local inbound rules automatically after verification.

The configurable script requires `-ClientNetworks`. The barebones script requires no parameters and uses the primary subnet detected from the machine's default IPv4 route.

## Included files

- `scripts/current/ad-default-firewalls/` — `ad-default-firewalls-v11.ps1` through `ad-default-firewalls-v11.3.ps1`.
- `scripts/current/dc-firewalls-barebones/` — `dc-firewalls-barebones-v2.ps1` through `dc-firewalls-barebones-v2.5.ps1`.
- `archive/older-scripts/`, `archive/previous-versions/`, and `archive/untested/` — retained reference material.

The `.1` versions change the TXT report layout only. They use aligned fixed-width tables, sort rules by local port, and shorten displayed rule names; they do not intentionally change firewall behavior.
