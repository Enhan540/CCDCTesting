# CCDC Scripts

This repository publishes Windows PowerShell firewall scripts for use and testing on Windows machines during CCDC competitions. It includes a configurable AD firewall script, a barebones automatically detected-subnet script, report-formatting revisions, and older or untested versions for reference.

## Barebones scripts

The barebones script automatically detects the machine's primary IPv4 subnet, creates or reuses a minimal AD firewall policy, verifies the rules, and creates before/after backups. Version 2.4 asks for confirmation before disabling other local inbound rules. Its TXT reports include enabled effective rules and their policy source.

PowerShell — download and run:

```powershell
$u='https://raw.githubusercontent.com/Enhan540/CCDCTesting/main/dc-firewalls-barebones-v2.4.ps1'; Invoke-WebRequest $u -OutFile .\dc-firewalls-barebones-v2.4.ps1; PowerShell.exe -ExecutionPolicy Bypass -File .\dc-firewalls-barebones-v2.4.ps1
```

cmd — download and run:

```cmd
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest 'https://raw.githubusercontent.com/Enhan540/CCDCTesting/main/dc-firewalls-barebones-v2.4.ps1' -OutFile '.\dc-firewalls-barebones-v2.4.ps1'; & '.\dc-firewalls-barebones-v2.4.ps1'"
```

## Configurable AD firewall scripts

The configurable script creates scoped AD service rules using supplied client networks, supports selected optional services and cleanup, and creates firewall backups. Version 11.3 includes aligned, port-sorted TXT reports and automatically requests Administrator elevation when needed.

PowerShell — download and run:

```powershell
$u='https://raw.githubusercontent.com/Enhan540/CCDCTesting/main/ad-default-firewalls-v11.3.ps1'; Invoke-WebRequest $u -OutFile .\ad-default-firewalls-v11.3.ps1; PowerShell.exe -ExecutionPolicy Bypass -File .\ad-default-firewalls-v11.3.ps1 -ClientNetworks 192.168.5.0/24
```

cmd — download and run:

```cmd
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest 'https://raw.githubusercontent.com/Enhan540/CCDCTesting/main/ad-default-firewalls-v11.3.ps1' -OutFile '.\ad-default-firewalls-v11.3.ps1'; & '.\ad-default-firewalls-v11.3.ps1' -ClientNetworks '192.168.5.0/24'"
```

## Quick guide

Run the commands from Windows PowerShell or cmd. The scripts request elevation when needed. Keep console or out-of-band access; barebones v2.4 writes its original backup before changing the firewall and prompts before disabling other inbound rules.

The configurable script requires `-ClientNetworks`. The barebones script requires no parameters and uses the primary subnet detected from the machine's default IPv4 route.

## Included files

- `ad-default-firewalls-v11.ps1` through `ad-default-firewalls-v11.3.ps1` — configurable AD firewall revisions; later versions include improved reports, self-elevation, and PowerShell 5.1 formatting fixes.
- `dc-firewalls-barebones-v2.ps1` through `dc-firewalls-barebones-v2.4.ps1` — minimal automatically detected-subnet revisions.
- `older scripts` — earlier versions retained for reference.
- `prev versions` — previous project versions.
- `untested` — scripts not yet validated for regular use.

The `.1` versions change the TXT report layout only. They use aligned fixed-width tables, sort rules by local port, and shorten displayed rule names; they do not intentionally change firewall behavior.
