# CCDC Firewall Scripts

These scripts configure inbound Windows Firewall rules for an Active Directory domain controller during CCDC competitions.

## Scripts

- `ad-default-firewalls-v11.ps1` — Configures scoped AD firewall rules, supports optional management services and cleanup, and creates backups. Its TXT reports use the original tab-separated format.
- `ad-default-firewalls-v11.1.ps1` — Same firewall behavior as v11, but its before/after TXT reports use aligned fixed-width tables sorted by local port, with displayed rule names limited to 15 characters.
- `ad-default-firewalls-v11.2.ps1` — Same behavior and report format as v11.1, but automatically relaunches itself with Administrator privileges when needed.
- `dc-firewalls-barebones-v2.ps1` — Automatically detects the local subnet, creates a minimal AD rule set, verifies the rules, disables other local inbound rules, and creates backups.
- `dc-firewalls-barebones-v2.1.ps1` — Same firewall behavior as barebones v2, but with cleaner aligned, port-sorted TXT reports and shortened displayed rule names.
- `dc-firewalls-barebones-v2.2.ps1` — Same behavior and report format as v2.1, but automatically relaunches itself with Administrator privileges when needed.

Run these only from an elevated Administrator console on the target Windows Server. Review backups and maintain console or out-of-band access before applying firewall changes.

## Download and run

PowerShell — `ad-default-firewalls-v11.2.ps1`:

```powershell
$u='https://raw.githubusercontent.com/Enhan540/CCDCTesting/main/ad-default-firewalls-v11.2.ps1'; Invoke-WebRequest $u -OutFile .\ad-default-firewalls-v11.2.ps1; PowerShell.exe -ExecutionPolicy Bypass -File .\ad-default-firewalls-v11.2.ps1 -ClientNetworks 192.168.5.0/24
```

cmd — `ad-default-firewalls-v11.2.ps1`:

```cmd
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest 'https://raw.githubusercontent.com/Enhan540/CCDCTesting/main/ad-default-firewalls-v11.2.ps1' -OutFile '.\ad-default-firewalls-v11.2.ps1'; & '.\ad-default-firewalls-v11.2.ps1' -ClientNetworks '192.168.5.0/24'"
```

PowerShell — `dc-firewalls-barebones-v2.2.ps1`:

```powershell
$u='https://raw.githubusercontent.com/Enhan540/CCDCTesting/main/dc-firewalls-barebones-v2.2.ps1'; Invoke-WebRequest $u -OutFile .\dc-firewalls-barebones-v2.2.ps1; PowerShell.exe -ExecutionPolicy Bypass -File .\dc-firewalls-barebones-v2.2.ps1
```

cmd — `dc-firewalls-barebones-v2.2.ps1`:

```cmd
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest 'https://raw.githubusercontent.com/Enhan540/CCDCTesting/main/dc-firewalls-barebones-v2.2.ps1' -OutFile '.\dc-firewalls-barebones-v2.2.ps1'; & '.\dc-firewalls-barebones-v2.2.ps1'"
```
