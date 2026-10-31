# CCDC Windows Firewall Scripts

This repository contains Windows PowerShell firewall scripts for CCDC competition systems. The newest general-purpose script is in the repository root. The current barebones script and reusable service module remain under `scripts/current/`. Older AD-firewall variants and historical scripts are retained under `archive/`.

## Newest script: `win-firewall-v1.0.1.ps1`

Run this script from an elevated Windows PowerShell session, or let it request elevation when needed. It detects whether the host is a Client or Domain Controller, enables all firewall profiles, sets default inbound traffic to Block and outbound traffic to Allow, creates the appropriate script-managed rules, disables other enabled local inbound rules, and exports before/after firewall backups and reports.

Version `1.0.1` is the first patch increment from `1.0`, released to correct role-parameter handling and service-module packaging issues.

The script preserves rules it creates. On a Domain Controller those include the AD rules; with `-ConfigureServices`, they also include selected service-listener rules. On a Client, selected service rules are the only rules created by the script.

### Basic run

```powershell
PowerShell.exe -ExecutionPolicy Bypass -File .\win-firewall-v1.0.1.ps1
```

Optional role validation:

```powershell
PowerShell.exe -ExecutionPolicy Bypass -File .\win-firewall-v1.0.1.ps1 -Role DC
```

### Client network scopes

On a Domain Controller, omit `-ClientNetworks` to use `LocalSubnet4`, or provide explicit IPv4 addresses/CIDR scopes:

```powershell
PowerShell.exe -ExecutionPolicy Bypass -File .\win-firewall-v1.0.1.ps1 -ClientNetworks 192.168.5.0/24
```

### Optional service rules

Use `-ConfigureServices` to discover running Windows services with TCP/UDP listeners. The script displays a numbered list and accepts individual numbers, comma-separated numbers, ranges, `All`, or `None`.

```powershell
PowerShell.exe -ExecutionPolicy Bypass -File .\win-firewall-v1.0.1.ps1 -ConfigureServices
```

```powershell
PowerShell.exe -ExecutionPolicy Bypass -File .\win-firewall-v1.0.1.ps1 -ConfigureServices -ServiceSelection 2,4-6
```

Service rules default to `Any` remote address. Restrict them explicitly when appropriate:

```powershell
PowerShell.exe -ExecutionPolicy Bypass -File .\win-firewall-v1.0.1.ps1 -ConfigureServices -ServiceSelection 2-4 -ServiceRemoteAddress 192.168.5.0/24
```

The service-selection logic is packaged inside `win-firewall-v1.0.1.ps1`, so copying only that file is sufficient. The separate module at `scripts/current/service-firewall/ServiceFirewallRules.psm1` remains available when the service-selection functionality is needed from another script.

### Detailed append-only logs

Use `-KeepLogs` to append detailed firewall activity to the stable default file:

```powershell
PowerShell.exe -ExecutionPolicy Bypass -File .\win-firewall-v1.0.1.ps1 -KeepLogs
```

Default log path:

```text
C:\CCDC\FirewallBackups\firewall.log
```

Use a custom path when several systems or workflows should share a log:

```powershell
PowerShell.exe -ExecutionPolicy Bypass -File .\win-firewall-v1.0.1.ps1 -ConfigureServices -KeepLogs C:\CCDC\FirewallBackups\competition-firewall.log
```

Runs using the same path append to the existing file. Console output remains concise; the log records rule-level creation, update, disable, verification, export, error, and rollback details.

### Modify and export modes

Update the remote scopes on existing enabled AD rules without running the full baseline or cleanup workflow:

```powershell
PowerShell.exe -ExecutionPolicy Bypass -File .\win-firewall-v1.0.1.ps1 -Modify -ClientNetworks 192.168.5.10,192.168.5.11
```

Export a report of currently enabled effective rules without changing firewall settings:

```powershell
PowerShell.exe -ExecutionPolicy Bypass -File .\win-firewall-v1.0.1.ps1 -Export
```

Restore a `.wfw` backup with `netsh`:

```powershell
netsh advfirewall import 'C:\CCDC\FirewallBackups\firewall-after-CLIENT01-0916-10302026.wfw'
```

Keep console or out-of-band access available. Firewall cleanup can interrupt remote management, application traffic, or CCDC services. Group Policy-controlled rules may remain enabled and are reported as nonlocal rules.

## Current barebones script

The most current legacy barebones workflow is `scripts/current/dc-firewalls-barebones/dc-firewalls-barebones-v3.3.3.ps1`. It provides the earlier AD-focused workflow with automatic Client/DC detection, `LocalSubnet4` support, `-Modify`, `-Export`, before/after backups, and enabled-rule reports.

For its full parameters, behavior, and examples, see [scripts/current/dc-firewalls-barebones/README.md](scripts/current/dc-firewalls-barebones/README.md).

Quick run:

```powershell
PowerShell.exe -ExecutionPolicy Bypass -File .\dc-firewalls-barebones-v3.3.3.ps1
```

## Repository layout

- `win-firewall-v1.0.1.ps1` — newest general-purpose Client/DC firewall script; `v1.0` is the previous revision.
- `scripts/current/dc-firewalls-barebones/` — current barebones script and detailed documentation.
- `scripts/current/service-firewall/` — reusable service-to-firewall rule module.
- `archive/previous-versions/ad-default-firewalls/` — archived configurable AD-firewall variants and their documentation.
- `archive/older-scripts/` — older general CCDC scripts.
- `archive/untested/` — scripts not yet validated for regular use.
