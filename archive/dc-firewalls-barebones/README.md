# Barebones Domain Controller Firewall

The current barebones script is `dc-firewalls-barebones-v3.3.3.ps1`. It is the prior-generation AD-focused workflow. It detects whether the host is a Domain Controller or Client, enables the firewall baseline, creates the scoped AD rules on a DC, and writes before/after firewall backups and reports under `C:\CCDC\FirewallBackups`.

## Parameters

- No parameters: run the full workflow. A DC uses `LocalSubnet4`; a Client applies the baseline and does not create AD rules.
- `-ClientNetworks`: supply comma-separated IPv4 addresses, CIDR scopes, or dotted-netmask scopes. On a DC these replace `LocalSubnet4`.
- `-Modify`: update only enabled local barebones AD-rule scopes. Requires `-ClientNetworks` and a detected DC. It skips full setup and cleanup.
- `-Role DC` or `-Role Client`: validate the expected detected workflow.
- `-Export`: write a TXT report of enabled effective firewall rules without changing settings. It cannot be combined with `-Modify`, `-Role`, or `-ClientNetworks`.

## Examples

Run the automatic workflow:

```powershell
PowerShell.exe -ExecutionPolicy Bypass -File .\dc-firewalls-barebones-v3.3.3.ps1
```

Use explicit client scopes:

```powershell
PowerShell.exe -ExecutionPolicy Bypass -File .\dc-firewalls-barebones-v3.3.3.ps1 -ClientNetworks 192.168.5.10,192.168.5.11
```

Modify existing enabled barebones rules:

```powershell
PowerShell.exe -ExecutionPolicy Bypass -File .\dc-firewalls-barebones-v3.3.3.ps1 -Modify -ClientNetworks 192.168.5.10,192.168.5.11
```

Export only:

```powershell
PowerShell.exe -ExecutionPolicy Bypass -File .\dc-firewalls-barebones-v3.3.3.ps1 -Export
```

## Domain Controller workflow

1. Enable Domain, Private, and Public firewall profiles.
2. Set default inbound traffic to Block and outbound traffic to Allow.
3. Export the initial `.wfw` backup and enabled-rule TXT report.
4. Detect and validate the Domain Controller role.
5. Create or update TCP/UDP 53, 88, 389, and 464 rules; TCP 445, 135, 49152-65535, and 3268; and UDP 123.
6. Use `LocalSubnet4` or the explicit `-ClientNetworks` values as the remote scope.
7. Verify every managed rule.
8. Disable other enabled local inbound rules.
9. Verify the resulting state and report any nonlocal/Group Policy rules that remain.
10. Export the final `.wfw` backup and enabled-rule TXT report.

## Client workflow

1. Enable the three firewall profiles and verify default actions.
2. Export the initial backup and report.
3. Detect and validate the Client role.
4. Create no AD baseline rules and disable no existing rules.
5. Verify the baseline again.
6. Export the final backup and report.

## Backups and reports

Backup and report filenames include the computer name and `HHmm-MMddyyyy`. A numeric suffix is added if a same-minute name already exists. Restore a backup with:

```powershell
netsh advfirewall import 'C:\CCDC\FirewallBackups\firewall-after-DC02-1435-10292026.wfw'
```

Reports contain separate enabled `INBOUND RULES` and `OUTBOUND RULES` sections and are generated from the effective ActiveStore policy.
