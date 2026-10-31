# CCDC Firewall Scripts

The primary script is `fireme-v2.0.ps1`. It applies the firewall baseline, detects Client or Domain Controller workflows, creates the required AD rules on Domain Controllers, disables other enabled local inbound rules, and writes firewall backups and reports.

`fireme-v1.0.ps1` does not discover Windows services or create service-port rules. The previous `win-firewall` revisions are preserved in `In-Progress/` for reference.

## Primary script: `fireme-v2.0.ps1`

Run from an elevated Windows PowerShell session:

```powershell
PowerShell.exe -ExecutionPolicy Bypass -File .\fireme-v2.0.ps1
```

The script enables Domain, Private, and Public firewall profiles, sets default inbound traffic to `Block`, sets default outbound traffic to `Allow`, verifies the baseline, exports an initial backup/report, applies the detected workflow, and exports the final state.

## Client workflow

On a non-DC machine, the script:

1. Applies and verifies the firewall baseline.
2. Exports the initial `.wfw` and `.txt` files.
3. Detects the Client role.
4. Creates no AD rules.
5. Disables all enabled local inbound rules.
6. Reports nonlocal or Group Policy rules that remain enabled.
7. Exports the final `.wfw` and `.txt` files.

Validate the expected role when desired:

```powershell
PowerShell.exe -ExecutionPolicy Bypass -File .\fireme-v2.0.ps1 -Role Client
```

## Domain Controller workflow

On a Domain Controller, the script creates or updates these AD rules:

- TCP/UDP 53, 88, 389, and 464.
- TCP 445 and 135.
- TCP 49152-65535 for dynamic RPC.
- UDP 123.
- TCP 3268.

Each AD rule is displayed as it is created or updated. Without `-ClientNetworks`, rules use `LocalSubnet4`:

```powershell
PowerShell.exe -ExecutionPolicy Bypass -File .\fireme-v2.0.ps1 -Role DC
```

Use explicit IPv4 addresses or scopes instead:

```powershell
PowerShell.exe -ExecutionPolicy Bypass -File .\fireme-v2.0.ps1 -ClientNetworks 192.168.5.0/24
```

After AD rule verification, the script disables other enabled local inbound rules, reports nonlocal rules, and exports the final state.

## Modify workflow

Update the remote scopes of existing enabled local AD rules without running the full baseline or cleanup workflow:

```powershell
PowerShell.exe -ExecutionPolicy Bypass -File .\fireme-v2.0.ps1 -Modify -ClientNetworks 192.168.5.10,192.168.5.11
```

`-Modify` requires a detected Domain Controller and `-ClientNetworks`. It does not create missing rules or change unrelated rules.

## Export workflow

Write a report of currently enabled effective firewall rules without changing settings:

```powershell
PowerShell.exe -ExecutionPolicy Bypass -File .\fireme-v2.0.ps1 -Export
```

`-Export` creates a TXT report only. It cannot be combined with `-Modify`, `-Role`, or `-ClientNetworks`.

## Print workflow

Use `-Print` to display currently enabled effective firewall rules without changing firewall settings or creating a `.wfw` backup. Bare `-Print` shows both directions:

```powershell
PowerShell.exe -ExecutionPolicy Bypass -File .\fireme-v2.0.ps1 -Print
```

Print only inbound or outbound rules:

```powershell
PowerShell.exe -ExecutionPolicy Bypass -File .\fireme-v2.0.ps1 -Print Inbound
PowerShell.exe -ExecutionPolicy Bypass -File .\fireme-v2.0.ps1 -Print Outbound
```

Comma-separated directions are normalized case-insensitively, with or without spaces and in either order:

```powershell
PowerShell.exe -ExecutionPolicy Bypass -File .\fireme-v2.0.ps1 -Print "Inbound,Outbound"
  PowerShell.exe -ExecutionPolicy Bypass -File .\fireme-v2.0.ps1 -Print "Outbound, Inbound"
```

`-Print` may be combined with `-Log`, but not with `-Modify`, `-Export`, `-Role`, or `-ClientNetworks`.

## Logging

Enable append-only detailed logging with the default path:

```powershell
PowerShell.exe -ExecutionPolicy Bypass -File .\fireme-v2.0.ps1 -Log
```

Default log:

```text
C:\CCDC\FirewallBackups\firewall.log
```

Use a custom path:

```powershell
PowerShell.exe -ExecutionPolicy Bypass -File .\fireme-v2.0.ps1 -Log C:\CCDC\FirewallBackups\fireme-run.log
```

Runs using the same path append to the existing file. Logs include baseline changes, AD-rule operations, disabled-rule details, backup/report paths, errors, and rollback information.

## Backups and reports

Full runs create initial and final `.wfw` backups plus enabled-rule `.txt` reports under `C:\CCDC\FirewallBackups`. `-Modify` creates before/after backups and reports. Filenames include the computer name and timestamp.

Restore a backup with:

```powershell
netsh advfirewall import 'C:\CCDC\FirewallBackups\firewall-after-DC02-1435-10302026.wfw'
```

Keep console or out-of-band access available. Inbound cleanup can affect remote management and competition services. Group Policy-controlled rules may remain enabled and are reported as nonlocal rules.

## Other scripts

- `In-Progress/` — previous `win-firewall-v1.0.3.ps1` and `win-firewall-v1.0.4.ps1` revisions.
- `fireme-v1.0.ps1` — previous primary generation.
- `fireme-v2.0.ps1` — current primary generation with normalized report-only `-Print` mode.
- `scripts/current/dc-firewalls-barebones/` — current barebones script and detailed documentation.
- `scripts/current/service-firewall/` — standalone service firewall module retained for separate or historical use.
- `archive/` — archived AD-firewall and older CCDC scripts.
