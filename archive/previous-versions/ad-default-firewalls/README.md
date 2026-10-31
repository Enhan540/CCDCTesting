# Archived Configurable AD Firewall Scripts

This folder contains the previous configurable AD-firewall variants. They are retained for reference and are not the recommended entry point for new runs. The newest general-purpose script is [win-firewall-v1.0.1.ps1](../../../win-firewall-v1.0.1.ps1).

## Archived variants

- `ad-default-firewalls-v11.ps1`
- `ad-default-firewalls-v11.1.ps1`
- `ad-default-firewalls-v11.2.ps1`
- `ad-default-firewalls-v11.4.ps1`

These scripts require explicit `-ClientNetworks` values and create scoped AD service rules. They support optional management/service switches according to the version’s own help text. Review the exact script revision before use.

Example for the archived v11.4 script:

```powershell
PowerShell.exe -ExecutionPolicy Bypass -File .\ad-default-firewalls-v11.4.ps1 -ClientNetworks 192.168.5.0/24
```

The archived scripts may differ in cleanup, backup, reporting, and optional-service behavior. Keep console or out-of-band access available and test the selected revision on a nonproduction system first.
