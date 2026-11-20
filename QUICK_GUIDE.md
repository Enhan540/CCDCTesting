# Quick guide: CCDC Firewall Scripts

This repository contains PowerShell scripts for applying or inspecting Windows Defender Firewall settings on CCDC systems. The current main script is `fireme-v2.1.ps1`. Run changes from an elevated Windows PowerShell session and keep console or other recovery access available: a full run disables enabled local inbound rules that it did not create, which can interrupt remote access or competition services.

## What happens when you run it

| Action | What the script does | Files or changes to expect |
|---|---|---|
| `PowerShell.exe -ExecutionPolicy Bypass -File .\fireme-v2.1.ps1` | Applies and verifies the baseline (Domain, Private, and Public profiles enabled; inbound defaults to Block; outbound defaults to Allow). It detects Client vs Domain Controller, saves an initial snapshot, applies that workflow, disables other enabled local inbound rules, then saves the final state. | Changes firewall settings. Writes before/after `.wfw` backups and enabled-rule `.txt` reports in `C:\CCDC\FirewallBackups`. |
| Add `-Role Client` or `-Role DC` | Checks that the detected machine role matches the requested role before proceeding with the regular full workflow. | Same changes and files as a full run if the role matches; stops if it does not. |
| Run on a Client | Applies the baseline, creates no AD rules, then disables enabled local inbound rules. Reports enabled nonlocal or Group Policy rules that remain. | Initial and final firewall backups/reports. |
| Run on a Domain Controller | Applies the baseline, creates or updates the required AD inbound rules, then disables other enabled local inbound rules. Default remote scope is `LocalSubnet4`. | Initial and final backups/reports; AD rules cover DNS, Kerberos, LDAP, password change, SMB, RPC, NTP, and Global Catalog ports. |
| Add `-ClientNetworks 192.168.5.0/24` | Uses the supplied IPv4 addresses/scopes for the AD rules instead of the default subnet scope. | Full-run behavior, scoped to those supplied networks. |
| Add `-Modify -ClientNetworks <addresses>` | On a detected Domain Controller, changes the remote scope only on existing enabled local AD rules managed by the script. It skips the baseline and inbound cleanup. | Before/after `.wfw` backups and reports; unrelated rules are left alone. Requires explicit client networks. |
| Add `-Export` | Reads currently enabled effective firewall rules and writes a text report. Does not change firewall settings. | TXT report only; no `.wfw` backup. |
| Add `-Print` (optionally `Inbound` or `Outbound`) | Displays currently enabled effective firewall rules in the console. | No firewall changes and no backup. |
| Add `-Log` (optionally a file path) | Appends detailed run activity, including changes, disabled-rule details, output paths, errors, and rollback information. | Default log is `C:\CCDC\FirewallBackups\firewall.log`; a supplied path overrides it. |

For a full DC run with a narrower scope, for example:

```powershell
PowerShell.exe -ExecutionPolicy Bypass -File .\fireme-v2.1.ps1 -Role DC -ClientNetworks 192.168.5.0/24
```

## Restore and review

Review the generated TXT reports to see enabled rules and the run results. A `.wfw` snapshot can be imported with:

```powershell
netsh advfirewall import 'C:\CCDC\FirewallBackups\<backup-file>.wfw'
```

Replace the placeholder with the actual backup path. Group Policy-controlled rules may remain enabled; the script reports these instead of claiming it removed them.

## Which files matter

- `fireme-v2.1.ps1` — current main script; supports full Client/DC workflows and `-Modify`, `-Export`, `-Print`, and `-Log`.
- `fireme-v2.0.ps1` — previous main version.
- `scripts/current/dc-firewalls-barebones/` — separate, narrower Domain Controller firewall script with its own README.
- `scripts/current/service-firewall/` — standalone service-firewall module, not part of the main `fireme` workflow.
- `In-Progress/` and `archive/` — older or historical scripts; not the default entry point.

## Note about the pasted maintenance notes

The supplied “Controller dependencies and SSH troubleshooting (v0.5.9 maintenance update)” describes CCDC Sentinel, a separate Linux VM inventory/collector/dashboard project. Its `setup.sh`, SSH enrollment, package updates, password rotation, Docker collector, and dashboard actions are not present in this repository and are not performed by these PowerShell scripts.
