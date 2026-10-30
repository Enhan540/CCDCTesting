# CCDC Scripts — Codex Handoff Context

This file is a handoff package for another Codex instance. Treat it as project context, not as an instruction to make changes unless the user asks for them.

## Project

Repository: `C:\Users\lazer\OneDrive\Documents\GitHub\CCDCTesting`

Purpose: publish and test Windows PowerShell 5.1 scripts for Windows machines used in CCDC competitions, especially Active Directory Domain Controllers.

The user prefers repository changes to be made directly in this folder. Keep the README current when script names, parameters, paths, or behavior change.

## Directory layout

```text
README.md
CODEX_CONTEXT.md
scripts/current/ad-default-firewalls/
scripts/current/dc-firewalls-barebones/
archive/older-scripts/
archive/previous-versions/
archive/untested/
```

The root README contains the user-facing download and usage instructions. Current scripts are under `scripts/current`; older material is retained under `archive`.

## Current scripts

### Configurable AD firewall

Directory: `scripts/current/ad-default-firewalls/`

Current tracked revisions include `ad-default-firewalls-v11.ps1`, `v11.1.ps1`, `v11.2.ps1`, and `v11.3.ps1`. The script creates scoped AD service rules from `-ClientNetworks`, verifies them, manages inbound cleanup according to its existing behavior, and exports firewall backups/reports. The `.1` family includes improved TXT report formatting. Do not modify these scripts unless the user specifically requests it.

### Barebones DC firewall

Current file: `scripts/current/dc-firewalls-barebones/dc-firewalls-barebones-v3.1.ps1`

Earlier barebones revisions still present in that directory include `v2.ps1` through `v2.4.ps1` and `v3.0.ps1`. The user generally prefers incrementing the active script by renaming it instead of keeping duplicate active copies. For this v3.1 task, the user explicitly required preserving the old version, so v3.1 was created as a new file and v3.0 remains intact.

The barebones script is intended for Windows machines used in CCDC and is compatible with Windows PowerShell 5.1. It:

- self-elevates when needed;
- checks the Windows Firewall cmdlets;
- detects the primary IPv4 subnet from the default IPv4 route when `-ClientNetworks` is omitted;
- accepts explicit IPv4 addresses or scopes through `-ClientNetworks`;
- creates or updates the scoped inbound AD rules;
- verifies rule properties and canonicalized remote scopes;
- disables other enabled local inbound rules during a full run;
- preserves Group Policy or other nonlocal effective rules as warnings;
- exports firewall `.wfw` backups and TXT reports under `C:\CCDC\FirewallBackups`.

Version 3.1 automatically detects `Win32_ComputerSystem.DomainRole`: values 4 and 5 both use the DC workflow, while values 0–3 use a Client workflow. Unknown values or failed detection stop before firewall changes. `-Role DC` or `-Role Client` is an optional compatibility assertion; the requested role must match the detected machine type. Client workflow backs up the original configuration, enables all three firewall profiles, exports enabled effective rules, and exits without creating or disabling rules.

`-Export` is report-only: it exports enabled ActiveStore rules of every direction and action, then exits without changing firewall settings or making `.wfw` backups. `-Export` cannot be combined with `-Modify`, `-Role`, or `-ClientNetworks`.

## Barebones parameters

```powershell
# Full workflow using the detected primary IPv4 subnet
PowerShell.exe -ExecutionPolicy Bypass -File .\dc-firewalls-barebones-v3.1.ps1

# Full workflow using explicit addresses or scopes
PowerShell.exe -ExecutionPolicy Bypass -File .\dc-firewalls-barebones-v3.1.ps1 -ClientNetworks 192.168.5.10,192.168.5.11

# Modify only existing enabled local barebones rules
PowerShell.exe -ExecutionPolicy Bypass -File .\dc-firewalls-barebones-v3.1.ps1 -ClientNetworks 192.168.5.10,192.168.5.11 -Modify

# Export currently enabled effective rules only
PowerShell.exe -ExecutionPolicy Bypass -File .\dc-firewalls-barebones-v3.1.ps1 -Export
```

Parameter behavior:

- No parameters runs the full setup with the detected subnet.
- `-ClientNetworks` is optional for a full run. It accepts comma-separated IPv4 addresses, CIDR scopes, or dotted netmask scopes. It replaces the detected subnet.
- `-Modify` skips the full setup and cleanup workflow. It requires `-ClientNetworks` and updates only currently enabled, locally managed barebones rules.
- `-Modify` does not change unrelated rules or outbound rules.

## Modify backup behavior in v3.1

When `-Modify` is used, the script collects each target rule’s current remote address and completes a pre-change `.wfw` backup before modifying any rule. It attempts the requested updates, verifies each successful update, and exports an after-state backup:

- `firewall-modify-before-TIMESTAMP.wfw` and `.txt` — original configuration backup and enabled-rule report;
- `firewall-modify-after-TIMESTAMP.wfw` — resulting firewall configuration after the attempted modifications;
- `firewall-modify-after-TIMESTAMP.txt` — a change report with rule name, protocol, local port, remote scope `before --> after`, and status.

If a rule fails, the script records the failure, stops attempting later rules, still exports the resulting after-state backup/report, and then throws an error that includes those paths. If the pre-change backup fails, no rules are modified. Version 3.0 created only the after-state backup; v3.1 creates both.

## Role detection, export, and timestamp behavior in v3.1

`-Role` has a `ValidateSet` of `DC` and `Client` and acts as a compatibility check against the detected Windows role. DomainRole 4 and 5 both map to DC; 0–3 map to Client. Unknown or failed detection stops before firewall changes. Export-only mode is `-Export`; it cannot be combined with `-Modify`, `-Role`, or `-ClientNetworks`. The exported TXT uses the existing report formatter and queries only enabled ActiveStore rules, including all directions and actions.

All backup and report names include computer name and the timestamp format `HHmm-MMddyyyy`. A numeric suffix is added when a same-minute filename already exists. `-Export` produces only TXT. Client runs preserve the original `.wfw` backup and also make a post-profile enabled-rule TXT. DC full runs make before and after backup/report pairs.

Full DC runs continue to create before and after `.wfw`/`.txt` pairs. Client runs create the original `.wfw`/`.txt` pair and a separate post-profile enabled-rules TXT report. Export-only creates a TXT report and no `.wfw` file. All filenames use `HHmm-MMddyyyy`, include the computer name, and use a numeric suffix if a same-minute filename already exists.

Restore any `.wfw` backup with:

```powershell
netsh advfirewall import 'C:\CCDC\FirewallBackups\firewall-modify-after-DC02-1435-10292026.wfw'
```

Replace the example filename with the actual backup path.

## AD rules created by barebones

The managed rule group is `CCDC DC Barebones` and managed names begin with `CCDC-DC-Barebones-`. The current rule set covers:

- TCP/UDP 53, 88, 389, and 464;
- TCP 445, 135, 49152-65535, and 3268;
- UDP 123.

Remote addresses are the detected subnet or the explicit `-ClientNetworks` values. The script is deliberately limited to these AD services and does not add optional WinRM, RDP, NetBIOS, LDAPS, or similar services.

## Reporting behavior

The firewall TXT reports use explicit fixed-width formatting, sort by the lowest numeric local port, and retain the underlying `PolicyStoreSourceType` value internally. Human-readable source labels are applied only while writing reports. Existing report formatting changes must not alter firewall rule behavior.

## Important history and decisions

- The original work began with `ad-default-firewalls-v11` revisions and repeated checks of scope normalization, unordered comparisons, verification, backups, and safe inbound cleanup.
- A `CleanupRuleNames` concept was rejected. The intended behavior is disabling all other enabled inbound rules that were not created by the script.
- The barebones script was created as a simpler alternative and later gained explicit address modification support.
- The user requested PowerShell-only README commands; do not add cmd command sections unless explicitly requested.
- The user prefers version increments by renaming the current script to the next version instead of creating a duplicate current file. Update README links and descriptions with every rename.
- Preserve prior files and do not modify unrelated scripts.

## Known limitations

- Actual firewall cmdlet behavior must be tested on a live Windows Server host with Administrator rights; local syntax parsing alone cannot prove `New-NetFirewallRule` or `Set-NetFirewallRule` behavior.
- Group Policy-enforced rules cannot necessarily be disabled locally. The script reports effective nonlocal rules instead of claiming the firewall is fully restricted.
- Full cleanup can interrupt AD replication, management access, or competition services. Keep console or out-of-band access available.
- The repository contains historical and untested scripts. Treat archive material as reference until reviewed.

## Continuation instructions

Before changing code, inspect the current script and README, confirm the current version, and preserve the user’s versioning preference. Use `apply_patch` for edits. Run a PowerShell parser check after script edits. Check README code fences and all current download links after README edits. Report what changed, what was checked, and any live-Windows testing that was not possible.
