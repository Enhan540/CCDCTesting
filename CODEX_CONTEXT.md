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
fireme-v1.0.ps1
In-Progress/
scripts/current/dc-firewalls-barebones/
scripts/current/service-firewall/
archive/older-scripts/
archive/previous-versions/
archive/untested/
```

The root README contains the user-facing download and usage instructions. Current scripts are under `scripts/current`; older material is retained under `archive`.

## Current scripts

### Newest firewall script

File: `fireme-v1.0.ps1`

The repository-root script is now the newest general-purpose firewall workflow. It supports Client and Domain Controller runs, AD-rule creation, inbound cleanup, append-only `-Log` logging, `-Modify`, and `-Export`. It has no service discovery or service-port rule creation. Bare `-Log` uses `C:\CCDC\FirewallBackups\firewall.log`; `-Log <path>` uses the supplied file.

Previous `win-firewall` revisions are preserved in `In-Progress/`. The standalone service module remains at `scripts/current/service-firewall/ServiceFirewallRules.psm1` for separate or historical use.

### Archived configurable AD firewall

Directory: `archive/previous-versions/ad-default-firewalls/`

Current tracked revisions include `ad-default-firewalls-v11.ps1`, `v11.1.ps1`, `v11.2.ps1`, `v11.3.ps1`, and `v11.4.ps1`. The script creates scoped AD service rules from `-ClientNetworks`, verifies them, manages inbound cleanup according to its existing behavior, and exports firewall backups/reports. Version 11.4 formats enabled TXT reports as separate Inbound and Outbound sections. Do not modify these scripts unless the user specifically requests it.

### Barebones DC firewall

Current file: `scripts/current/dc-firewalls-barebones/dc-firewalls-barebones-v3.3.3.ps1`

Detailed usage is documented in `scripts/current/dc-firewalls-barebones/README.md`. It remains the current barebones revision, while `fireme-v1.0.ps1` is the recommended newest script.

Earlier barebones revisions still present in that directory include `v2.ps1` through `v2.4.ps1` and `v3.0.ps1`. The user generally prefers incrementing the active script by renaming it instead of keeping duplicate active copies. v3.1 was originally created while preserving v3.0 as explicitly requested; the active script was subsequently renamed for later revisions.

The barebones script is intended for Windows machines used in CCDC and is compatible with Windows PowerShell 5.1. It:

- self-elevates when needed;
- checks the Windows Firewall cmdlets;
- uses the Windows Firewall `LocalSubnet4` keyword when `-ClientNetworks` is omitted;
- accepts explicit IPv4 addresses or scopes through `-ClientNetworks`;
- creates or updates the scoped inbound AD rules;
- verifies rule properties and canonicalized remote scopes;
- disables other enabled local inbound rules during a full run;
- preserves Group Policy or other nonlocal effective rules as warnings;
- exports firewall `.wfw` backups and TXT reports under `C:\CCDC\FirewallBackups`.

Version 3.3.3 retains that workflow and adds section-based TXT reports: enabled Inbound rules are shown first, followed by enabled Outbound rules. Empty sections say `No enabled rules found.` The `netsh` export remains a bounded process with progress messages and a clear timeout after 60 seconds.

All TXT export paths use `Get-RuleReport`, which queries ActiveStore with `-Enabled True` and explicitly filters `Enabled` to True. This includes before/after backup reports, Client reports, and `-Export`; reports include all directions and actions among enabled rules. The DC final export is freshly queried after rule creation and cleanup. `-Export` is report-only and exits without changing firewall settings or making `.wfw` backups. It cannot be combined with `-Modify`, `-Role`, or `-ClientNetworks`.

## Barebones parameters

```powershell
# Full workflow using the LocalSubnet4 firewall scope
PowerShell.exe -ExecutionPolicy Bypass -File .\dc-firewalls-barebones-v3.3.3.ps1

# Full workflow using explicit addresses or scopes
PowerShell.exe -ExecutionPolicy Bypass -File .\dc-firewalls-barebones-v3.3.3.ps1 -ClientNetworks 192.168.5.10,192.168.5.11

# Modify only existing enabled local barebones rules
PowerShell.exe -ExecutionPolicy Bypass -File .\dc-firewalls-barebones-v3.3.3.ps1 -ClientNetworks 192.168.5.10,192.168.5.11 -Modify

# Export currently enabled effective rules only
PowerShell.exe -ExecutionPolicy Bypass -File .\dc-firewalls-barebones-v3.3.3.ps1 -Export
```

Parameter behavior:

- No parameters runs the full setup with the detected subnet.
- `-ClientNetworks` is optional for a full run. It accepts comma-separated IPv4 addresses, CIDR scopes, or dotted netmask scopes. It replaces the detected subnet.
- `-Modify` skips the full setup and cleanup workflow. It requires `-ClientNetworks` and updates only currently enabled, locally managed barebones rules.
- `-Modify` does not change unrelated rules or outbound rules.

## Modify backup behavior in v3.3.3

When `-Modify` is used, the script collects each target rule’s current remote address and completes a pre-change `.wfw` backup before modifying any rule. It attempts the requested updates, verifies each successful update, and exports an after-state backup:

- `firewall-modify-before-TIMESTAMP.wfw` and `.txt` — original configuration backup and enabled-rule report;
- `firewall-modify-after-TIMESTAMP.wfw` — resulting firewall configuration after the attempted modifications;
- `firewall-modify-after-TIMESTAMP.txt` — a change report with rule name, protocol, local port, remote scope `before --> after`, and status.

If a rule fails, the script records the failure, stops attempting later rules, still exports the resulting after-state backup/report, and then throws an error that includes those paths. If the pre-change backup fails, no rules are modified. Versions 3.0 and 3.1 created only the after-state backup; v3.2 and later create both.

## Role detection, export, and timestamp behavior in v3.3.3

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

The firewall TXT reports use explicit fixed-width formatting, sort by the lowest numeric local port within each direction, and retain the underlying `PolicyStoreSourceType` value internally. Human-readable source labels are applied only while writing reports. Reports contain separate `INBOUND RULES` and `OUTBOUND RULES` sections. Existing report formatting changes must not alter firewall rule behavior.

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
