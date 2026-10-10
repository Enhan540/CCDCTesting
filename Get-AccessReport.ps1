<#
.SYNOPSIS
  Reports which local and domain users belong to which groups, and what those users can do.
.DESCRIPTION
  Writes these files to OutDir\AccessReport_<host>_<timestamp>\:
    local_users_groups.txt      Each local user and the local groups they belong to
    local_group_members.txt     Each local group and its direct members
    domain_users_groups.txt     Each domain user and their group memberships (needs the AD module)
    domain_group_members.txt    Domain groups and their members, expanded recursively (needs AD module)
    user_rights.txt             Privileges granted by policy (SeDebugPrivilege, SeRemoteInteractiveLogonRight, etc.)
    share_permissions.txt       SMB share ACLs
    ntfs_permissions.txt        NTFS ACLs on the paths given in -Paths
    access_summary.csv          One row per user/group pair, for sorting or filtering in Excel
  Read-only: it changes nothing. Run from an elevated PowerShell.
.EXAMPLE
  .\Get-AccessReport.ps1
  .\Get-AccessReport.ps1 -Paths 'C:\inetpub','D:\Shares' -SkipDomain
#>
[CmdletBinding()]
param(
    [string]$OutDir = 'C:\CCDC\Output',
    [string[]]$Paths = @('C:\Users', 'C:\Windows\System32\config', 'C:\inetpub'),
    [switch]$SkipDomain
)

$ErrorActionPreference = 'Continue'
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$dir   = Join-Path $OutDir ("AccessReport_{0}_{1}" -f $env:COMPUTERNAME, $stamp)
New-Item -ItemType Directory -Path $dir -Force | Out-Null

$csvRows = New-Object System.Collections.Generic.List[object]
function Add-CsvRow {
    param($Scope, $Account, $Type, $Group, $Enabled)
    $csvRows.Add([pscustomobject]@{
        Scope = $Scope; Account = $Account; AccountType = $Type; Group = $Group; Enabled = $Enabled
    })
}

# ---------- Local users and groups ----------
$localUsers  = Get-LocalUser
$localGroups = Get-LocalGroup

# Build a membership map: group -> members (direct only)
$localMembers = @{}
foreach ($g in $localGroups) {
    $localMembers[$g.Name] = @(Get-LocalGroupMember -Group $g.Name -ErrorAction SilentlyContinue)
}

# Per-user view (inverted map)
$userGroups = @{}
foreach ($g in $localGroups) {
    foreach ($m in $localMembers[$g.Name]) {
        $short = $m.Name.Split('\')[-1]
        if (-not $userGroups.ContainsKey($m.Name)) { $userGroups[$m.Name] = New-Object System.Collections.Generic.List[string] }
        $userGroups[$m.Name].Add($g.Name)
    }
}

$localUserLines = foreach ($u in $localUsers) {
    $qualified = "$env:COMPUTERNAME\$($u.Name)"
    $groups = if ($userGroups.ContainsKey($qualified)) { $userGroups[$qualified] -join ', ' } else { '(none)' }
    Add-CsvRow 'Local' $u.Name 'User' $groups $u.Enabled
    "{0,-22} enabled={1,-5} groups: {2}" -f $u.Name, $u.Enabled, $groups
}
$localUserLines | Out-File (Join-Path $dir 'local_users_groups.txt') -Encoding utf8

$localGroupLines = foreach ($g in $localGroups) {
    "== $($g.Name)  ($($g.Description))"
    if ($localMembers[$g.Name].Count -eq 0) { '   (no members)' }
    foreach ($m in $localMembers[$g.Name]) {
        "   {0,-40} {1}" -f $m.Name, $m.ObjectClass
        Add-CsvRow 'Local-Group' $m.Name $m.ObjectClass $g.Name ''
    }
}
$localGroupLines | Out-File (Join-Path $dir 'local_group_members.txt') -Encoding utf8

# ---------- Domain users and groups ----------
if (-not $SkipDomain -and (Get-Command Get-ADUser -ErrorAction SilentlyContinue)) {
    try {
        $domainUsers = Get-ADUser -Filter * -Properties Enabled, MemberOf, LastLogonDate
        $domainUserLines = foreach ($u in $domainUsers) {
            $groups = @()
            try {
                $groups = Get-ADPrincipalGroupMembership -Identity $u.DistinguishedName |
                    Where-Object { $_.Name -ne 'Domain Users' } | ForEach-Object Name
            } catch { }
            $gtext = if ($groups) { $groups -join ', ' } else { '(none)' }
            foreach ($gn in $groups) { Add-CsvRow 'Domain' $u.SamAccountName 'User' $gn $u.Enabled }
            "{0,-22} enabled={1,-5} last logon={2}`n    groups: {3}" -f $u.SamAccountName, $u.Enabled, $u.LastLogonDate, $gtext
        }
        $domainUserLines | Out-File (Join-Path $dir 'domain_users_groups.txt') -Encoding utf8

        $domainGroups = Get-ADGroup -Filter * -Properties Members
        $domainGroupLines = foreach ($g in $domainGroups | Sort-Object Name) {
            "== $($g.Name)"
            $members = Get-ADGroupMember -Identity $g.DistinguishedName -Recursive -ErrorAction SilentlyContinue
            if (-not $members) { '   (no members)' }
            foreach ($m in $members) {
                "   {0,-40} {1}" -f $m.SamAccountName, $m.objectClass
                Add-CsvRow 'Domain-Group' $m.SamAccountName $m.objectClass $g.Name ''
            }
        }
        $domainGroupLines | Out-File (Join-Path $dir 'domain_group_members.txt') -Encoding utf8
    } catch {
        "ERROR reading AD: $($_.Exception.Message)" | Out-File (Join-Path $dir 'domain_users_groups.txt') -Encoding utf8
    }
} else {
    'Skipped domain section (AD module not present or -SkipDomain given).' |
        Out-File (Join-Path $dir 'domain_users_groups.txt') -Encoding utf8
}

# ---------- User rights assignments (what each account/group is allowed to do) ----------
$seceditFile = Join-Path $env:TEMP "ccdc_userrights_$stamp.inf"
secedit.exe /export /areas USER_RIGHTS /cfg $seceditFile | Out-Null
if (Test-Path $seceditFile) {
    $rightsLines = Get-Content $seceditFile | Where-Object { $_ -match '^Se' }
    $rightsLines | ForEach-Object {
        $name, $value = $_ -split '\s*=\s*', 2
        "{0,-38} {1}" -f $name, $value
    } | Out-File (Join-Path $dir 'user_rights.txt') -Encoding utf8
    Remove-Item $seceditFile -Force
    "Privilege names: SeDebugPrivilege = debug other processes; SeRemoteInteractiveLogonRight = RDP logon;" |
        Out-File (Join-Path $dir 'user_rights.txt') -Append -Encoding utf8
    "SeBackupPrivilege / SeRestorePrivilege = read/write any file; SeTakeOwnershipPrivilege = take any object;" |
        Out-File (Join-Path $dir 'user_rights.txt') -Append -Encoding utf8
} else {
    'secedit export failed.' | Out-File (Join-Path $dir 'user_rights.txt') -Encoding utf8
}

# ---------- Share permissions ----------
Get-SmbShare | ForEach-Object {
    "== $($_.Name)  ($($_.Path))"
    Get-SmbShareAccess -Name $_.Name | ForEach-Object {
        "   {0,-35} {1,-6} {2}" -f $_.AccountName, $_.AccessControlType, $_.AccessRight
    }
} | Out-File (Join-Path $dir 'share_permissions.txt') -Encoding utf8

# ---------- NTFS permissions on key paths ----------
$ntfs = foreach ($p in $Paths) {
    if (-not (Test-Path $p)) { "MISSING: $p"; continue }
    "== $p"
    (Get-Acl $p).Access | ForEach-Object {
        "   {0,-40} {1,-8} {2}" -f $_.IdentityReference, $_.AccessControlType, $_.FileSystemRights
    }
}
$ntfs | Out-File (Join-Path $dir 'ntfs_permissions.txt') -Encoding utf8

# ---------- Summary CSV ----------
$csvRows | Export-Csv (Join-Path $dir 'access_summary.csv') -NoTypeInformation -Encoding utf8

Write-Host "Access report written to: $dir"
