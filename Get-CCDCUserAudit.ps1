#Requires -Version 5.1
<#
.SYNOPSIS
  Read-only audit of local and Active Directory user accounts.
.DESCRIPTION
  Lists each account's enabled/disabled status and direct group memberships.
  AD enumeration requires the ActiveDirectory PowerShell module and permission
  to query the domain. Local enumeration uses Microsoft.PowerShell.LocalAccounts.
  Run in 64-bit Windows PowerShell 5.1 or compatible PowerShell on Windows.
.EXAMPLE
  .\Get-CCDCUserAudit.ps1
.EXAMPLE
  .\Get-CCDCUserAudit.ps1 -OutputDirectory C:\CCDC\Reports -DomainServer dc01.ccdc.local
#>
[CmdletBinding()]
param(
    [string]$OutputDirectory = 'C:\CCDC\Reports',
    [string]$DomainServer
)

$ErrorActionPreference = 'Stop'
$warnings = [System.Collections.Generic.List[string]]::new()
$localResults = @()
$domainResults = @()
$localSuccess = $false
$domainSuccess = $false
$domainLabel = '(not detected)'

function Format-UserSection {
    param([string]$Title, [object[]]$Users, [bool]$Succeeded)
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add(('=' * 60))
    $lines.Add($Title)
    $lines.Add(('=' * 60))
    $lines.Add('')
    if (-not $Succeeded) {
        $lines.Add('NOT AVAILABLE - see warnings at end of report.')
        $lines.Add('')
        return $lines.ToArray()
    }
    if ($Users.Count -eq 0) {
        $lines.Add('No accounts returned.')
        $lines.Add('')
        return $lines.ToArray()
    }
    foreach ($user in ($Users | Sort-Object Name)) {
        $lines.Add("Username: $($user.Name)")
        $lines.Add("Status:   $($user.Status)")
        if ($user.SID) { $lines.Add("SID:      $($user.SID)") }
        $lines.Add('Groups:')
        if (@($user.Groups).Count -eq 0) {
            $lines.Add('  (none found / unable to determine)')
        } else {
            foreach ($group in (@($user.Groups) | Sort-Object -Unique)) {
                $lines.Add("  - $group")
            }
        }
        if ($user.Note) { $lines.Add("Note:     $($user.Note)") }
        $lines.Add(('-' * 60))
        $lines.Add('')
    }
    return $lines.ToArray()
}

# Local accounts and memberships (including local groups containing domain users).
try {
    Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction Stop
    $localUsers = @(Get-LocalUser -ErrorAction Stop)
    $membershipBySid = @{}
    foreach ($group in @(Get-LocalGroup -ErrorAction Stop)) {
        try {
            foreach ($member in @(Get-LocalGroupMember -Group $group.Name -ErrorAction Stop)) {
                if ($member.SID) {
                    $sid = $member.SID.Value
                    if (-not $membershipBySid.ContainsKey($sid)) { $membershipBySid[$sid] = @() }
                    $membershipBySid[$sid] += $group.Name
                }
            }
        } catch {
            $warnings.Add("Could not enumerate local group '$($group.Name)': $($_.Exception.Message)")
        }
    }
    $localResults = @($localUsers | ForEach-Object {
        $sid = $_.SID.Value
        [pscustomobject]@{
            Name = $_.Name
            SID = $sid
            Status = if ($_.Enabled) { 'ENABLED' } else { 'DISABLED' }
            Groups = if ($membershipBySid.ContainsKey($sid)) { @($membershipBySid[$sid]) } else { @() }
            Note = ''
        }
    })
    $localSuccess = $true
} catch {
    $warnings.Add("Local account enumeration failed: $($_.Exception.Message)")
}

# Domain accounts and direct domain group memberships.
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $adArgs = @{}
    if ($DomainServer) { $adArgs.Server = $DomainServer }
    $domain = Get-ADDomain @adArgs -ErrorAction Stop
    $domainLabel = $domain.DNSRoot
    $domainUsers = @(Get-ADUser -Filter * -Properties Enabled,PrimaryGroupID,MemberOf,SID @adArgs -ErrorAction Stop)
    $domainResults = @(foreach ($user in $domainUsers) {
        $groups = @()
        $note = ''
        try {
            # Includes primary group (typically Domain Users), unlike MemberOf alone.
            $groups = @(Get-ADPrincipalGroupMembership -Identity $user @adArgs -ErrorAction Stop |
                ForEach-Object { $_.Name })
        } catch {
            $note = 'Group lookup incomplete (see warnings).'
            $warnings.Add("Domain groups for '$($user.SamAccountName)' could not be fully retrieved: $($_.Exception.Message)")
            # Fallback: direct MemberOf DNs; primary group may be omitted.
            $groups = @(foreach ($dn in @($user.MemberOf)) {
                if ($dn -match '^CN=((?:\\.|[^,])+)') { $Matches[1] } else { $dn }
            })
        }
        [pscustomobject]@{
            Name = $user.SamAccountName
            SID = $user.SID.Value
            Status = if ($user.Enabled) { 'ENABLED' } else { 'DISABLED' }
            Groups = @($groups)
            Note = $note
        }
    })
    $domainSuccess = $true
} catch {
    $warnings.Add("Domain enumeration unavailable: $($_.Exception.Message). Install RSAT Active Directory tools, check domain connectivity, or specify -DomainServer.")
}

$disabledCount = @($localResults | Where-Object Status -eq 'DISABLED').Count +
                 @($domainResults | Where-Object Status -eq 'DISABLED').Count
$lines = [System.Collections.Generic.List[string]]::new()
$lines.Add(('=' * 60))
$lines.Add('                    CCDC USER AUDIT')
$lines.Add(('=' * 60))
$lines.Add("Computer:          $env:COMPUTERNAME")
$lines.Add("Domain:            $domainLabel")
$lines.Add("Date:              $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')")
$lines.Add('')
$lines.Add('SUMMARY')
$lines.Add("Local users:       $(if ($localSuccess) { $localResults.Count } else { 'UNAVAILABLE' })")
$lines.Add("Domain users:      $(if ($domainSuccess) { $domainResults.Count } else { 'UNAVAILABLE' })")
$lines.Add("Disabled found:    $disabledCount (among successfully enumerated accounts)")
$lines.Add('')
foreach ($line in (Format-UserSection 'LOCAL USERS' $localResults $localSuccess)) { $lines.Add($line) }
foreach ($line in (Format-UserSection 'DOMAIN USERS' $domainResults $domainSuccess)) { $lines.Add($line) }
$lines.Add(('=' * 60))
$lines.Add('WARNINGS / LIMITATIONS')
$lines.Add(('=' * 60))
$lines.Add('Group lists show direct memberships, not all nested/effective memberships.')
$lines.Add('Domain users belonging to local groups are not included in their domain group lists.')
$lines.Add('Local group membership failures may produce incomplete group lists.')
if ($warnings.Count -eq 0) { $lines.Add('No enumeration warnings.') }oreach ($warning in $warnings) { $lines.Add("- $warning") }

try {
    New-Item -Path $OutputDirectory -ItemType Directory -Force -ErrorAction Stop | Out-Null
    $file = Join-Path $OutputDirectory ("UserAudit_{0}_{1}.txt" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd_HHmmss'))
    $lines | Out-File -FilePath $file -Encoding UTF8 -ErrorAction Stop
    Write-Output "Report saved: $file"
    if ($warnings.Count -gt 0) { Write-Warning "$($warnings.Count) warning(s) in report. Review WARNINGS / LIMITATIONS section." }
} catch {
    Write-Error "Could not write report: $($_.Exception.Message)"
}
