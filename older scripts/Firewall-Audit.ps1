<#
.SYNOPSIS
  Audits Windows Firewall state and inbound allow rules; optionally applies a restrictive baseline.
.DESCRIPTION
  Writes firewall_audit_<timestamp>.txt with profile state, every enabled inbound allow rule
  (with resolved ports and programs), and listening ports that have no matching allow rule.
  -ApplyBaseline enables all profiles and sets default inbound to Block.
  Review the audit BEFORE applying the baseline so required services are not cut off.
.EXAMPLE
  .\Firewall-Audit.ps1
  .\Firewall-Audit.ps1 -ApplyBaseline -AllowPorts 3389,445
#>
[CmdletBinding()]
param(
    [string]$OutDir = 'C:\CCDC\Output',
    [switch]$ApplyBaseline,
    [int[]]$AllowPorts = @()
)

$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$outFile = Join-Path $OutDir ("firewall_audit_{0}.txt" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

function Out-Line { param($Text) $Text | Tee-Object -FilePath $outFile -Append }

Out-Line "=== Firewall profiles ==="
Get-NetFirewallProfile | Format-Table Name, Enabled, DefaultInboundAction, DefaultOutboundAction -AutoSize |
    Out-String | Tee-Object -FilePath $outFile -Append

Out-Line "`n=== Enabled inbound ALLOW rules ==="
$rules = Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True
$report = foreach ($r in $rules) {
    $pf  = $r | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
    $app = $r | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue
    [pscustomobject]@{
        Name      = $r.DisplayName
        Profile   = $r.Profile
        Protocol  = $pf.Protocol
        LocalPort = ($pf.LocalPort -join ',')
        Program   = $app.Program
    }
}
$report | Format-Table -Wrap | Out-String | Tee-Object -FilePath $outFile -Append

Out-Line "`n=== Listening TCP ports with no obvious allow rule ==="
$allowedPorts = $report | ForEach-Object { $_.LocalPort -split ',' } | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ }
Get-NetTCPConnection -State Listen | Where-Object { $allowedPorts -notcontains $_.LocalPort } |
    Select-Object LocalAddress, LocalPort, OwningProcess |
    Format-Table -AutoSize | Out-String | Tee-Object -FilePath $outFile -Append

if ($ApplyBaseline) {
    Out-Line "`n=== Applying baseline ==="
    Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow
    Out-Line 'All profiles enabled; default inbound = Block.'

    foreach ($p in $AllowPorts) {
        $name = "CCDC Allow TCP $p"
        if (-not (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName $name -Direction Inbound -Protocol TCP -LocalPort $p -Action Allow -Profile Any | Out-Null
            Out-Line "Added rule: $name"
        }
    }
    Out-Line 'Baseline applied. Verify required services still respond.'
}

Out-Line "`nDone. Results: $outFile"
Write-Host "Results: $outFile"
