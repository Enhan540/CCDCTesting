<#
.SYNOPSIS
  Rotates local user passwords and writes a change log (no plaintext passwords in the log).
.DESCRIPTION
  Generates a random password per account, applies it, and records the account name and
  timestamp in password_rotation_<timestamp>.txt. New passwords are written to a separate
  secrets file that is restricted to Administrators (SYSTEM and Administrators only).
  Move the secrets file to your team's secure store and delete the local copy after use.
  Accounts listed in -ExcludeUsers are skipped. Always test on one account first.
.EXAMPLE
  .\Rotate-Passwords.ps1 -Users alice,bob -WhatIf
  .\Rotate-Passwords.ps1 -Users alice,bob
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string[]]$Users,
    [string[]]$ExcludeUsers = @('Administrator', 'Guest', 'DefaultAccount', 'WDAGUtilityAccount'),
    [int]$Length = 20,
    [string]$OutDir = 'C:\CCDC\Output'
)

$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$stamp     = Get-Date -Format 'yyyyMMdd_HHmmss'
$logFile   = Join-Path $OutDir "password_rotation_$stamp.txt"
$secrets   = Join-Path $OutDir "new_passwords_$stamp.txt"

function New-RandomPassword {
    param([int]$Len)
    $upper   = 'ABCDEFGHJKLMNPQRSTUVWXYZ'.ToCharArray()
    $lower   = 'abcdefghijkmnopqrstuvwxyz'.ToCharArray()
    $digits  = '23456789'.ToCharArray()
    $symbols = '!@#$%^&*-_=+?'.ToCharArray()
    $all     = $upper + $lower + $digits + $symbols
    $rng     = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes   = New-Object byte[] $Len
    $rng.GetBytes($bytes)
    $chars = foreach ($b in $bytes) { $all[$b % $all.Length] }
    # guarantee one of each class
    $chars[0] = $upper[(Get-Random -Maximum $upper.Length)]
    $chars[1] = $lower[(Get-Random -Maximum $lower.Length)]
    $chars[2] = $digits[(Get-Random -Maximum $digits.Length)]
    $chars[3] = $symbols[(Get-Random -Maximum $symbols.Length)]
    -join $chars
}

if (-not $Users) {
    $Users = Get-LocalUser | Where-Object { $_.Enabled -and $ExcludeUsers -notcontains $_.Name } | ForEach-Object Name
}

"Password rotation on $env:COMPUTERNAME at $stamp" | Out-File $logFile -Encoding utf8
"Secrets file: $secrets (RESTRICTED - move to secure store, then delete)" | Out-File $logFile -Append -Encoding utf8
"" | Out-File $secrets -Encoding utf8

foreach ($u in $Users) {
    if ($ExcludeUsers -contains $u) { "SKIP (excluded): $u" | Out-File $logFile -Append; continue }
    $acct = Get-LocalUser -Name $u -ErrorAction SilentlyContinue
    if (-not $acct) { "NOT FOUND: $u" | Out-File $logFile -Append; continue }

    if ($PSCmdlet.ShouldProcess($u, 'Set new password')) {
        $pw = New-RandomPassword -Len $Length
        try {
            $secure = ConvertTo-SecureString $pw -AsPlainText -Force
            Set-LocalUser -Name $u -Password $secure -ErrorAction Stop
            "{0}  OK  {1}" -f (Get-Date -Format 'HH:mm:ss'), $u | Out-File $logFile -Append
            "$u`t$pw" | Out-File $secrets -Append -Encoding utf8
        } catch {
            "{0}  FAILED {1}: {2}" -f (Get-Date -Format 'HH:mm:ss'), $u, $_.Exception.Message |
                Out-File $logFile -Append
        }
    }
}

# Restrict the secrets file to Administrators and SYSTEM only
if (Test-Path $secrets) {
    icacls $secrets /inheritance:r /grant:r 'Administrators:F' 'SYSTEM:F' | Out-Null
}

Write-Host "Log: $logFile"
Write-Host "Secrets: $secrets (move to secure store, then delete)"
