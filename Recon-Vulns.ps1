<#
.SYNOPSIS
  Local vulnerability and hardening check for your own Windows host.
.DESCRIPTION
  Checks for common weaknesses: missing hotfixes, SMBv1, weak SMB signing, NTLM/LM settings,
  RDP NLA, PowerShell logging, Defender state, guest account, password policy,
  unquoted service paths, and weak service permissions. Writes recon_<timestamp>.txt.
  Read-only: it does not change any setting.
.EXAMPLE
  .\Recon-Vulns.ps1
#>
[CmdletBinding()]
param(
    [string]$OutDir = 'C:\CCDC\Output'
)

$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$outFile = Join-Path $OutDir ("recon_{0}_{1}.txt" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd_HHmmss'))

function Out-Line { param($Text) $Text | Tee-Object -FilePath $outFile -Append }
function Get-Reg { param($Path, $Name) (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name }

function Add-Finding {
    param([string]$Severity, [string]$Check, [string]$Detail)
    Out-Line ("[{0,-8}] {1}: {2}" -f $Severity, $Check, $Detail)
}

Out-Line "Recon on $env:COMPUTERNAME at $(Get-Date)"
Out-Line ('=' * 70)

# 1. Patch level
$hotfixes = Get-HotFix | Sort-Object InstalledOn -Descending
$latest = $hotfixes | Select-Object -First 1
Add-Finding 'INFO' 'Latest hotfix' ("{0} installed {1}" -f $latest.HotFixID, $latest.InstalledOn)
if ($latest.InstalledOn -lt (Get-Date).AddDays(-60)) {
    Add-Finding 'HIGH' 'Patching' 'No hotfix in the last 60 days. Check Windows Update.'
}

# 2. SMB
$smb = Get-SmbServerConfiguration
if ($smb.EnableSMB1Protocol) { Add-Finding 'HIGH' 'SMBv1' 'SMBv1 server is enabled' }
else { Add-Finding 'OK' 'SMBv1' 'disabled' }
if (-not $smb.RequireSecuritySignature) { Add-Finding 'MED' 'SMB signing' 'not required' }
else { Add-Finding 'OK' 'SMB signing' 'required' }

# 3. NTLM / LM
$lmLevel = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel'
if ($null -eq $lmLevel -or $lmLevel -lt 5) {
    Add-Finding 'MED' 'LM/NTLM' "LmCompatibilityLevel=$lmLevel (5 = NTLMv2 only)"
} else { Add-Finding 'OK' 'LM/NTLM' "LmCompatibilityLevel=$lmLevel" }

# 4. RDP
$nla = Get-Reg 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
$rdpDeny = Get-Reg 'HKLM:\System\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
if ($rdpDeny -eq 0) {
    if ($nla -ne 1) { Add-Finding 'HIGH' 'RDP NLA' 'RDP is on and NLA is not enforced' }
    else { Add-Finding 'OK' 'RDP NLA' 'enforced' }
} else { Add-Finding 'INFO' 'RDP' 'disabled' }

# 5. Guest and built-in accounts
$guest = Get-LocalUser -Name Guest -ErrorAction SilentlyContinue
if ($guest -and $guest.Enabled) { Add-Finding 'HIGH' 'Guest account' 'enabled' }
else { Add-Finding 'OK' 'Guest account' 'disabled or absent' }

$admin = Get-LocalUser -Name Administrator -ErrorAction SilentlyContinue
if ($admin -and $admin.Enabled) { Add-Finding 'MED' 'Administrator' 'built-in Administrator is enabled' }

# 6. Password policy
$pol = net accounts
$minLen = ($pol | Select-String 'Minimum password length').ToString().Split()[-1]
Add-Finding 'INFO' 'Min password length' $minLen
$lockout = ($pol | Select-String 'Lockout threshold').ToString().Split()[-1]
Add-Finding 'INFO' 'Lockout threshold' $lockout

# 7. Logging
$psLog = Get-Reg 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging'
if ($psLog -eq 1) { Add-Finding 'OK' 'PS script block logging' 'on' }
else { Add-Finding 'MED' 'PS script block logging' 'off' }

$sec = (Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue)
if ($sec) { Add-Finding 'INFO' 'Security log size' ("{0} MB, max {1} MB" -f [math]::Round($sec.FileSize/1MB,1), [math]::Round($sec.MaximumSizeInBytes/1MB,1)) }

# 8. Defender
$mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
if ($mp) {
    if ($mp.RealTimeProtectionEnabled) { Add-Finding 'OK' 'Defender real-time' 'on' }
    else { Add-Finding 'HIGH' 'Defender real-time' 'OFF' }
    Add-Finding 'INFO' 'Defender signatures' ("updated {0}" -f $mp.AntivirusSignatureLastUpdated)
}

# 9. Unquoted service paths
Get-CimInstance Win32_Service | Where-Object {
    $_.PathName -and $_.PathName -notmatch '^"' -and $_.PathName -match '\s' -and $_.PathName -notmatch '^[A-Za-z]:\\Windows\\'
} | ForEach-Object {
    Add-Finding 'MED' 'Unquoted service path' ("{0}: {1}" -f $_.Name, $_.PathName)
}

# 10. Writable service binaries (simple check: Users/Everyone can modify)
Get-CimInstance Win32_Service | Where-Object { $_.PathName } | ForEach-Object {
    $exe = ($_.PathName -replace '"','').Split(' ')[0]
    if (Test-Path $exe) {
        $acl = Get-Acl $exe -ErrorAction SilentlyContinue
        $weak = $acl.Access | Where-Object {
            $_.IdentityReference -match 'Everyone|Users|Authenticated Users' -and
            $_.FileSystemRights -match 'Write|Modify|FullControl'
        }
        if ($weak) { Add-Finding 'HIGH' 'Writable service binary' ("{0}: {1}" -f $_.Name, $exe) }
    }
}

# 11. Listening ports for review
Out-Line "`n--- Listening TCP ports ---"
Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess |
    Sort-Object LocalPort | Format-Table -AutoSize | Out-String | Tee-Object -FilePath $outFile -Append

Out-Line "`nDone. Results: $outFile"
Write-Host "Results: $outFile"
