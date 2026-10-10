<#
.SYNOPSIS
  Installs common CCDC tooling and applies baseline configuration on Windows.
.DESCRIPTION
  Installs tools via winget (Sysinternals, Notepad++, 7-Zip, Wireshark, Nmap, PuTTY, Git)
  and optionally configures a baseline (audit logging, PowerShell logging, RDP NLA).
  Every step is logged to setup_log_<timestamp>.txt in the Output folder.
  Note: tmux and most Linux CLI tools are not native to Windows. Install them in WSL
  (wsl --install) and run Setup-Environment.sh there, or use this script for the Windows side.
.EXAMPLE
  .\Setup-Environment.ps1 -ApplyBaseline
#>
[CmdletBinding()]
param(
    [string]$OutDir = 'C:\CCDC\Output',
    [switch]$SkipInstall,
    [switch]$ApplyBaseline
)

$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$log = Join-Path $OutDir ("setup_log_{0}.txt" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

function Write-Log {
    param([string]$Msg)
    "{0} {1}" -f (Get-Date -Format 'HH:mm:ss'), $Msg | Tee-Object -FilePath $log -Append
}

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell.'
}

if (-not $SkipInstall) {
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        $packages = @(
            'Microsoft.Sysinternals.ProcessExplorer',
            'Microsoft.Sysinternals.Autoruns',
            'Notepad++.Notepad++',
            '7zip.7zip',
            'WiresharkFoundation.Wireshark',
            'Insecure.Nmap',
            'PuTTY.PuTTY',
            'Git.Git'
        )
        foreach ($p in $packages) {
            Write-Log "winget install $p"
            winget install --id $p --silent --accept-package-agreements --accept-source-agreements 2>&1 |
                Out-File -FilePath $log -Append -Encoding utf8
        }
    } else {
        Write-Log 'winget not found. Install App Installer from the Microsoft Store or install tools manually.'
    }
}

if ($ApplyBaseline) {
    Write-Log 'Applying baseline configuration...'

    # Process command-line auditing (4688) and PowerShell logging
    auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable | Out-Null
    Set-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    if (-not (Test-Path 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging')) {
        New-Item 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Force | Out-Null
    }
    Set-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -Value 1 -Type DWord
    Write-Log 'Process creation auditing and PowerShell script block logging enabled.'

    # RDP: require Network Level Authentication
    Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1
    Write-Log 'RDP NLA enforced.'

    # Firewall on for all profiles
    Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True
    Write-Log 'Windows Firewall enabled on all profiles.'

    # Disable SMBv1
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue
    Write-Log 'SMBv1 disabled (server).'

    # Defender real-time protection
    Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
    Write-Log 'Defender real-time protection confirmed on.'

    Write-Log 'Baseline applied. Review each change against the scoring rules before relying on it.'
}

Write-Log "Done. Log: $log"
