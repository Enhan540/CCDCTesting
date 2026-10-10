<#
.SYNOPSIS
  Inventory of a Windows host: ports, services, users, software, tasks, persistence, shares, firewall.
.DESCRIPTION
  Writes one .txt per section into OutDir\Inventory_<host>_<timestamp>\.
  Also writes services.csv, which Restart-Services.ps1 uses as its baseline.
  Run from an elevated PowerShell (Administrator).
.EXAMPLE
  .\Get-Inventory.ps1 -OutDir C:\CCDC\Output
#>
[CmdletBinding()]
param(
    [string]$OutDir = 'C:\CCDC\Output'
)

$ErrorActionPreference = 'Continue'
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$dir   = Join-Path $OutDir ("Inventory_{0}_{1}" -f $env:COMPUTERNAME, $stamp)
New-Item -ItemType Directory -Path $dir -Force | Out-Null

function Save-Section {
    param([string]$Name, [scriptblock]$Block)
    $file = Join-Path $dir "$Name.txt"
    try   { & $Block 2>&1 | Out-String -Width 4096 | Out-File -FilePath $file -Encoding utf8 }
    catch { "ERROR: $($_.Exception.Message)" | Out-File -FilePath $file -Encoding utf8 }
    Write-Host "[+] $Name"
}

function Get-PortOwner {
    param($Conn)
    [pscustomobject]@{
        Address = $Conn.LocalAddress
        Port    = $Conn.LocalPort
        PID     = $Conn.OwningProcess
        Process = (Get-Process -Id $Conn.OwningProcess -ErrorAction SilentlyContinue).ProcessName
    }
}

Save-Section 'system' {
    Get-ComputerInfo -Property CsName, WindowsProductName, WindowsVersion, OsBuildNumber, CsDomain, CsDomainRole
    '--- ipconfig /all ---'
    ipconfig /all
}

Save-Section 'ports_tcp_listening' {
    Get-NetTCPConnection -State Listen | ForEach-Object { Get-PortOwner $_ } |
        Sort-Object Port | Format-Table -AutoSize
}

Save-Section 'ports_udp_endpoints' {
    Get-NetUDPEndpoint | ForEach-Object { Get-PortOwner $_ } |
        Sort-Object Port | Format-Table -AutoSize
}

$svc = Get-CimInstance Win32_Service | Select-Object Name, DisplayName, State, StartMode, StartName, PathName
$svc | Export-Csv -Path (Join-Path $dir 'services.csv') -NoTypeInformation
Save-Section 'services' {
    $svc | Sort-Object Name | Format-Table Name, State, StartMode, StartName -AutoSize
    '--- binary paths ---'
    $svc | Sort-Object Name | Format-List Name, PathName
}

Save-Section 'local_users' {
    Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, PasswordRequired, PasswordExpires, Description |
        Format-Table -AutoSize
}

Save-Section 'local_group_members' {
    Get-LocalGroup | ForEach-Object {
        "== $($_.Name) =="
        Get-LocalGroupMember -Group $_.Name -ErrorAction SilentlyContinue | Format-Table Name, ObjectClass -AutoSize
    }
}

Save-Section 'domain_users' {
    if (Get-Command Get-ADUser -ErrorAction SilentlyContinue) {
        Get-ADUser -Filter * -Properties Enabled, LastLogonDate, PasswordLastSet |
            Select-Object SamAccountName, Enabled, LastLogonDate, PasswordLastSet | Format-Table -AutoSize
    } else {
        'ActiveDirectory module not available (not a DC, or RSAT not installed).'
    }
}

Save-Section 'logged_on_sessions' { quser }

Save-Section 'installed_software' {
    Get-ItemProperty -Path @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    ) -ErrorAction SilentlyContinue |
        Where-Object DisplayName |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
        Sort-Object DisplayName | Format-Table -Wrap
}

Save-Section 'scheduled_tasks_enabled' {
    Get-ScheduledTask | Where-Object State -ne 'Disabled' | ForEach-Object {
        [pscustomobject]@{
            Path   = $_.TaskPath
            Name   = $_.TaskName
            RunAs  = $_.Principal.UserId
            Action = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' ; '
        }
    } | Format-Table -Wrap
}

Save-Section 'autorun_keys' {
    $keys = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    foreach ($k in $keys) {
        "== $k"
        Get-ItemProperty -Path $k -ErrorAction SilentlyContinue | Format-List
    }
    '== Winlogon (Shell / Userinit)'
    Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' | Select-Object Shell, Userinit
}

Save-Section 'smb_shares' { Get-SmbShare | Format-Table Name, Path, Description -AutoSize }

Save-Section 'firewall_profiles' {
    Get-NetFirewallProfile | Format-Table Name, Enabled, DefaultInboundAction, DefaultOutboundAction -AutoSize
}

Save-Section 'hosts_file' { Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" }

Save-Section 'installed_roles_features' {
    if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
        Get-WindowsFeature | Where-Object Installed | Format-Table Name, DisplayName -AutoSize
    } else {
        'Get-WindowsFeature not available (client OS).'
    }
}

Write-Host "`nInventory complete: $dir"
