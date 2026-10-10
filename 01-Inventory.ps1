# Read-only Windows inventory. Run elevated for fuller results.
[CmdletBinding()]
param([string]$OutputRoot = 'C:\CCDC\Reports')
$ErrorActionPreference = 'Stop'
$dir = Join-Path $OutputRoot ("Inventory_{0}_{1}" -f $env:COMPUTERNAME,(Get-Date -Format 'yyyyMMdd_HHmmss'))
New-Item -ItemType Directory -Path $dir -Force | Out-Null
function Save-Report {
    param([string]$Name,[scriptblock]$Query)
    try {
        & $Query | Export-Clixml -LiteralPath (Join-Path $dir "$Name.xml") -Depth 4
        Write-Verbose "Saved $Name"
    } catch { Write-Warning "Unable to collect ${Name}: $_" }
}
Save-Report 'computer' { Get-ComputerInfo }
Save-Report 'ipconfig' { Get-NetIPConfiguration }
Save-Report 'addresses' { Get-NetIPAddress }
Save-Report 'routes' { Get-NetRoute }
Save-Report 'dns' { Get-DnsClientServerAddress }
Save-Report 'localusers' { Get-LocalUser }
Save-Report 'localgroups' { Get-LocalGroup }
Save-Report 'administrators' { Get-LocalGroupMember -Group 'Administrators' }
Save-Report 'services' { Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,PathName,StartName }
Save-Report 'processes' { Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine }
Save-Report 'tcp' { Get-NetTCPConnection }
Save-Report 'udp' { Get-NetUDPEndpoint }
Save-Report 'shares' { Get-SmbShare }
Save-Report 'firewallprofiles' { Get-NetFirewallProfile }
Save-Report 'firewallrules' { Get-NetFirewallRule }
Save-Report 'firewallports' { Get-NetFirewallPortFilter }
Save-Report 'firewalladdresses' { Get-NetFirewallAddressFilter }
Save-Report 'scheduledtasks' { Get-ScheduledTask }
Save-Report 'startup' { Get-CimInstance Win32_StartupCommand }
Save-Report 'installedsoftware' {
    @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') |
        ForEach-Object { Get-ItemProperty $_ -ErrorAction SilentlyContinue } |
        Where-Object DisplayName | Select-Object DisplayName,DisplayVersion,Publisher,InstallDate
}
Save-Report 'recent-system-events' { Get-WinEvent -FilterHashtable @{LogName='System';StartTime=(Get-Date).AddHours(-12)} -MaxEvents 250 }
Save-Report 'recent-security-events' { Get-WinEvent -FilterHashtable @{LogName='Security';StartTime=(Get-Date).AddHours(-12)} -MaxEvents 250 }
"Host=$env:COMPUTERNAME`nCreated=$(Get-Date -Format o)`nOutput=$dir" | Set-Content -LiteralPath (Join-Path $dir 'README.txt')
Write-Output "Inventory saved: $dir (CLIXML; use Import-Clixml to review)"
