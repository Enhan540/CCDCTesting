# Read-only quick triage. Findings are leads, not proof of compromise.
[CmdletBinding()]
param([string]$OutputRoot='C:\CCDC\Reports',[string]$WebRoot='C:\inetpub\wwwroot')
$dir=Join-Path $OutputRoot ("Security_{0}" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
New-Item -ItemType Directory -Path $dir -Force | Out-Null
function Collect([string]$Name,[scriptblock]$Query) {
    try { & $Query | Export-Clixml -LiteralPath (Join-Path $dir "$Name.xml") -Depth 4 }
    catch { Write-Warning "${Name}: $_" }
}
Collect 'admins' { Get-LocalGroupMember Administrators }
Collect 'users' { Get-LocalUser }
Collect 'non-microsoft-tasks' { Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } }
Collect 'services' { Get-CimInstance Win32_Service | Select-Object Name,State,StartMode,PathName,StartName }
Collect 'listeners' { Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess }
Collect 'runkeys' {
    @('HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce','HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce') |
        ForEach-Object { Get-ItemProperty -Path $_ -ErrorAction SilentlyContinue }
}
Collect 'startupfolders' {
    @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup","$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup") |
        ForEach-Object { Get-ChildItem -LiteralPath $_ -Force -ErrorAction SilentlyContinue }
}
Collect 'wmi-event-filters' { Get-CimInstance -Namespace root/subscription -ClassName __EventFilter }
Collect 'wmi-event-consumers' { Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer }
Collect 'wmi-bindings' { Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding }
Collect 'security-events' { Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625,4720,4728,4732,4740;StartTime=(Get-Date).AddHours(-24)} -MaxEvents 300 }
if (Test-Path -LiteralPath $WebRoot -PathType Container) {
    Collect 'web-recent' { Get-ChildItem -LiteralPath $WebRoot -File -Recurse -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 100 FullName,Length,LastWriteTime }
    Collect 'web-hashes' { Get-ChildItem -LiteralPath $WebRoot -File -Recurse -ErrorAction SilentlyContinue | Get-FileHash -Algorithm SHA256 }
}
Write-Output "Security audit saved: $dir. Review manually; this is not a vulnerability scanner."
