<#
.SYNOPSIS
  Create or restore backups of key Windows config: registry hives, firewall, hosts, services, scheduled tasks, IIS/DNS if present.
.DESCRIPTION
  -Action Create   : writes a timestamped backup folder and a manifest.txt (with SHA256 hashes).
  -Action Restore  : restores from a named backup folder (prompts for confirmation unless -Force).
  Log output goes to <BackupRoot>\backup_log.txt.
.EXAMPLE
  .\Backup-Config.ps1 -Action Create
  .\Backup-Config.ps1 -Action Restore -BackupPath C:\CCDC\Backups\Backup_20261010_120000 -Force
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Create', 'Restore')][string]$Action,
    [string]$BackupRoot = 'C:\CCDC\Backups',
    [string]$BackupPath,
    [switch]$Force
)

$ErrorActionPreference = 'Continue'
$log = Join-Path $BackupRoot 'backup_log.txt'
New-Item -ItemType Directory -Path $BackupRoot -Force | Out-Null

function Write-Log {
    param([string]$Msg)
    $line = "{0} {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Msg
    $line | Tee-Object -FilePath $log -Append
}

function New-Backup {
    $dest = Join-Path $BackupRoot ("Backup_{0}_{1}" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd_HHmmss'))
    New-Item -ItemType Directory -Path $dest -Force | Out-Null
    Write-Log "Creating backup: $dest"

    # Registry hives
    $hives = @{
        'HKLM_SOFTWARE' = 'HKLM\SOFTWARE'
        'HKLM_SYSTEM'   = 'HKLM\SYSTEM'
        'HKLM_SAM'      = 'HKLM\SAM'
        'HKLM_SECURITY' = 'HKLM\SECURITY'
    }
    foreach ($name in $hives.Keys) {
        $out = Join-Path $dest "$name.hiv"
        reg.exe save $hives[$name] $out /y | Out-Null
        Write-Log ("reg save {0}: exit {1}" -f $hives[$name], $LASTEXITCODE)
    }

    # Firewall policy
    $fw = Join-Path $dest 'firewall_policy.wfw'
    netsh.exe advfirewall export $fw | Out-Null
    Write-Log "Firewall exported: $fw"

    # Files
    $files = @(
        "$env:SystemRoot\System32\drivers\etc\hosts",
        "$env:SystemRoot\System32\drivers\etc\services"
    )
    foreach ($f in $files) {
        if (Test-Path $f) { Copy-Item $f -Destination $dest -Force; Write-Log "Copied $f" }
    }

    # Services and scheduled tasks
    Get-CimInstance Win32_Service | Export-Csv (Join-Path $dest 'services.csv') -NoTypeInformation
    Get-ScheduledTask | Export-Clixml (Join-Path $dest 'scheduled_tasks.xml')
    Write-Log 'Services and scheduled tasks exported.'

    # IIS (if installed)
    if (Get-Command Get-WebSite -ErrorAction SilentlyContinue) {
        $appcmd = "$env:SystemRoot\System32\inetsrv\appcmd.exe"
        & $appcmd add backup ("CCDC_" + (Get-Date -Format 'yyyyMMddHHmmss')) | Out-Null
        Copy-Item "$env:SystemRoot\System32\inetsrv\config" (Join-Path $dest 'iis_config') -Recurse -Force
        Write-Log 'IIS config copied.'
    }

    # DNS (if DNS server role present)
    if (Get-Command Export-DnsServerZone -ErrorAction SilentlyContinue) {
        Get-DnsServerZone | ForEach-Object {
            Export-DnsServerZone -Name $_.ZoneName -FileName "$($_.ZoneName).dns" -ErrorAction SilentlyContinue
        }
        Write-Log 'DNS zones exported to the DNS server data folder (copy from %SystemRoot%\System32\dns).'
    }

    # Manifest with hashes
    $manifest = Join-Path $dest 'manifest.txt'
    Get-ChildItem $dest -File | Where-Object Name -ne 'manifest.txt' | ForEach-Object {
        $h = Get-FileHash $_.FullName -Algorithm SHA256
        "{0}  {1}" -f $h.Hash, $_.Name
    } | Out-File $manifest -Encoding utf8
    Write-Log "Manifest written: $manifest"
    Write-Log "Backup complete: $dest"
}

function Restore-Backup {
    if (-not $BackupPath -or -not (Test-Path $BackupPath)) {
        throw "BackupPath is missing or does not exist: $BackupPath"
    }
    Write-Log "Restore requested from: $BackupPath"
    if (-not $Force) {
        $ans = Read-Host 'This will overwrite live config. Type YES to continue'
        if ($ans -ne 'YES') { Write-Log 'Restore cancelled by user.'; return }
    }

    # Verify hashes first
    $manifest = Join-Path $BackupPath 'manifest.txt'
    if (Test-Path $manifest) {
        foreach ($line in Get-Content $manifest) {
            $hash, $name = $line -split '\s{2}', 2
            $current = (Get-FileHash (Join-Path $BackupPath $name) -Algorithm SHA256).Hash
            if ($current -ne $hash) { Write-Log "HASH MISMATCH: $name (aborting)"; throw "Integrity check failed for $name" }
        }
        Write-Log 'Manifest hashes verified.'
    }

    # Firewall
    $fw = Join-Path $BackupPath 'firewall_policy.wfw'
    if (Test-Path $fw) { netsh.exe advfirewall import $fw | Out-Null; Write-Log 'Firewall policy imported.' }

    # Hosts file
    $hosts = Join-Path $BackupPath 'hosts'
    if (Test-Path $hosts) {
        Copy-Item $hosts "$env:SystemRoot\System32\drivers\etc\hosts" -Force
        Write-Log 'hosts restored.'
    }

    # Registry hives: reg restore only works for hives that are not in use, so this is a
    # guided step. Hives are NOT loaded automatically to avoid breaking the running system.
    Get-ChildItem $BackupPath -Filter '*.hiv' | ForEach-Object {
        Write-Log "Hive available for manual restore: $($_.Name) (use reg.exe restore or boot recovery)."
    }
    Write-Log 'Restore complete (registry hives require manual handling; see log).'
}

switch ($Action) {
    'Create'  { New-Backup }
    'Restore' { Restore-Backup }
}
