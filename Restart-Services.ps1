<#
.SYNOPSIS
  Checks services against an inventory baseline and restarts any that stopped unexpectedly.
.DESCRIPTION
  Reads services.csv from an Inventory folder (produced by Get-Inventory.ps1).
  Services that were Running and set to Automatic at baseline but are now stopped
  are restarted. Results go to service_restart_<timestamp>.txt in the Output folder.
  Use -WatchMode to loop and check on an interval.
.EXAMPLE
  .\Restart-Services.ps1 -BaselineCsv C:\CCDC\Output\Inventory_HOST_20261010\services.csv
  .\Restart-Services.ps1 -BaselineCsv ... -WatchMode -IntervalSeconds 60
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$BaselineCsv,
    [string]$OutDir = 'C:\CCDC\Output',
    [string[]]$ExcludeNames = @(),
    [switch]$WatchMode,
    [int]$IntervalSeconds = 60
)

$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$outFile = Join-Path $OutDir ("service_restart_{0}.txt" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

if (-not (Test-Path $BaselineCsv)) { throw "Baseline not found: $BaselineCsv" }
$baseline = Import-Csv $BaselineCsv |
    Where-Object { $_.StartMode -eq 'Auto' -and $_.State -eq 'Running' -and $ExcludeNames -notcontains $_.Name }

"Baseline: $BaselineCsv"                                | Tee-Object -FilePath $outFile -Append
"Monitoring $($baseline.Count) auto-start services."    | Tee-Object -FilePath $outFile -Append

function Invoke-Check {
    foreach ($b in $baseline) {
        $svc = Get-Service -Name $b.Name -ErrorAction SilentlyContinue
        if (-not $svc) {
            "{0} MISSING  {1}  (service no longer exists)" -f (Get-Date -Format 'HH:mm:ss'), $b.Name |
                Tee-Object -FilePath $outFile -Append
            continue
        }
        if ($svc.Status -ne 'Running') {
            "{0} STOPPED  {1}  ({2}) status={3}" -f (Get-Date -Format 'HH:mm:ss'), $b.Name, $b.DisplayName, $svc.Status |
                Tee-Object -FilePath $outFile -Append
            try {
                Start-Service -Name $b.Name -ErrorAction Stop
                (Get-Service -Name $b.Name).Status | ForEach-Object {
                    "           restarted -> $_" | Tee-Object -FilePath $outFile -Append
                }
            } catch {
                "           FAILED: $($_.Exception.Message)" | Tee-Object -FilePath $outFile -Append
            }
        }
    }
}

if ($WatchMode) {
    while ($true) { Invoke-Check; Start-Sleep -Seconds $IntervalSeconds }
} else {
    Invoke-Check
    "Done. Results: $outFile" | Write-Host
}
