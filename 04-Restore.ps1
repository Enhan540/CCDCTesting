# Preview by default; restore requires -Apply and interactive confirmation (or -Confirm:$false).
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param([Parameter(Mandatory)][string]$BackupPath,[Parameter(Mandatory)][string]$Destination,[switch]$Apply)
$ErrorActionPreference='Stop'
$backup=(Resolve-Path -LiteralPath $BackupPath).ProviderPath
$data=Join-Path $backup 'data'; $manifestPath=Join-Path $backup 'manifest.csv'
if (-not (Test-Path -LiteralPath $data -PathType Container) -or -not (Test-Path -LiteralPath $manifestPath)) { throw 'Invalid backup directory.' }
$manifest=@(Import-Csv -LiteralPath $manifestPath)
foreach ($entry in $manifest) {
    if ([IO.Path]::IsPathRooted($entry.RelativePath) -or $entry.RelativePath -match '(^|[\\/])\.\.([\\/]|$)') { throw 'Unsafe manifest path.' }
    $file=Join-Path $data $entry.RelativePath
    if ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -ne $entry.SHA256) { throw "Backup integrity check failed: $file" }
}
if (-not $Apply) { Write-Output "PREVIEW: restore $($manifest.Count) files from $data into $Destination; existing files may be overwritten. Pass -Apply to execute."; return }
if ($PSCmdlet.ShouldProcess($Destination,"Restore files from $backup")) {
    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    & robocopy $data $Destination /E /COPY:DAT /DCOPY:DAT /R:1 /W:1 /XJ /NP | Out-Null
    if ($LASTEXITCODE -ge 8) { throw "Robocopy restore failed (exit $LASTEXITCODE)" }
    Write-Output 'Restore complete. Existing extra destination files were not deleted; validate the application before resuming service.'
}
