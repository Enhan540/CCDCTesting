# Copies a chosen directory into a timestamped backup with a SHA256 manifest.
[CmdletBinding()]
param([Parameter(Mandatory)][string]$SourcePath,[string]$BackupRoot='C:\CCDC\Backups')
$ErrorActionPreference='Stop'
$source=(Resolve-Path -LiteralPath $SourcePath).ProviderPath
if (-not (Test-Path -LiteralPath $source -PathType Container)) { throw 'Source must be a directory.' }
New-Item -ItemType Directory -Path $BackupRoot -Force | Out-Null
$destination=Join-Path $BackupRoot ("{0}_{1}" -f ((Split-Path $source -Leaf) -replace '[^a-zA-Z0-9_-]','_'),(Get-Date -Format 'yyyyMMdd_HHmmss_ffff'))
New-Item -ItemType Directory -Path $destination | Out-Null
$data=Join-Path $destination 'data'
New-Item -ItemType Directory -Path $data | Out-Null
& robocopy $source $data /E /COPY:DAT /DCOPY:DAT /R:1 /W:1 /XJ /NP | Out-Null
$code=$LASTEXITCODE
if ($code -ge 8) { throw "Robocopy failed (exit code $code); inspect $destination" }
$files=Get-ChildItem -LiteralPath $data -File -Recurse -Force
$manifest=@($files | ForEach-Object {
    [pscustomobject]@{ RelativePath=$_.FullName.Substring($data.Length).TrimStart('\'); SHA256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }
})
$manifest | Export-Csv -LiteralPath (Join-Path $destination 'manifest.csv') -NoTypeInformation
[pscustomobject]@{ Source=$source;Created=(Get-Date).ToString('o');FileCount=$manifest.Count } |
    ConvertTo-Json | Set-Content -LiteralPath (Join-Path $destination 'metadata.json')
Write-Output "Backup complete: $destination ($($manifest.Count) files). Protect this backup from unauthorized access."
