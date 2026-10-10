# Preview optional Windows CLI installations. Never installs unless -Install.
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param([switch]$Install,[string[]]$PackageIds=@('Microsoft.Sysinternals','Git.Git','Microsoft.PowerShell'))
$cmd = Get-Command winget -ErrorAction SilentlyContinue
if (-not $cmd) { Write-Warning 'winget is unavailable; use approved offline installers instead.'; return }
foreach ($id in $PackageIds) {
    if (-not $Install) { Write-Output "PREVIEW: winget install --id $id --exact"; continue }
    if ($PSCmdlet.ShouldProcess($id,'Install via winget')) {
        & winget install --id $id --exact --accept-source-agreements --accept-package-agreements
        if ($LASTEXITCODE -ne 0) { Write-Warning "winget failed for $id (exit $LASTEXITCODE)" }
    }
}
