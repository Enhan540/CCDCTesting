# Check selected services. Restart only with -RestartStopped and explicit confirmation.
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param([Parameter(Mandatory)][string[]]$Names,[switch]$RestartStopped)
foreach ($name in $Names) {
    try {
        $svc=Get-Service -Name $name -ErrorAction Stop
        if ($svc.Status -eq 'Running') { Write-Output "$name RUNNING"; continue }
        Write-Warning "$name status: $($svc.Status)"
        if ($RestartStopped -and $PSCmdlet.ShouldProcess($name,'Start stopped service')) {
            Start-Service -Name $name -ErrorAction Stop
            Write-Output "$name now $((Get-Service -Name $name).Status)"
        }
    } catch { Write-Warning "Unable to check/start ${name}: $_" }
}
