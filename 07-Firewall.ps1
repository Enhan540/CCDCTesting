# Audit firewall, or explicitly add a narrowly scoped inbound TCP allow rule.
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param([ValidateSet('Audit','AllowInboundTcp')][string]$Action='Audit',[string]$Name,[ValidateRange(1,65535)][int]$Port=443,[string]$RemoteAddress)
if ($Action -eq 'Audit') {
    Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction
    Get-NetFirewallRule -Enabled True | Select-Object DisplayName,Direction,Action,Profile
    return
}
if ([string]::IsNullOrWhiteSpace($Name) -or [string]::IsNullOrWhiteSpace($RemoteAddress)) { throw 'For AllowInboundTcp, specify -Name and -RemoteAddress (IP or CIDR).' }
if ($RemoteAddress -eq 'Any' -or $RemoteAddress -eq '0.0.0.0/0' -or $RemoteAddress -eq '::/0') { throw 'Use a specific authorized source IP or CIDR; unrestricted sources are intentionally blocked.' }
if ($PSCmdlet.ShouldProcess("TCP $Port from $RemoteAddress", "Create inbound allow rule $Name")) {
    New-NetFirewallRule -DisplayName $Name -Direction Inbound -Action Allow -Protocol TCP -LocalPort $Port -RemoteAddress $RemoteAddress -Profile Any -ErrorAction Stop
    Write-Output "Created firewall rule: $Name. Verify access and review conflicting rules."
}
