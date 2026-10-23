# Rotate one existing LOCAL user's password. Does not touch domain accounts.
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param([Parameter(Mandatory)][string]$UserName)
$ErrorActionPreference='Stop'
$user=Get-LocalUser -Name $UserName -ErrorAction Stop
Write-Warning 'Changing a service account password may break scheduled tasks, IIS app pools, or Windows services. Confirm dependencies first.'
$secret=Read-Host "Enter NEW password for local user $($user.Name)" -AsSecureString
if ($PSCmdlet.ShouldProcess($user.Name,'Rotate local account password')) {
    Set-LocalUser -Name $user.Name -Password $secret -ErrorAction Stop
    Write-Output "Password updated for $($user.Name). Store the secret in an approved password manager; no password was logged."
}
