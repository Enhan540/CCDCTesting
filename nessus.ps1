# Installs Tenable Nessus on supported 64-bit Windows systems.
# Download the official Nessus Windows installer from Tenable before running this script.
[CmdletBinding()]
param(
    [Parameter()]
    [string]$InstallerPath
)

$ErrorActionPreference = 'Stop'
$officialDownloads = 'https://www.tenable.com/downloads/nessus'

# Require an elevated PowerShell session because Nessus installs a Windows service.
$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($currentIdentity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run PowerShell as Administrator, then run this script again.'
}

if (-not $InstallerPath) {
    Start-Process $officialDownloads
    Write-Host 'Download the Windows x64 Nessus installer from the official Tenable page.'
    $InstallerPath = Read-Host 'Enter the full path to the downloaded .msi file'
}

if (-not (Test-Path -LiteralPath $InstallerPath -PathType Leaf)) {
    throw "Installer not found: $InstallerPath"
}
if ([IO.Path]::GetExtension($InstallerPath) -ne '.msi') {
    throw 'Expected the official Windows .msi installer. No other file type will be run.'
}

# Check the digital signature before launching the installer.
$signature = Get-AuthenticodeSignature -LiteralPath $InstallerPath
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'Tenable') {
    throw "Installer signature is not valid or is not signed by Tenable. Status: $($signature.Status)"
}

Write-Host 'Starting the signed Tenable Nessus installer. Complete the installer wizard.'
Start-Process -FilePath 'msiexec.exe' -ArgumentList @('/i', ('"{0}"' -f $InstallerPath)) -Wait

Write-Host ''
Write-Host 'When installation finishes, complete Essentials registration in the Nessus browser setup:'
Write-Host '  1. Choose Register for Nessus Essentials.'
Write-Host '  2. Get an activation code from Tenable (or enter one you already have).'
Write-Host '  3. Create the local Nessus administrator account.'
Write-Host 'The local web interface is https://localhost:8834'
$openUi = Read-Host 'Open the Nessus setup page now? [Y/n]'
if ($openUi -notmatch '^(n|no)$') {
    Start-Process 'https://localhost:8834'
}
