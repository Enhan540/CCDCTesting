#requires -Version 5.1
<##
.SYNOPSIS
  Barebones scoped firewall policy for a CCDC Active Directory domain controller.

.DESCRIPTION
  Runs without parameters. It detects the primary IPv4 subnet, creates the
  barebones AD rules, verifies them, and disables other enabled local inbound
  rules after verification.
#>
[CmdletBinding()]
param()

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'Administrator privileges are required. Relaunching with elevation...' -ForegroundColor Yellow
    $child = Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',("`"{0}`"" -f $PSCommandPath)) -Wait -PassThru
    exit $child.ExitCode
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$scriptPrefix = 'CCDC-DC-Barebones-'
$ruleGroup = 'CCDC DC Barebones'
$dryRun = $false
$backupDirectory = 'C:\CCDC\FirewallBackups'
$beforeBackup = $null

function Write-Step([int]$Number, [string]$Text) {
    Write-Host ("`n[{0}/9] {1}" -f $Number, $Text) -ForegroundColor Cyan
}

function ConvertTo-IPv4Bytes([string]$Address) {
    $ip = $null
    if (-not [Net.IPAddress]::TryParse($Address, [ref]$ip) -or
        $ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
        throw "Invalid IPv4 address: $Address"
    }
    return $ip.GetAddressBytes()
}

function ConvertTo-PrefixLength([string]$Mask) {
    $bytes = ConvertTo-IPv4Bytes $Mask
    $prefix = 0
    $seenZero = $false
    foreach ($byte in $bytes) {
        for ($bit = 7; $bit -ge 0; $bit--) {
            if (($byte -band (1 -shl $bit)) -ne 0) {
                if ($seenZero) { throw "Non-contiguous IPv4 netmask: $Mask" }
                $prefix++
            } else { $seenZero = $true }
        }
    }
    return $prefix
}

function ConvertTo-NetworkCidr([string]$Address, [int]$PrefixLength) {
    $bytes = ConvertTo-IPv4Bytes $Address
    if ($PrefixLength -lt 1 -or $PrefixLength -gt 32) {
        throw "IPv4 prefix must be between /1 and /32: /$PrefixLength"
    }
    $remaining = $PrefixLength
    for ($i = 0; $i -lt 4; $i++) {
        $bits = [Math]::Max(0, [Math]::Min(8, $remaining))
        $mask = 0
        if ($bits -ne 0) { $mask = (0xFF -shl (8 - $bits)) -band 0xFF }
        $bytes[$i] = [byte]($bytes[$i] -band $mask)
        $remaining -= $bits
    }
    return "{0}.{1}.{2}.{3}/{4}" -f $bytes[0],$bytes[1],$bytes[2],$bytes[3],$PrefixLength
}

function ConvertTo-CanonicalScope([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) { return $Value }
    if ($Value -eq 'Any') { return 'Any' }
    $parts = $Value.Split('/')
    $bytes = ConvertTo-IPv4Bytes $parts[0]
    if ($parts.Count -eq 1) { return ("{0}.{1}.{2}.{3}" -f $bytes[0],$bytes[1],$bytes[2],$bytes[3]) }
    $prefix = 0
    if (-not [int]::TryParse($parts[1], [ref]$prefix)) { $prefix = ConvertTo-PrefixLength $parts[1] }
    return ConvertTo-NetworkCidr $parts[0] $prefix
}

function Get-CanonicalSet([object]$Values) {
    return @($Values | ForEach-Object { ConvertTo-CanonicalScope ([string]$_) } | Sort-Object -Unique)
}

function Resolve-Subnet {
    $routes = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
        Sort-Object RouteMetric, InterfaceMetric)
    if ($routes.Count -eq 0) { throw 'No active IPv4 default route was found.' }
    $bestMetric = "{0}:{1}" -f $routes[0].RouteMetric, $routes[0].InterfaceMetric
    $best = @($routes | Where-Object { ("{0}:{1}" -f $_.RouteMetric,$_.InterfaceMetric) -eq $bestMetric })
    $interfaces = @($best | Select-Object -ExpandProperty InterfaceIndex -Unique)
    if ($interfaces.Count -ne 1) { throw 'Primary IPv4 adapter is ambiguous; cannot continue safely.' }
    $config = Get-NetIPConfiguration -InterfaceIndex $interfaces[0] -ErrorAction Stop
    $ipv4 = @($config.IPv4Address)
    if ($ipv4.Count -ne 1) { throw 'Primary adapter does not have exactly one IPv4 address.' }
    return ConvertTo-NetworkCidr $ipv4[0].IPv4Address ([int]$ipv4[0].PrefixLength)
}

function Assert-IPv4Scopes([string[]]$Values, [string]$Label) {
    foreach ($value in $Values) {
        $null = ConvertTo-CanonicalScope $value
        if ((ConvertTo-CanonicalScope $value) -eq '0.0.0.0/0') { throw "$Label cannot contain /0." }
    }
}

function Get-ReportSortKey([string]$LocalPort) {
    $match = [regex]::Match($LocalPort, '\d+')
    if ($match.Success) { return [int]$match.Value }
    return [int]::MaxValue
}

function Format-RuleName([string]$Name) {
    if ($Name.Length -le 15) { return $Name }
    return $Name.Substring(0, 12) + '...'
}

function Write-FirewallReport([string]$Path, [object[]]$Rules) {
    $rows = @($Rules | Sort-Object SortKey, Name, Protocol)
    $localWidth = [Math]::Max(15, (($rows | ForEach-Object { ([string]$_.LocalAddress).Length } | Measure-Object -Maximum).Maximum))
    $remoteWidth = [Math]::Max(15, (($rows | ForEach-Object { ([string]$_.RemoteAddress).Length } | Measure-Object -Maximum).Maximum))
    $format = "{0,-15}  {1,-9}  {2,-12}  {3,-13}  {4,-$localWidth}  {5}"
    $header = $format -f 'Rule Name','Protocol','Local Port','Remote Port','Local Address','Remote Address'
    $separator = '-' * $header.Length
    $title = ' FIREWALL RULES '
    $title = $title.PadLeft([int](($header.Length + $title.Length) / 2)).PadRight($header.Length)
    $lines = @('','=' * $header.Length,$title,'',$header,$separator)
    foreach ($row in $rows) {
        $lines += ($format -f (Format-RuleName $row.Name),$row.Protocol,$row.LocalPort,$row.RemotePort,$row.LocalAddress,$row.RemoteAddress)
    }
    $lines | Set-Content -LiteralPath $Path -Encoding UTF8 -ErrorAction Stop
}

function Get-RuleReport {
    foreach ($rule in @(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -ErrorAction Stop)) {
        $port = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop
        $address = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop
        $localPort = if ([string]$port.Protocol -ieq 'ICMPv4') {
            'type:' + (@($port.IcmpType) -join ',')
        } else {
            @($port.LocalPort) -join ','
        }
        [pscustomobject]@{
            Name = [string]$rule.Name
            Protocol = [string]$port.Protocol
            LocalPort = $localPort
            RemotePort = @($port.RemotePort) -join ','
            LocalAddress = @($address.LocalAddress) -join ','
            RemoteAddress = @($address.RemoteAddress) -join ','
            SortKey = Get-ReportSortKey $localPort
        }
    }
}

function Write-RuleReport([string]$Path, [object[]]$Rules) {
    Write-FirewallReport $Path $Rules
}

function Export-Policy([string]$Directory, [string]$BaseName, [object[]]$Rules) {
    New-Item -ItemType Directory -Path $Directory -Force -ErrorAction Stop | Out-Null
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
    $wfw = Join-Path $Directory "$BaseName-$stamp.wfw"
    $txt = Join-Path $Directory "$BaseName-$stamp.txt"
    if ((Test-Path -LiteralPath $wfw) -or (Test-Path -LiteralPath $txt)) { throw "Refusing to overwrite backup: $wfw" }
    & netsh.exe advfirewall export $wfw | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $wfw) -or (Get-Item -LiteralPath $wfw).Length -le 0) {
        throw "Firewall export failed: $wfw"
    }
    Write-RuleReport $txt $Rules
    if ((Get-Item -LiteralPath $txt).Length -le 0) { throw "Rule report failed: $txt" }
    [pscustomobject]@{ Wfw = $wfw; Txt = $txt }
}

function New-ADSpec([string]$Suffix, [string]$Protocol, [string]$Port, [string[]]$Remote) {
    [pscustomobject]@{ Name = "$scriptPrefix$Suffix"; DisplayName = "CCDC DC Barebones $Suffix"; Protocol = $Protocol; LocalPort = $Port; Remote = @($Remote) }
}

function Assert-CreatedRule($Spec) {
    $rule = @(Get-NetFirewallRule -PolicyStore PersistentStore -Name $Spec.Name -ErrorAction SilentlyContinue)
    if ($rule.Count -ne 1) { throw "Verification failed for $($Spec.Name): rule does not exist exactly once." }
    $r = $rule[0]
    $fail = @()
    if ([string]$r.Enabled -ne 'True') { $fail += 'Enabled=True' }
    if ([string]$r.Direction -ne 'Inbound') { $fail += 'Direction=Inbound' }
    if ([string]$r.Action -ne 'Allow') { $fail += 'Action=Allow' }
    $port = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $r -ErrorAction Stop
    $address = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $r -ErrorAction Stop
    if ([string]$port.Protocol -ine $Spec.Protocol) { $fail += "Protocol=$($Spec.Protocol)" }
    if ((@($port.LocalPort) -join ',') -ne $Spec.LocalPort) { $fail += "LocalPort=$($Spec.LocalPort)" }
    $actual = (Get-CanonicalSet $address.RemoteAddress) -join ','
    $expected = (Get-CanonicalSet $Spec.Remote) -join ','
    if ($actual -ne $expected) { $fail += "RemoteAddress=$expected (actual $actual)" }
    if ($fail.Count -gt 0) { throw "Verification failed for $($Spec.Name): $($fail -join '; ')" }
}

try {
    Write-Step 1 'Check administrator privileges and firewall cmdlets'
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run as Administrator.' }
    foreach ($command in @('Get-NetFirewallRule','New-NetFirewallRule','Remove-NetFirewallRule','Set-NetFirewallRule','Get-NetFirewallProfile','Set-NetFirewallProfile')) {
        if (-not (Get-Command $command -ErrorAction SilentlyContinue)) { throw "Required firewall cmdlet is unavailable: $command" }
    }

    $subnetValue = Resolve-Subnet
    $remoteScope = @($subnetValue)
    $specs = @(
        (New-ADSpec 'TCP-53' 'TCP' '53' $remoteScope); (New-ADSpec 'UDP-53' 'UDP' '53' $remoteScope)
        (New-ADSpec 'TCP-88' 'TCP' '88' $remoteScope); (New-ADSpec 'UDP-88' 'UDP' '88' $remoteScope)
        (New-ADSpec 'TCP-389' 'TCP' '389' $remoteScope); (New-ADSpec 'UDP-389' 'UDP' '389' $remoteScope)
        (New-ADSpec 'TCP-464' 'TCP' '464' $remoteScope); (New-ADSpec 'UDP-464' 'UDP' '464' $remoteScope)
        (New-ADSpec 'TCP-445' 'TCP' '445' $remoteScope); (New-ADSpec 'TCP-135' 'TCP' '135' $remoteScope)
        (New-ADSpec 'TCP-RPC-Dynamic' 'TCP' '49152-65535' $remoteScope); (New-ADSpec 'UDP-123' 'UDP' '123' $remoteScope)
        (New-ADSpec 'TCP-3268' 'TCP' '3268' $remoteScope)
    )

    Write-Step 2 'Back up original firewall configuration'
    $beforeRules = @(Get-RuleReport)
    $beforeBackup = Export-Policy $backupDirectory 'firewall-before' $beforeRules
    Write-Host "Before backup: $($beforeBackup.Wfw)" -ForegroundColor Green
    Write-Host "Before report: $($beforeBackup.Txt)" -ForegroundColor Green

    Write-Step 3 'Enable Domain, Private, and Public firewall profiles'
    Set-NetFirewallProfile -Name Domain,Private,Public -Enabled True -Confirm:$false -ErrorAction Stop

    Write-Step 4 'Record enabled firewall rules'
    Write-Host ("Detected subnet: {0}" -f $subnetValue) -ForegroundColor Gray
    Write-Host ("Remote scope: {0}" -f ($remoteScope -join ', ')) -ForegroundColor Gray
    Write-Host ("Enabled rules found: {0}" -f $beforeRules.Count) -ForegroundColor Gray

    Write-Step 5 'Detect primary IPv4 subnet'
    Write-Host "Using subnet: $subnetValue" -ForegroundColor Green

    Write-Step 6 'Create inbound AD allow rules'
    foreach ($spec in $specs) {
        $existing = @(Get-NetFirewallRule -PolicyStore PersistentStore -Name $spec.Name -ErrorAction SilentlyContinue)
        if ($existing.Count -gt 0) { throw "Rule already exists: $($spec.Name). Restore the before backup or remove it manually before retrying." }
        New-NetFirewallRule -PolicyStore PersistentStore -Name $spec.Name -DisplayName $spec.DisplayName -Group $ruleGroup -Enabled True -Direction Inbound -Action Allow -Profile Any -Protocol $spec.Protocol -LocalPort $spec.LocalPort -LocalAddress Any -RemoteAddress $spec.Remote -RemotePort Any -Program Any -Service Any -Confirm:$false -ErrorAction Stop | Out-Null
    }

    Write-Step 7 'Verify every created rule'
    foreach ($spec in $specs) { Assert-CreatedRule $spec }
    Write-Host 'All created rules verified.' -ForegroundColor Green

    Write-Step 8 'Optionally disable other local inbound rules'
    Write-Warning 'Disabling other enabled local inbound rules can interrupt AD replication, remote management, and CCDC scoring.'
    $created = @($specs | ForEach-Object { $_.Name })
    $targets = @(Get-NetFirewallRule -PolicyStore PersistentStore -Direction Inbound -Enabled True -ErrorAction Stop |
        Where-Object { $created -notcontains $_.Name })
    Write-Host ("Local inbound rules to disable: {0}" -f $targets.Count) -ForegroundColor Yellow
    if ($targets.Count -gt 0) {
        $targets | Set-NetFirewallRule -Enabled False -Confirm:$false -ErrorAction Stop
        Write-Host 'Other enabled local inbound rules disabled.' -ForegroundColor Green
    }
    $effectiveNonLocal = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Inbound -Enabled True -Action Allow -ErrorAction Stop |
        Where-Object { $created -notcontains $_.Name -and $_.PolicyStore -ne 'PersistentStore' })
    if ($effectiveNonLocal.Count -gt 0) {
        Write-Warning ("{0} effective inbound Allow rule(s) remain outside local policy and were not disabled (likely Group Policy)." -f $effectiveNonLocal.Count)
        $effectiveNonLocal | ForEach-Object { Write-Warning ("Remaining effective rule: {0}" -f $_.Name) }
    }

    Write-Step 9 'Export final firewall configuration and report'
    $afterRules = @(Get-RuleReport)
    $afterBackup = Export-Policy $backupDirectory 'firewall-after' $afterRules
    Write-Host "After backup: $($afterBackup.Wfw)" -ForegroundColor Green
    Write-Host "After report: $($afterBackup.Txt)" -ForegroundColor Green
    $remainingAllows = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Inbound -Enabled True -Action Allow -ErrorAction Stop)
    if ($remainingAllows.Count -gt $specs.Count) { Write-Warning "Effective policy contains additional enabled inbound Allow rules; the firewall is not fully restricted to this script's rules." }
    Write-Host "Rollback: netsh advfirewall import `"$($beforeBackup.Wfw)`"" -ForegroundColor Magenta
} catch {
    Write-Warning "Barebones firewall configuration stopped: $($_.Exception.Message)"
    if ($beforeBackup) { Write-Host "Rollback: netsh advfirewall import `"$($beforeBackup.Wfw)`"" -ForegroundColor Magenta }
    throw
}
