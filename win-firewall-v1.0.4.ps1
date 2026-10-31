#requires -Version 5.1
<##
.SYNOPSIS
  CCDC Windows Firewall baseline for Client and Domain Controller systems.

.DESCRIPTION
  Applies a blocking inbound baseline, creates the required AD rules on a
  Domain Controller, optionally creates rules for selected service listeners,
  disables other enabled local inbound rules, and exports before/after state.
  -Log enables append-only detailed firewall logging. It can be used by
  itself or followed by a log path.
#>
[CmdletBinding()]
param(
    [string[]]$ClientNetworks,
    [switch]$Modify,
    [ValidateSet('DC','Client')][string]$Role,
    [switch]$ConfigureServices,
    [string]$ServiceSelection,
    [string[]]$ServiceRemoteAddress = @('Any'),
    [switch]$Log,
    [switch]$Export,
    [Parameter(ValueFromRemainingArguments=$true)]
    [string[]]$RemainingArguments
)

if ($Export -and ($Modify -or $ConfigureServices -or $PSBoundParameters.ContainsKey('Role') -or
    $PSBoundParameters.ContainsKey('ClientNetworks') -or $PSBoundParameters.ContainsKey('ServiceSelection') -or
    $PSBoundParameters.ContainsKey('ServiceRemoteAddress'))) {
    throw '-Export cannot be combined with role, network, or service configuration parameters.'
}
if ($Modify -and ($ConfigureServices -or $PSBoundParameters.ContainsKey('ServiceSelection') -or
    $PSBoundParameters.ContainsKey('ServiceRemoteAddress'))) {
    throw '-Modify cannot be combined with service configuration parameters.'
}

$backupDirectory = 'C:\CCDC\FirewallBackups'
$scriptPrefix = 'CCDC-DC-Barebones-'
$adGroup = 'CCDC DC Barebones'
$serviceGroup = 'CCDC Service Firewall'
$servicePrefix = 'CCDC-Service'
$beforeBackup = $null
$logPath = $null
$runArguments = ($PSBoundParameters.Keys -join ',')

function Resolve-LogPath {
    param([switch]$Enabled, [string[]]$Arguments)
    if (-not $Enabled) { return $null }
    if (@($Arguments).Count -gt 1) { throw '-Log accepts at most one optional path.' }
    if (@($Arguments).Count -eq 1) {
        $text = ([string]$Arguments[0]).Trim()
        if ($text.StartsWith('-')) { throw "Invalid -Log path: $text" }
        if (-not [string]::IsNullOrWhiteSpace($text)) { return $text }
    }
    return (Join-Path $backupDirectory 'firewall.log')
}

function Write-Log {
    param([Parameter(Mandatory)][string]$Event, [string]$Detail = '')
    if (-not $script:logPath) { return }
    $line = '{0} | {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Event
    if (-not [string]::IsNullOrWhiteSpace($Detail)) { $line += " | $Detail" }
    Add-Content -LiteralPath $script:logPath -Value $line -Encoding UTF8 -ErrorAction Stop
}

function Start-RunLog {
    $script:logPath = Resolve-LogPath -Enabled:$Log -Arguments $RemainingArguments
    if (-not $script:logPath) { return }
    $parent = Split-Path -Parent $script:logPath
    if ($parent) { New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop | Out-Null }
    Add-Content -LiteralPath $script:logPath -Value @('', '===== RUN START =====',
        ("Time={0}" -f (Get-Date -Format 'o')),
        ("Computer={0}" -f $env:COMPUTERNAME),
        'ScriptVersion=1.0.4',
        ("Arguments={0}" -f $script:runArguments),
        ("LogPath={0}" -f $script:logPath)) -Encoding UTF8 -ErrorAction Stop
    Write-Host "Detailed firewall logging enabled: $script:logPath" -ForegroundColor Gray
}

function Get-Role {
    $role = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    switch ([int]$role.DomainRole) {
        0 { $name = 'Standalone workstation'; $workflow = 'Client' }
        1 { $name = 'Domain-joined workstation'; $workflow = 'Client' }
        2 { $name = 'Standalone server'; $workflow = 'Client' }
        3 { $name = 'Domain-joined member server'; $workflow = 'Client' }
        4 { $name = 'Domain Controller'; $workflow = 'DC' }
        5 { $name = 'Domain Controller'; $workflow = 'DC' }
        default { throw "Unknown Windows DomainRole: $($role.DomainRole)" }
    }
    [pscustomobject]@{ DomainRole = [int]$role.DomainRole; Name = $name; Workflow = $workflow }
}

function Assert-Role([string]$Actual, [string]$Requested) {
    if ($Requested -and $Actual -ne $Requested) { throw "Requested -Role $Requested but detected $Actual." }
}

function Set-Baseline {
    Set-NetFirewallProfile -Name Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -Confirm:$false -ErrorAction Stop
    foreach ($p in @(Get-NetFirewallProfile -Name Domain,Private,Public -ErrorAction Stop)) {
        if (-not $p.Enabled -or [string]$p.DefaultInboundAction -ne 'Block' -or [string]$p.DefaultOutboundAction -ne 'Allow') {
            throw "Firewall baseline verification failed for profile $($p.Name)."
        }
    }
    Write-Log 'BASELINE' 'Profiles=Domain,Private,Public | Inbound=Block | Outbound=Allow'
}

function New-UniquePaths([string]$Base, [string[]]$Extensions) {
    New-Item -ItemType Directory -Path $backupDirectory -Force -ErrorAction Stop | Out-Null
    $stamp = Get-Date -Format 'HHmm-MMddyyyy'
    $safeComputer = ($env:COMPUTERNAME -replace '[^A-Za-z0-9_.-]', '_')
    for ($i = 0; $i -lt 1000; $i++) {
        $suffix = if ($i) { '-{0:D2}' -f $i } else { '' }
        $stem = "$Base-$safeComputer-$stamp$suffix"
        $paths = @{}; $ok = $true
        foreach ($ext in $Extensions) { $paths[$ext] = Join-Path $backupDirectory "$stem.$ext"; if (Test-Path $paths[$ext]) { $ok = $false } }
        if ($ok) { return $paths }
    }
    throw "Could not allocate output paths for $Base."
}

function Get-RuleRows {
    $rows = foreach ($r in @(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -ErrorAction Stop)) {
        $p = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $r -ErrorAction Stop
        $a = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $r -ErrorAction Stop
        [pscustomobject]@{ DisplayName=$r.DisplayName; Direction=$r.Direction; Protocol=$p.Protocol; LocalPort=(@($p.LocalPort)-join ','); RemotePort=(@($p.RemotePort)-join ','); LocalAddress=(@($a.LocalAddress)-join ','); RemoteAddress=(@($a.RemoteAddress)-join ',') }
    }
    return @($rows)
}

function Write-Report([string]$Path, [object[]]$Rows) {
    $lines = @('CCDC Windows Firewall report', ("Created: {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')), '')
    foreach ($direction in @('Inbound','Outbound')) {
        $lines += "[$direction]"
        $selected = @($Rows | Where-Object Direction -eq $direction | Sort-Object LocalPort,DisplayName)
        if (-not $selected) { $lines += 'No enabled rules found.' }
        foreach ($r in $selected) { $lines += ('{0} | {1} | {2} | Local={3}:{4} | Remote={5}:{6}' -f $r.DisplayName,$r.Protocol,$r.Direction,$r.LocalAddress,$r.LocalPort,$r.RemoteAddress,$r.RemotePort) }
        $lines += ''
    }
    $lines | Set-Content -LiteralPath $Path -Encoding UTF8 -ErrorAction Stop
}

function Export-State([string]$Base) {
    $paths = New-UniquePaths $Base @('wfw','txt')
    $netsh = Join-Path $env:SystemRoot 'System32\netsh.exe'
    $proc = Start-Process -FilePath $netsh -ArgumentList "advfirewall export `"$($paths.wfw)`"" -Wait -PassThru -NoNewWindow
    if ($proc.ExitCode -ne 0 -or -not (Test-Path $paths.wfw)) { throw "Firewall export failed: $($paths.wfw)" }
    $rows = @(Get-RuleRows); Write-Report $paths.txt $rows
    Write-Log 'EXPORT' "Wfw=$($paths.wfw) | Txt=$($paths.txt) | EnabledRules=$($rows.Count)"
    [pscustomobject]@{ Wfw=$paths.wfw; Txt=$paths.txt }
}

function ConvertTo-Scope([string[]]$Values) {
    $out = @()
    foreach ($v in $Values) { foreach ($part in ([string]$v -split '[,;]')) { $x=$part.Trim(); if ($x) { if ($x -notmatch '^(?i:Any|LocalSubnet4)$' -and $x -notmatch '^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$') { throw "Invalid IPv4 scope: $x" }; if ($x -eq '0.0.0.0/0') { throw 'IPv4 /0 is not allowed.' }; $out += $x } } }
    if (-not $out) { throw 'At least one IPv4 scope is required.' }
    return @($out | Sort-Object -Unique)
}

function Invoke-ADRules([string[]]$Remote) {
    $specs = @(
        @('TCP','53'),@('UDP','53'),@('TCP','88'),@('UDP','88'),@('TCP','389'),@('UDP','389'),@('TCP','464'),@('UDP','464'),
        @('TCP','445'),@('TCP','135'),@('TCP','49152-65535'),@('UDP','123'),@('TCP','3268'))
    $created = @()
    foreach ($s in $specs) {
        $name = "$scriptPrefix$($s[0])-$($s[1] -replace '[^0-9-]','')"
        $display = "CCDC DC Barebones $($s[0])-$($s[1])"
        $rule = @(Get-NetFirewallRule -PolicyStore PersistentStore -Name $name -ErrorAction SilentlyContinue)
        if ($rule.Count -eq 0) { New-NetFirewallRule -PolicyStore PersistentStore -Name $name -DisplayName $display -Group $adGroup -Enabled True -Direction Inbound -Action Allow -Profile Any -Protocol $s[0] -LocalPort $s[1] -RemoteAddress $Remote -Confirm:$false -ErrorAction Stop | Out-Null; $action='Create' }
        else { Set-NetFirewallRule -PolicyStore PersistentStore -Name $name -Enabled False -Confirm:$false -ErrorAction Stop; Set-NetFirewallRule -PolicyStore PersistentStore -Name $name -Enabled True -RemoteAddress $Remote -Confirm:$false -ErrorAction Stop; $action='Update' }
        $created += $name
        Write-Host ("{0} AD rule: {1} ({2}/{3}, Remote={4})" -f $action,$name,$s[0],$s[1],($Remote -join ',')) -ForegroundColor Green
        Write-Log 'AD-RULE' "Action=$action | Name=$name | Protocol=$($s[0]) | LocalPort=$($s[1]) | Remote=$($Remote -join ',')"
    }
    return $created
}

function Update-ADRules([string[]]$Remote) {
    $rules = @(Get-NetFirewallRule -PolicyStore PersistentStore -Group $adGroup -Direction Inbound -Enabled True -ErrorAction Stop | Where-Object Name -like "$scriptPrefix*")
    if (-not $rules) { throw 'No enabled local AD rules were found to modify.' }
    foreach ($rule in $rules) {
        Set-NetFirewallRule -PolicyStore PersistentStore -Name $rule.Name -RemoteAddress $Remote -Confirm:$false -ErrorAction Stop
        Write-Log 'AD-RULE' "Action=Update | Name=$($rule.Name) | Remote=$($Remote -join ',')"
    }
    Write-Host "Updated enabled AD rules: $($rules.Count)" -ForegroundColor Green
}

function Get-EmbeddedServiceCandidates {
    $servicesByPid = @{}
    foreach ($service in @(Get-CimInstance -ClassName Win32_Service -Filter "State = 'Running'" -ErrorAction Stop)) {
        if ([int]$service.ProcessId -le 0) { continue }
        if (-not $servicesByPid.ContainsKey([int]$service.ProcessId)) {
            $servicesByPid[[int]$service.ProcessId] = [System.Collections.Generic.List[object]]::new()
        }
        $servicesByPid[[int]$service.ProcessId].Add($service)
    }
    $endpoints = @()
    if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
        $endpoints += @(Get-NetTCPConnection -State Listen -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{ Protocol='TCP'; LocalAddress=[string]$_.LocalAddress; LocalPort=[int]$_.LocalPort; OwningProcess=[int]$_.OwningProcess }
        })
    }
    if (Get-Command Get-NetUDPEndpoint -ErrorAction SilentlyContinue) {
        $endpoints += @(Get-NetUDPEndpoint -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{ Protocol='UDP'; LocalAddress=[string]$_.LocalAddress; LocalPort=[int]$_.LocalPort; OwningProcess=[int]$_.OwningProcess }
        })
    }
    $script:serviceRawEndpointCount = $endpoints.Count
    $script:serviceExcludedUdpCount = 0
    $groups = @{}
    foreach ($endpoint in $endpoints) {
        if ($endpoint.Protocol -eq 'UDP' -and [int]$endpoint.LocalPort -ge 49152 -and [int]$endpoint.LocalPort -le 65535) {
            $script:serviceExcludedUdpCount++
            continue
        }
        if (-not $servicesByPid.ContainsKey($endpoint.OwningProcess)) { continue }
        foreach ($service in $servicesByPid[$endpoint.OwningProcess]) {
            $key = '{0}|{1}|{2}' -f $service.Name,$endpoint.Protocol,$endpoint.LocalPort
            if (-not $groups.ContainsKey($key)) {
                $groups[$key] = [pscustomobject]@{
                    ServiceName=[string]$service.Name; DisplayName=[string]$service.DisplayName
                    Protocol=[string]$endpoint.Protocol; LocalPort=[int]$endpoint.LocalPort
                    LocalAddresses=[System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                    ProcessIds=[System.Collections.Generic.HashSet[int]]::new()
                    UsesWildcard=$false
                }
            }
            $group = $groups[$key]
            [void]$group.LocalAddresses.Add([string]$endpoint.LocalAddress)
            [void]$group.ProcessIds.Add([int]$endpoint.OwningProcess)
            if ([string]$endpoint.LocalAddress -in @('0.0.0.0','::','*')) { $group.UsesWildcard=$true }
        }
    }
    $result = foreach ($group in $groups.Values) {
        $addresses = @($group.LocalAddresses | Sort-Object)
        $firewallAddresses = if ($group.UsesWildcard) { @('Any') } else { $addresses }
        [pscustomobject]@{
            ServiceName=$group.ServiceName; DisplayName=$group.DisplayName; Protocol=$group.Protocol
            LocalPort=$group.LocalPort; LocalAddresses=$addresses; FirewallLocalAddress=$firewallAddresses
            LocalAddressDisplay=if ($group.UsesWildcard) { 'Any' } else { ($addresses -join ',') }
            ProcessIds=@($group.ProcessIds | Sort-Object); UsesWildcard=$group.UsesWildcard
        }
    }
    $script:serviceGroupedCandidateCount = @($result).Count
    @($result | Sort-Object ServiceName,Protocol,LocalPort)
}

function ConvertTo-EmbeddedServiceSelection([string]$Value, [int]$Maximum) {
    $text=$Value.Trim()
    if ($text -ieq 'All') { return @(1..$Maximum) }
    if ($text -ieq 'None') { return @() }
    if ([string]::IsNullOrWhiteSpace($text)) { throw 'Selection cannot be empty.' }
    $selected=[System.Collections.Generic.HashSet[int]]::new()
    foreach ($part in $text.Split(',')) {
        $item=$part.Trim()
        if ($item -match '^([0-9]+)\s*-\s*([0-9]+)$') {
            $start=[int]$Matches[1];$end=[int]$Matches[2]
            if ($start -gt $end) { throw "Invalid descending range: $item" }
            foreach ($number in $start..$end) { [void]$selected.Add($number) }
        } elseif ($item -match '^[0-9]+$') { [void]$selected.Add([int]$item) }
        else { throw "Invalid selection item: $item" }
    }
    foreach ($number in $selected) { if ($number -lt 1 -or $number -gt $Maximum) { throw "Selection $number is outside the displayed range 1-$Maximum." } }
    @($selected | Sort-Object)
}

function Get-EmbeddedServiceRuleName([psobject]$Candidate, [string]$Prefix) {
    $safe=$Candidate.ServiceName -replace '[^a-zA-Z0-9_.-]','_'
    return "$Prefix-$safe-$($Candidate.Protocol)-$($Candidate.LocalPort)"
}

function Invoke-EmbeddedServiceSelection {
    $candidates=@(Get-EmbeddedServiceCandidates)
    Write-Log 'SERVICE-DISCOVERY' "RawEndpoints=$script:serviceRawEndpointCount | GroupedCandidates=$script:serviceGroupedCandidateCount"
    Write-Log 'SERVICE-FILTER' 'Excluded=UDP/49152-65535'
    $indexed=@($candidates | ForEach-Object -Begin {$i=0} -Process {$i++;$_ | Add-Member -NotePropertyName Number -NotePropertyValue $i -PassThru})
    if ($indexed.Count -eq 0) { Write-Host 'No running service listeners were found.'; return @() }
    Write-Host ("Available service listeners: {0} unique entries" -f $indexed.Count) -ForegroundColor Gray
    $indexed | Format-Table Number,ServiceName,DisplayName,Protocol,LocalPort,LocalAddressDisplay -AutoSize | Out-Host
    foreach ($candidate in $indexed) {
        Write-Log 'SERVICE-CANDIDATE' "Service=$($candidate.ServiceName) | Protocol=$($candidate.Protocol) | Port=$($candidate.LocalPort) | Addresses=$($candidate.LocalAddresses -join ',') | LocalAddress=$($candidate.LocalAddressDisplay)"
    }
    $selectionProvided = $null -ne $ServiceSelection
    $interactive = $true
    try { $interactive = [Environment]::UserInteractive -and ($null -ne $Host.UI) } catch { $interactive = $false }
    do {
        if ($selectionProvided) { $inputSelection=$ServiceSelection; $selectionProvided=$false; $script:ServiceSelection=$null }
        elseif (-not $interactive) {
            Write-Host 'No interactive console is available. Skipping service-rule creation.' -ForegroundColor Yellow
            Write-Log 'SERVICE-SELECTION' 'Value=None | Reason=Noninteractive input'
            return @()
        } else { $inputSelection=Read-Host 'Enter selections (All, None, numbers, or ranges)' }
        if ([string]::IsNullOrWhiteSpace([string]$inputSelection)) {
            Write-Host 'No service selection entered. Skipping service-rule creation.' -ForegroundColor Yellow
            Write-Log 'SERVICE-SELECTION' 'Value=None | Reason=Blank input'
            return @()
        }
        try {$numbers=@(ConvertTo-EmbeddedServiceSelection $inputSelection $indexed.Count);$valid=$true}
        catch {
            if (-not $interactive -or -not $selectionProvided) { Write-Warning $_.Exception.Message; if (-not $interactive) { return @() } }
            else { throw }
            $valid=$false
        }
    } until ($valid)
    if ($numbers.Count -eq 0) { Write-Host 'No rules selected. No firewall changes were made.'; return @() }
    $changes=@()
    foreach ($number in $numbers) {
        $candidate=$indexed[$number-1];$name=Get-EmbeddedServiceRuleName $candidate $servicePrefix
        New-NetFirewallRule -PolicyStore PersistentStore -Name $name -DisplayName "$($candidate.DisplayName) ($($candidate.Protocol)/$($candidate.LocalPort))" -Group $serviceGroup -Enabled True -Direction Inbound -Action Allow -Profile Any -Protocol $candidate.Protocol -LocalAddress ([string[]]$candidate.FirewallLocalAddress) -LocalPort ([string]$candidate.LocalPort) -RemoteAddress $ServiceRemoteAddress -RemotePort Any -Service $candidate.ServiceName -Program Any -Confirm:$false -ErrorAction Stop | Out-Null
        Write-Log 'SERVICE-RULE' "Status=CreatedOrUpdated | Name=$name | Protocol=$($candidate.Protocol) | LocalPort=$($candidate.LocalPort) | Remote=$($ServiceRemoteAddress -join ',')"
        $changes += $name
    }
    return @($changes)
}

function Invoke-ServiceRules {
    $changes=@(Invoke-EmbeddedServiceSelection)
    Write-Log 'SERVICE' "Remote=$($ServiceRemoteAddress -join ',') | Selection=$ServiceSelection | Rules=$($changes.Count)"
}

function Disable-OtherInbound([string[]]$Preserve) {
    $rules = @(Get-NetFirewallRule -PolicyStore PersistentStore -Direction Inbound -Enabled True -ErrorAction Stop)
    $targets = @($rules | Where-Object { $Preserve -notcontains $_.Name -and $_.Group -cne $serviceGroup -and $_.Name -notlike "$servicePrefix-*" })
    foreach ($r in $targets) {
        $p = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $r -ErrorAction SilentlyContinue
        $a = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $r -ErrorAction SilentlyContinue
        Set-NetFirewallRule -PolicyStore PersistentStore -Name $r.Name -Enabled False -Confirm:$false -ErrorAction Stop
        Write-Log 'DISABLE' "Name=$($r.Name) | Protocol=$($p.Protocol) | LocalPort=$(@($p.LocalPort)-join ',') | Remote=$(@($a.RemoteAddress)-join ',')"
    }
    $nonlocal = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Inbound -Enabled True -Action Allow -ErrorAction Stop | Where-Object { $Preserve -notcontains $_.Name -and $_.Group -cne $serviceGroup -and $_.Name -notlike "$servicePrefix-*" -and [string]$_.PolicyStoreSourceType -ne 'Local' })
    Write-Log 'CLEANUP' "LocalFound=$($rules.Count) | Disabled=$($targets.Count) | NonlocalRemaining=$($nonlocal.Count)"
    Write-Host "Enabled local inbound rules found: $($rules.Count)" -ForegroundColor Gray
    Write-Host "Script-created inbound rules preserved: $($rules.Count - $targets.Count)" -ForegroundColor Gray
    Write-Host "Non-script-created inbound rules disabled: $($targets.Count)" -ForegroundColor Gray
    Write-Host "Nonlocal inbound rules reported separately: $($nonlocal.Count)" -ForegroundColor Gray
    if ($nonlocal.Count) { Write-Warning "$($nonlocal.Count) nonlocal inbound rule(s) remain enabled and could not be disabled locally." }
}

try {
    Start-RunLog
    Write-Host 'Checking administrator privileges and firewall cmdlets...' -ForegroundColor Cyan
    $id=[Security.Principal.WindowsIdentity]::GetCurrent(); $pr=New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run as Administrator.' }
    $commands = if ($Export) { @('Get-NetFirewallRule','Get-NetFirewallPortFilter','Get-NetFirewallAddressFilter') } else { @('Get-NetFirewallRule','New-NetFirewallRule','Set-NetFirewallRule','Get-NetFirewallProfile','Set-NetFirewallProfile','Get-NetFirewallPortFilter','Get-NetFirewallAddressFilter') }
    foreach ($c in $commands) { if (-not (Get-Command $c -ErrorAction SilentlyContinue)) { throw "Required firewall cmdlet is unavailable: $c" } }
    if ($Export) { $out=New-UniquePaths 'firewall-export' @('txt'); Write-Report $out.txt @(Get-RuleRows); Write-Host "Enabled firewall report: $($out.txt)"; Write-Log 'STATUS' 'Export completed'; return }
    if ($ClientNetworks) { $ClientNetworks=ConvertTo-Scope $ClientNetworks }
    if ($Modify) {
        if (-not $ClientNetworks) { throw '-Modify requires -ClientNetworks.' }
        $detectedRole=Get-Role; Assert-Role -Actual ([string]$detectedRole.Workflow) -Requested $Role
        if ($detectedRole.Workflow -ne 'DC') { throw '-Modify is only available on a Domain Controller.' }
        $beforeBackup=Export-State 'firewall-modify-before'; Write-Host "Before backup: $($beforeBackup.Wfw)" -ForegroundColor Green
        Update-ADRules $ClientNetworks
        $afterBackup=Export-State 'firewall-modify-after'; Write-Host "After backup: $($afterBackup.Wfw)" -ForegroundColor Green
        Write-Log 'STATUS' "Modify completed | AfterBackup=$($afterBackup.Wfw)"
        Write-Host "Modify workflow completed. Log: $(if ($logPath) { $logPath } else { 'not enabled' })" -ForegroundColor Green
        return
    }
    Set-Baseline; $beforeBackup=Export-State 'firewall-before'; Write-Host "Before backup: $($beforeBackup.Wfw)" -ForegroundColor Green
    $detectedRole=Get-Role; Assert-Role -Actual ([string]$detectedRole.Workflow) -Requested $Role; Write-Log 'ROLE' "Detected=$($detectedRole.Name) | DomainRole=$($detectedRole.DomainRole) | Workflow=$($detectedRole.Workflow)"; Write-Host "Detected machine: $($detectedRole.Name) (DomainRole $($detectedRole.DomainRole)); workflow: $($detectedRole.Workflow)" -ForegroundColor Gray
    $preserve=@()
    if ($detectedRole.Workflow -eq 'DC') { $remote=if ($ClientNetworks) { $ClientNetworks } else { @('LocalSubnet4') }; $preserve += Invoke-ADRules $remote; Write-Host "AD rules created or updated: $($preserve.Count)" -ForegroundColor Gray }
    if ($ConfigureServices) { Invoke-ServiceRules }
    $preserve += @(Get-NetFirewallRule -PolicyStore PersistentStore -Group $serviceGroup -ErrorAction SilentlyContinue | Where-Object Name -like "$servicePrefix-*" | Select-Object -ExpandProperty Name)
    Disable-OtherInbound $preserve
    $afterBackup=Export-State 'firewall-after'; Write-Host "After backup: $($afterBackup.Wfw)" -ForegroundColor Green; Write-Host "After report: $($afterBackup.Txt)" -ForegroundColor Green
    Write-Log 'STATUS' "Completed | Workflow=$($detectedRole.Workflow) | AfterBackup=$($afterBackup.Wfw)"
    Write-Host "Workflow completed. Log: $(if ($logPath) { $logPath } else { 'not enabled' })" -ForegroundColor Green
} catch {
    try { Write-Log 'ERROR' $_.Exception.Message; if ($beforeBackup) { Write-Log 'ROLLBACK' "netsh advfirewall import `"$($beforeBackup.Wfw)`"" } } catch { }
    Write-Warning "Firewall configuration stopped: $($_.Exception.Message)"
    throw
}
