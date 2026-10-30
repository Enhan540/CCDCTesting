#requires -Version 5.1

Set-StrictMode -Version Latest

function Get-ServiceFirewallCandidates {
    [CmdletBinding()]
    param()

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
            [pscustomobject]@{ Protocol = 'TCP'; LocalAddress = [string]$_.LocalAddress; LocalPort = [int]$_.LocalPort; OwningProcess = [int]$_.OwningProcess }
        })
    }
    if (Get-Command Get-NetUDPEndpoint -ErrorAction SilentlyContinue) {
        $endpoints += @(Get-NetUDPEndpoint -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{ Protocol = 'UDP'; LocalAddress = [string]$_.LocalAddress; LocalPort = [int]$_.LocalPort; OwningProcess = [int]$_.OwningProcess }
        })
    }

    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($endpoint in $endpoints) {
        if (-not $servicesByPid.ContainsKey($endpoint.OwningProcess)) { continue }
        foreach ($service in $servicesByPid[$endpoint.OwningProcess]) {
            $rows.Add([pscustomobject]@{
                ServiceName = [string]$service.Name
                DisplayName = [string]$service.DisplayName
                ProcessId = $endpoint.OwningProcess
                Protocol = $endpoint.Protocol
                LocalAddress = $endpoint.LocalAddress
                LocalPort = $endpoint.LocalPort
                PathName = [string]$service.PathName
            })
        }
    }

    @($rows | Sort-Object ServiceName, Protocol, LocalPort, LocalAddress -Unique)
}

function ConvertTo-ServiceFirewallSelection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][int]$Maximum
    )

    $text = $Value.Trim()
    if ($text -ieq 'All') { return @(1..$Maximum) }
    if ($text -ieq 'None') { return @() }
    if ([string]::IsNullOrWhiteSpace($text)) { throw 'Selection cannot be empty.' }

    $selected = [System.Collections.Generic.HashSet[int]]::new()
    foreach ($part in $text.Split(',')) {
        $item = $part.Trim()
        if ($item -match '^([0-9]+)\s*-\s*([0-9]+)$') {
            $start = [int]$Matches[1]; $end = [int]$Matches[2]
            if ($start -gt $end) { throw "Invalid descending range: $item" }
            foreach ($number in $start..$end) { [void]$selected.Add($number) }
        } elseif ($item -match '^[0-9]+$') {
            [void]$selected.Add([int]$item)
        } else {
            throw "Invalid selection item: $item"
        }
    }
    foreach ($number in $selected) {
        if ($number -lt 1 -or $number -gt $Maximum) { throw "Selection $number is outside the displayed range 1-$Maximum." }
    }
    @($selected | Sort-Object)
}

function ConvertTo-ServiceFirewallRuleName {
    param([Parameter(Mandatory)][psobject]$Candidate, [Parameter(Mandatory)][string]$Prefix)
    $safe = ($Candidate.ServiceName -replace '[^a-zA-Z0-9_.-]', '_')
    return "$Prefix-$safe-$($Candidate.Protocol)-$($Candidate.LocalPort)"
}

function Invoke-ServiceFirewallSelection {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [string[]]$RemoteAddress = @('Any'),
        [ValidateNotNullOrEmpty()][string]$RuleGroup = 'CCDC Service Firewall',
        [ValidateNotNullOrEmpty()][string]$RulePrefix = 'CCDC-Service',
        [string]$Selection,
        [switch]$Reconcile,
        [switch]$DisableStaleRules,
        [switch]$Preview
    )

    $dryRun = [bool]($Preview -or $WhatIfPreference)
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $dryRun -and -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this command from an elevated Windows PowerShell session.'
    }

    $candidates = @(Get-ServiceFirewallCandidates)
    $indexed = @($candidates | ForEach-Object -Begin { $i = 0 } -Process {
        $i++
        $_ | Add-Member -NotePropertyName Number -NotePropertyValue $i -PassThru
    })
    Write-Output -NoEnumerate ([pscustomobject]@{ Type = 'Discovered'; Candidates = $indexed })

    if ($indexed.Count -eq 0) {
        Write-Host 'No running service listeners were found.'
        return
    }

    $indexed | Format-Table Number, ServiceName, DisplayName, Protocol, LocalAddress, LocalPort, ProcessId -AutoSize | Out-Host
    do {
        $inputSelection = if ($null -ne $Selection) { $Selection; $Selection = $null } else { Read-Host 'Enter selections (All, None, numbers, or ranges)' }
        try { $numbers = @(ConvertTo-ServiceFirewallSelection -Value $inputSelection -Maximum $indexed.Count); $valid = $true }
        catch { Write-Warning $_.Exception.Message; $valid = $false }
    } until ($valid)

    if ($numbers.Count -eq 0) {
        Write-Host 'No rules selected. No firewall changes were made.'
        return
    }

    $selected = @($numbers | ForEach-Object { $indexed[$_ - 1] })
    $desiredNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $changes = [System.Collections.Generic.List[object]]::new()
    foreach ($candidate in $selected) {
        $name = ConvertTo-ServiceFirewallRuleName $candidate $RulePrefix
        [void]$desiredNames.Add($name)
        $changes.Add([pscustomobject]@{ Name = $name; Candidate = $candidate; Status = 'Pending' })
        $settings = @{
            Name = $name; DisplayName = "$($candidate.DisplayName) ($($candidate.Protocol)/$($candidate.LocalPort))";
            Group = $RuleGroup; Enabled = 'True'; Direction = 'Inbound'; Action = 'Allow'; Profile = 'Any';
            Protocol = $candidate.Protocol; LocalAddress = $candidate.LocalAddress; LocalPort = [string]$candidate.LocalPort;
            RemoteAddress = $RemoteAddress; RemotePort = 'Any'; Service = $candidate.ServiceName;
            Program = 'Any'; PolicyStore = 'PersistentStore'; Confirm = $false; ErrorAction = 'Stop'
        }
        if ($dryRun) { Write-Host "Preview: would create/update $name" -ForegroundColor Yellow; continue }
        if ($PSCmdlet.ShouldProcess($name, 'Create or update inbound service firewall rule')) {
            New-NetFirewallRule @settings | Out-Null
            ($changes | Where-Object Name -eq $name).Status = 'CreatedOrUpdated'
        }
    }

    $stale = @()
    if ($Reconcile) {
        $stale = @(Get-NetFirewallRule -PolicyStore PersistentStore -Group $RuleGroup -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like "$RulePrefix-*" -and -not $desiredNames.Contains($_.Name) })
        foreach ($rule in $stale) {
            if ($DisableStaleRules) {
                if ($dryRun) { Write-Host "Preview: would disable stale rule $($rule.Name)" -ForegroundColor Yellow }
                elseif ($PSCmdlet.ShouldProcess($rule.Name, 'Disable stale managed firewall rule')) { $rule | Set-NetFirewallRule -Enabled False -Confirm:$false -ErrorAction Stop }
            } elseif ($dryRun) { Write-Host "Preview: would remove stale rule $($rule.Name)" -ForegroundColor Yellow
            } elseif ($PSCmdlet.ShouldProcess($rule.Name, 'Remove stale managed firewall rule')) { $rule | Remove-NetFirewallRule -Confirm:$false -ErrorAction Stop }
        }
    }

    [pscustomobject]@{ Type = 'Result'; Candidates = $indexed; Selected = $selected; Changes = @($changes); StaleRules = $stale; Preview = $dryRun }
}

Export-ModuleMember -Function Invoke-ServiceFirewallSelection
