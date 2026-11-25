#Requires -Version 7

function Get-ResourceName([string]$Id) { if ($Id) { ($Id.TrimEnd('/') -split '/')[-1] } }

function Get-TierFamily([string]$Sku) {
    switch ($Sku.Trim()) {
        { $_ -in 'Developer', 'Basic', 'Standard', 'Premium', 'Isolated' } { return 'Classic' }
        'Consumption' { return 'Classic (Consumption)' }
        { $_ -in 'BasicV2', 'StandardV2', 'PremiumV2' } { return 'v2' }
        default { return 'Unknown' }
    }
}

function New-ImpactedList {
    [pscustomobject]@{
        ids = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        names = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    }
}

function Add-Impacted($List, [string]$ResourceId, [string]$Name) {
    if ($ResourceId -and $ResourceId.Trim() -match '^/subscriptions/') { [void]$List.ids.Add($ResourceId.Trim().TrimEnd('/')) }
    elseif (-not [string]::IsNullOrWhiteSpace($Name)) { [void]$List.names.Add($Name.Trim()) }
    else { throw 'Impacted-resource row has neither a subscription resource ID nor a resource name.' }
}

function Get-ScopeDecision($Instance, $Listed, [switch]$IncludeConsumption) {
    $family = Get-TierFamily $Instance.sku
    if ($family -eq 'Unknown') {
        Write-Warning "$($Instance.name): unrecognized or missing APIM SKU '$($Instance.sku)'. Retaining for manual review."
        return [pscustomobject]@{ inScope = $true; tierFamily = $family; reason = "unrecognized or missing SKU '$($Instance.sku)': scope cannot be determined" }
    }
    if ($Listed) {
        $isListed = $Listed.ids.Contains("$($Instance.id)".TrimEnd('/')) -or $Listed.names.Contains("$($Instance.name)")
        $reason = if (-not $isListed) { 'not listed by Microsoft' }
                  elseif ($family -eq 'v2') { 'listed by Microsoft, but now a v2 tier (migrated after the incident?)' }
                  else { 'listed by Microsoft' }
        return [pscustomobject]@{ inScope = $isListed; tierFamily = $family; reason = $reason }
    }
    $inScope = $true
    $reason = "Classic dedicated tier (platform $(if ($Instance.platformVersion) { $Instance.platformVersion } else { 'unknown' }))"
    if ($family -eq 'v2') { $inScope = $false; $reason = 'v2 tier (not affected)' }
    elseif ($family -eq 'Classic (Consumption)') {
        $inScope = [bool]$IncludeConsumption
        $reason = if ($IncludeConsumption) { 'Consumption tier explicitly included' }
                  else { 'Consumption tier: not listed by Microsoft in the tenants checked (-IncludeConsumption to include)' }
    }
    [pscustomobject]@{ inScope = $inScope; tierFamily = $family; reason = $reason }
}

function ConvertTo-ReportBoolean($Value, [string]$Context) {
    $parsed = $false
    if ($null -eq $Value -or -not [bool]::TryParse("$Value".Trim(), [ref]$parsed)) {
        throw "Expected True or False for $Context; received '$Value'."
    }
    return $parsed
}

function Select-ApimInstance([object[]]$Instances, [string]$ScopeFile, [switch]$IncludeConsumption) {
    $decisions = @{}
    if ($ScopeFile -and (Test-Path -LiteralPath $ScopeFile)) {
        $rows = @(Import-Csv -LiteralPath $ScopeFile)
        if (-not $rows.Count) {
            if (-not $Instances.Count) { Write-Warning "Scope file and APIM inventory are both empty: $ScopeFile"; return }
            throw "Scope file is empty: $ScopeFile. Regenerate it with Check-ApimExposure.ps1."
        }
        foreach ($row in $rows) {
            if ([string]::IsNullOrWhiteSpace($row.id) -or $row.PSObject.Properties.Name -notcontains 'inScope') {
                throw "Invalid scope file ${ScopeFile}: every row must have id and inScope columns."
            }
            $key = $row.id.Trim().TrimEnd('/')
            if ($decisions.ContainsKey($key)) { throw "Duplicate resource ID in scope file ${ScopeFile}: $key" }
            $decisions[$key] = ConvertTo-ReportBoolean $row.inScope "inScope for $key in $ScopeFile"
        }
        $visible = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($instance in $Instances) { [void]$visible.Add("$($instance.id)".TrimEnd('/')) }
        foreach ($key in $decisions.Keys) {
            if ($decisions[$key] -and -not $visible.Contains($key)) { Write-Warning "In-scope resource not present in the current inventory: $key" }
        }
    }
    foreach ($instance in $Instances) {
        if ([string]::IsNullOrWhiteSpace($instance.id)) { throw 'APIM inventory contains an instance without a resource ID.' }
        $decision = Get-ScopeDecision $instance $null -IncludeConsumption:$IncludeConsumption
        $key = "$($instance.id)".TrimEnd('/')
        if ($decision.tierFamily -eq 'Unknown') { $instance; continue }
        if ($decisions.ContainsKey($key)) {
            if ($decisions[$key]) { $instance }
        } else {
            if ($decisions.Count) { Write-Warning "$key is missing from $ScopeFile; applying the tier fallback. Regenerate the scope file." }
            if ($decision.inScope) { $instance }
        }
    }
}

function Get-PrincipalIds($Identity) {
    if (-not $Identity) { return }
    $idn = if ($Identity -is [string]) { $Identity | ConvertFrom-Json -ErrorAction Stop } else { $Identity }
    if (-not $idn) { return }
    $type = "$($idn.type)" -replace '\s', ''
    if ($type -eq 'None') { return }
    if ($type -notin 'SystemAssigned', 'UserAssigned', 'SystemAssigned,UserAssigned', 'UserAssigned,SystemAssigned') {
        throw "Unrecognized managed-identity type '$($idn.type)'; cannot determine identity coverage."
    }
    $ids = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    if ($type -match 'SystemAssigned') {
        if (-not $idn.principalId) { throw 'System-assigned identity has no principalId.' }
        [void]$ids.Add("$($idn.principalId)")
    }
    if ($type -match 'UserAssigned') {
        $assigned = @($idn.userAssignedIdentities.PSObject.Properties)
        if (-not $assigned.Count) { throw 'User-assigned identity has no identity entries.' }
        foreach ($entry in $assigned) {
            if (-not $entry.Value.principalId) { throw "User-assigned identity $($entry.Name) has no principalId." }
            [void]$ids.Add("$($entry.Value.principalId)")
        }
    }
    foreach ($id in $ids) {
        $guid = [guid]::Empty
        if (-not [guid]::TryParse($id, [ref]$guid) -or $guid -eq [guid]::Empty) { throw "Invalid managed-identity principalId '$id'." }
        $guid.ToString()
    }
}

function Invoke-AzJson([string[]]$Arguments) {
    $output = az @Arguments --output json
    if ($LASTEXITCODE -ne 0) { throw "Azure CLI command 'az $($Arguments -join ' ')' failed (exit $LASTEXITCODE). Check az login and permissions." }
    if (-not $output) { throw "Azure CLI command 'az $($Arguments -join ' ')' returned no JSON." }
    try { ConvertFrom-Json -InputObject ($output -join "`n") -NoEnumerate -ErrorAction Stop }
    catch { throw "Azure CLI command 'az $($Arguments -join ' ')' returned invalid JSON: $($_.Exception.Message)" }
}

function Get-EnabledSubscription {
    $accounts = Invoke-AzJson @('account', 'list')
    if ($accounts -isnot [array]) { throw 'Azure CLI account list did not return an array.' }
    $ids = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($account in $accounts) {
        if ($account.state -eq 'Enabled') {
            $id = [guid]::Empty
            if (-not [guid]::TryParse("$($account.id)", [ref]$id) -or $id -eq [guid]::Empty) { throw 'Enabled subscription has an invalid or missing ID.' }
            [void]$ids.Add($id.ToString())
        } elseif ($account.state -notin 'Disabled', 'Deleted', 'PastDue', 'Warned') {
            Write-Warning "Subscription '$($account.id)' has unexpected state '$($account.state)' and was not scanned."
        }
    }
    if (-not $ids.Count) { throw 'No enabled subscriptions were returned by Azure CLI. Check az login and tenant access.' }
    $ids
}

function Assert-ResponseCollection($Response, [string]$Property, [string]$Context) {
    if ($null -ne $Response.error) { throw "$Context returned an error: $($Response.error | ConvertTo-Json -Depth 6 -Compress)" }
    if ($null -eq $Response -or $Response.$Property -isnot [System.Collections.IList]) {
        throw "Unexpected response from ${Context}: expected a '$Property' array."
    }
}

function ConvertFrom-LogAnalyticsResponse($Response) {
    Assert-ResponseCollection $Response 'tables' 'Log Analytics'
    if (-not $Response.tables.Count) { throw 'Log Analytics returned no result table.' }
    $table = $Response.tables[0]
    Assert-ResponseCollection $table 'columns' 'Log Analytics result table'
    Assert-ResponseCollection $table 'rows' 'Log Analytics result table'
    $columns = @($table.columns | ForEach-Object { if ($_.name) { "$($_.name)" } else { "$($_.ColumnName)" } })
    if (-not $columns.Count -or @($columns | Where-Object { [string]::IsNullOrWhiteSpace($_) }).Count -or
        @($columns | Sort-Object -Unique).Count -ne $columns.Count) {
        throw 'Log Analytics returned missing or duplicate column names.'
    }
    foreach ($row in $table.rows) {
        if ($row -isnot [System.Collections.IList] -or $row.Count -ne $columns.Count) { throw 'Log Analytics returned a row with an unexpected number of columns.' }
        $values = [ordered]@{}
        for ($c = 0; $c -lt $columns.Count; $c++) { $values[$columns[$c]] = $row[$c] }
        [pscustomobject]$values
    }
}

function ConvertTo-UtcDate([datetime]$Value) {
    if ($Value.Kind -eq [DateTimeKind]::Unspecified) { return [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc) }
    $Value.ToUniversalTime()
}

function Assert-AuditWindow([datetime]$Start, [datetime]$End, [int]$LookbackDays) {
    if ($Start -ge $End) { throw 'WindowStart must be earlier than WindowEnd (exclusive).' }
    if ($LookbackDays -lt 1) { throw 'LookbackDays must be a positive number of days.' }
    if ($Start -lt [datetime]::UtcNow.AddDays(-$LookbackDays)) {
        Write-Warning 'WindowStart is earlier than the requested lookback. Increase LookbackDays; the incident window may not be covered.'
    }
}
