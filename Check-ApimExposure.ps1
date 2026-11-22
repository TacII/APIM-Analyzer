#Requires -Version 7
<#
Checks every enabled subscription you can see for Azure API Management Classic instances
and writes CSVs to .\apim-exposure\ . Read-only. Needs Reader on the subscriptions.
Run `az login` first (az CLI).

Which instances are in scope:
  1. Microsoft's own list of impacted resources, when available - from -ImpactedResourcesCsv (Service Health >
     Security advisories > the advisory > Impacted Resources > Export to CSV), or read from the Service Health
     API if your account may (Owner/Contributor or a role with Microsoft.ResourceHealth/events/fetchEventDetails/action).
  2. Otherwise: Classic dedicated tiers (Developer, Basic, Standard, Premium). v2 tiers are not affected, and
     Consumption instances were not listed by Microsoft in the tenants checked so far; add -IncludeConsumption
     to include them anyway.

Author:  Mathias Haas, Fidelity Consulting AB
Contact: bWF0aGlhcy5oYWFzQGZpZGVsaXR5Y29uc3VsdGluZy5zZQ== (base64)
License: MIT (see LICENSE). Provided as is, without warranty.
#>
param(
    [string]$ImpactedResourcesCsv,   # export of Microsoft's impacted-resources list for the advisory
    [switch]$IncludeConsumption      # without a Microsoft list: treat Consumption instances as in scope too
)
$ErrorActionPreference = 'Stop'
$out = Join-Path $PWD 'apim-exposure'
New-Item -ItemType Directory -Force $out | Out-Null

# ARM calls go straight to the REST API with a token from az, not through `az rest`. On Windows az is az.cmd,
# which runs via cmd.exe and cuts URLs at '&' - so every nextLink (…&$skip=100) silently returned page 1 again.
$script:armToken = $null
function Get-ArmToken {
    if (-not $script:armToken -or $script:armToken.expires -lt [DateTimeOffset]::UtcNow.AddMinutes(5)) {
        $t = az account get-access-token --resource 'https://management.azure.com/' -o json | ConvertFrom-Json
        if ($LASTEXITCODE -ne 0 -or -not $t.accessToken) { throw 'Could not get an Azure Resource Manager token. Run az login.' }
        $exp = if ($t.expires_on) { [DateTimeOffset]::FromUnixTimeSeconds([long]$t.expires_on) } else { [DateTimeOffset]::new([datetime]$t.expiresOn) }
        $script:armToken = @{ value = $t.accessToken; expires = $exp }
    }
    return $script:armToken.value
}
# Returns @{ ok; data } or @{ ok = $false; error }. Retries throttling (429) and server errors a few times.
function Invoke-Arm([string]$Method, [string]$Url, $Body) {
    for ($try = 1; ; $try++) {
        $p = @{ Method = $Method; Uri = $Url; Headers = @{ Authorization = "Bearer $(Get-ArmToken)" } }
        if ($null -ne $Body) { $p.Body = ($Body | ConvertTo-Json -Depth 10 -Compress); $p.ContentType = 'application/json' }
        try { return [pscustomobject]@{ ok = $true; data = (Invoke-RestMethod @p) } }
        catch {
            $code = 0; try { $code = [int]$_.Exception.Response.StatusCode } catch { }
            if ($try -lt 4 -and ($code -eq 429 -or $code -ge 500)) { Start-Sleep -Seconds ([Math]::Pow(2, $try)); continue }
            $msg = if ($_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { $_.Exception.Message }
            return [pscustomobject]@{ ok = $false; error = "HTTP $code $msg" }
        }
    }
}

# Resource Graph through its REST API rather than `az graph query`: this pages through all results and
# accepts authorizationScopeFilter, which is needed to see role assignments inherited from management groups.
function Invoke-Graph([string]$Query, [string[]]$Subs, [string]$ScopeFilter) {
    for ($c = 0; $c -lt $Subs.Count; $c += 1000) {
        $chunk = @($Subs[$c..([Math]::Min($c + 999, $Subs.Count - 1))])
        $got = 0; $skip = $null
        do {
            $opts = [ordered]@{ '$top' = 1000; resultFormat = 'objectArray' }
            if ($skip) { $opts['$skipToken'] = $skip }
            if ($ScopeFilter) { $opts['authorizationScopeFilter'] = $ScopeFilter }
            $res = Invoke-Arm POST 'https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-06-01-preview' `
                @{ subscriptions = $chunk; query = $Query; options = $opts }
            if (-not $res.ok) { throw "Resource Graph query failed: $($res.error)" }
            $r = $res.data
            foreach ($d in @($r.data)) { $got++; $d }
            $skip = $r.'$skipToken'
        } while ($skip)
        if ($r.totalRecords -gt $got) { throw "Result truncated ($got of $($r.totalRecords)) - the query is not being applied as intended." }
    }
}

$subs = @(az account list --query "[?state=='Enabled'].id" -o tsv)
Write-Host "Searching $($subs.Count) subscriptions..."

# 1. All APIM instances, with tier, network settings and identity
$q = @"
resources
| where type =~ 'microsoft.apimanagement/service'
| project id, name, subscriptionId, resourceGroup, location,
    sku = tostring(sku.name),
    platformVersion = tostring(properties.platformVersion),
    vnetType = tostring(properties.virtualNetworkType),
    publicAccess = tostring(properties.publicNetworkAccess),
    privateEndpoints = array_length(properties.privateEndpointConnections),
    publicIPs = tostring(properties.publicIPAddresses),
    privateIPs = tostring(properties.privateIPAddresses),
    identity = tostring(identity)
"@
$apim = @(Invoke-Graph $q $subs)
$apim | Export-Csv "$out\apim-instances.csv"

# 1a. Scope. Microsoft's own impacted-resources list wins; otherwise Classic dedicated tiers.
$listed = $null; $scopeSource = 'rule: Classic dedicated tiers (Developer, Basic, Standard, Premium)' + $(if ($IncludeConsumption) { ' + Consumption' } else { '' })
function Get-ResourceName([string]$Id) { if ($Id) { ($Id.TrimEnd('/') -split '/')[-1] } }
# Tier family from the SKU. Note: stv2/stv2.1 in platformVersion is the compute platform of the *Classic* tiers,
# not the v2 tiers. The v2 tiers are the SKUs BasicV2, StandardV2 and PremiumV2.
function Get-TierFamily([string]$Sku) {
    if ($Sku -match 'V2$') { return 'v2' }
    if ($Sku -eq 'Consumption') { return 'Classic (Consumption)' }
    return 'Classic'
}
# A Microsoft list holds full resource IDs where available (preferred) and bare names otherwise.
function New-ImpactedList { [pscustomobject]@{ ids = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                                               names = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase) } }
function Add-Impacted($List, [string]$ResourceId, [string]$Name) {
    if ($ResourceId -and $ResourceId -match '^/subscriptions/') { [void]$List.ids.Add($ResourceId.TrimEnd('/')) }
    elseif ($Name) { [void]$List.names.Add($Name.Trim()) }
}
# Scope decision for one instance. $Listed is $null without a Microsoft list.
function Get-ScopeDecision($Instance, $Listed, [switch]$IncludeConsumption) {
    $family = Get-TierFamily $Instance.sku
    $d = { param($in, $reason) [pscustomobject]@{ inScope = $in; tierFamily = $family; reason = $reason } }
    if ($Listed) {
        $isListed = $Listed.ids.Contains("$($Instance.id)".TrimEnd('/')) -or $Listed.names.Contains("$($Instance.name)")
        if (-not $isListed) { return & $d $false 'not listed by Microsoft' }
        # v2 tiers are not affected. A listed v2 instance was most likely migrated after the incident: keep it in
        # scope (its secrets may have been exposed while it was Classic) but never rate it LIKELY EXPOSED.
        if ($family -eq 'v2') { return & $d $true 'listed by Microsoft, but now a v2 tier (migrated after the incident?)' }
        return & $d $true 'listed by Microsoft'
    }
    if ($family -eq 'v2') { return & $d $false 'v2 tier (not affected)' }
    if ($family -eq 'Classic (Consumption)' -and -not $IncludeConsumption) { return & $d $false 'Consumption tier: not listed by Microsoft in the tenants checked (-IncludeConsumption to include)' }
    return & $d $true "Classic dedicated tier (platform $(if ($Instance.platformVersion) { $Instance.platformVersion } else { 'unknown' }))"
}

# Status for an in-scope instance. A v2-tier instance is never rated LIKELY EXPOSED (it is only in scope when
# Microsoft lists it, i.e. it was Classic during the incident and has been migrated since).
# Console label: the status plus tier family and platform, e.g. "LIKELY EXPOSED [Classic, stv2.1]", so that a
# Classic instance on platform stv2.1 cannot be mistaken for a v2-tier instance.
function Get-StatusLabel([string]$Status, [string]$TierFamily, [string]$PlatformVersion) {
    $parts = @(@($TierFamily, $PlatformVersion) | Where-Object { $_ })
    if ($parts.Count) { return "$Status [$($parts -join ', ')]" }
    return $Status
}
function Get-InstanceStatus([switch]$Unchecked, [string]$TierFamily, [switch]$NoNetwork, [switch]$SecretsHeld) {
    if ($Unchecked) { return 'UNCHECKED' }
    if ($TierFamily -eq 'v2') { return 'REVIEW (v2 tier)' }
    if ($NoNetwork -or $SecretsHeld) { return 'LIKELY EXPOSED' }
    return 'REVIEW'
}

if ($ImpactedResourcesCsv) {
    # The portal export's column names vary; accept a resource ID column, or a service/resource name column
    $listed = New-ImpactedList
    foreach ($r in @(Import-Csv $ImpactedResourcesCsv)) {
        $cols = @{}; foreach ($p in $r.PSObject.Properties) { $cols[($p.Name -replace '[\s_]', '').ToLower()] = "$($p.Value)".Trim() }
        $rid = if ($cols['resourceid']) { $cols['resourceid'] } else { $cols['targetresourceid'] }
        $nm = if ($cols['servicename']) { $cols['servicename'] } elseif ($cols['resourcename']) { $cols['resourcename'] } else { $cols['name'] }
        Add-Impacted $listed $rid $nm
    }
    if (-not ($listed.ids.Count + $listed.names.Count)) { throw "No resources found in $ImpactedResourcesCsv (expected a 'Resource ID', 'Service Name' or 'Resource Name' column)." }
    $scopeSource = "Microsoft's impacted-resources list from $ImpactedResourcesCsv ($($listed.ids.Count + $listed.names.Count) resources)"
} else {
    $events = @(Invoke-Graph "servicehealthresources | where type =~ 'microsoft.resourcehealth/events' | extend p = properties | where tostring(p.EventType) =~ 'SecurityAdvisory' and tostring(p.Title) contains 'API Management' and tostring(p.Title) contains 'Classic' | project trackingId = name, subscriptionId, title = tostring(p.Title)" $subs)
    if ($events.Count) {
        $tmp = New-ImpactedList; $denied = @()
        foreach ($e in $events) {
            $url = "https://management.azure.com/subscriptions/$($e.subscriptionId)/providers/Microsoft.ResourceHealth/events/$($e.trackingId)/listSecurityAdvisoryImpactedResources?api-version=2022-10-01"
            while ($url) {
                $res = Invoke-Arm POST $url
                if (-not $res.ok) { $denied += $e.subscriptionId; break }
                foreach ($v in @($res.data.value)) { $tr = "$($v.properties.targetResourceId)"; Add-Impacted $tmp $tr (Get-ResourceName $tr) }
                $url = $res.data.nextLink
            }
        }
        $ids = (@($events.trackingId) | Sort-Object -Unique) -join ', '
        if (-not $denied.Count) { $listed = $tmp; $scopeSource = "Microsoft's impacted-resources list (Service Health advisory $ids, $($listed.ids.Count + $listed.names.Count) resources)" }
        else {
            Write-Warning ("Service Health advisory $ids found, but its impacted-resources list could not be read for $(@($denied | Sort-Object -Unique).Count) subscription(s). " +
                "That needs e.g. Owner/Contributor or a role with Microsoft.ResourceHealth/events/fetchEventDetails/action. " +
                "Export the list from Service Health > Security advisories > Impacted Resources and pass it with -ImpactedResourcesCsv. Falling back to the tier rule.")
        }
    }
}
$scope = foreach ($i in $apim) {
    $dec = Get-ScopeDecision $i $listed -IncludeConsumption:$IncludeConsumption
    [pscustomobject]@{ id = $i.id; name = $i.name; subscriptionId = $i.subscriptionId; sku = $i.sku; tierFamily = $dec.tierFamily; platformVersion = $i.platformVersion
                       inScope = $dec.inScope; reason = $dec.reason; scopeSource = $(if ($listed) { 'microsoft' } else { 'rule' }) }
}
$scope | Export-Csv "$out\scope.csv"
$inScopeIds = @($scope | Where-Object inScope | ForEach-Object { $_.id })
$classic = @($apim | Where-Object { $_.id -in $inScopeIds })
$outOfScope = @($scope | Where-Object { -not $_.inScope })
Write-Host "Scope: $scopeSource"
Write-Host 'Note: stv2/stv2.1 (platformVersion) is the compute platform of the Classic tiers, not the v2 tiers (BasicV2/StandardV2/PremiumV2).' -ForegroundColor DarkGray
Write-Host "APIM instances: $($apim.Count) total, $($classic.Count) in scope, $($outOfScope.Count) out of scope"
$scope | Where-Object inScope | Format-Table name, subscriptionId, sku, tierFamily, platformVersion, reason -AutoSize
if ($outOfScope.Count) { $outOfScope | Format-Table name, sku, tierFamily, platformVersion, reason -AutoSize }
$v2Listed = @($scope | Where-Object { $_.inScope -and $_.tierFamily -eq 'v2' })
if ($v2Listed.Count) { Write-Warning "Listed by Microsoft but now a v2 tier (rated REVIEW, not LIKELY EXPOSED): $($v2Listed.name -join ', '). Check whether they were migrated from Classic after the incident." }
if ($listed) {
    $unknown = @(@($listed.ids | Where-Object { $_ -notin @($apim | ForEach-Object { "$($_.id)".TrimEnd('/') }) }) + @($listed.names | Where-Object { $_ -notin @($apim.name) }))
    if ($unknown.Count) { Write-Warning "Listed by Microsoft but not visible to this account: $(($unknown | ForEach-Object { Get-ResourceName $_ }) -join ', ')" }
}

# 1b. Preflight: direct per-subscription check. Resource Graph silently hides what you can't read;
# a direct call returns 403 instead, and an empty list here means "really none".
$n = 0
$pre = foreach ($s in $subs) {
    $n++; Write-Host "Preflight $n/$($subs.Count): $s"
    $direct = 0; $err = $null
    $url = "https://management.azure.com/subscriptions/$s/providers/Microsoft.ApiManagement/service?api-version=2024-05-01"
    while ($url -and -not $err) {
        $res = Invoke-Arm GET $url
        if ($res.ok) { $direct += @($res.data.value).Count; $url = $res.data.nextLink } else { $err = $res.error }
    }
    if (-not $err) {
        $viaGraph = @($apim | Where-Object { $_.subscriptionId -eq $s }).Count
        [pscustomobject]@{ subscriptionId = $s; access = 'OK'; apimDirect = $direct; apimViaGraph = $viaGraph
                           mismatch = ($direct -ne $viaGraph); detail = '' }
    } else {
        [pscustomobject]@{ subscriptionId = $s; access = 'DENIED/ERROR'; apimDirect = $null; apimViaGraph = $null
                           mismatch = $true; detail = ($err -split "`n")[0] }
    }
}
$pre | Export-Csv "$out\subscription-access.csv"
$bad = @($pre | Where-Object { $_.access -ne 'OK' })
$mm = @($pre | Where-Object { $_.access -eq 'OK' -and $_.mismatch })
Write-Host "Preflight: $(@($pre | Where-Object access -eq 'OK').Count) of $($subs.Count) subscriptions readable"
if ($bad.Count) { Write-Warning "NOT CHECKED (no access or error): $($bad.subscriptionId -join ', ')" }
if ($mm.Count) { Write-Warning "Graph and direct counts differ for: $($mm.subscriptionId -join ', ') - results may be incomplete" }
if (-not $bad.Count -and -not $mm.Count) { Write-Host 'Preflight clean: every subscription was readable and counts agree.' -ForegroundColor Green }

# 2. Named values and other secret-bearing objects on Classic instances
$script:failures = @()
# A pricing tier that does not support an object kind (e.g. identity providers on Consumption) is not a failure:
# there is nothing of that kind to expose.
function Test-NotInTier([string]$Err) { return $Err -match 'MethodNotAllowedInPricingTier' }
function Get-Paged([string]$Url) {
    $orig = $Url
    while ($Url) {
        $res = Invoke-Arm GET $Url
        if (-not $res.ok) {
            if (-not (Test-NotInTier $res.error)) { $script:failures += [pscustomobject]@{ url = $orig; error = $res.error } }
            return
        }
        $res.data.value
        $Url = $res.data.nextLink
    }
}
function Get-One([string]$Url) {
    $res = Invoke-Arm GET $Url
    if (-not $res.ok) {
        if (-not (Test-NotInTier $res.error)) { $script:failures += [pscustomobject]@{ url = $Url; error = $res.error } }
        return $null
    }
    return $res.data
}
# Principal IDs (lower-case) of the instance's managed identities. An identity block of type 'None' has none.
function Get-PrincipalIds($Identity) {
    if (-not $Identity) { return @() }
    $idn = if ($Identity -is [string]) { $Identity | ConvertFrom-Json } else { $Identity }
    if (-not $idn -or $idn.type -eq 'None') { return @() }
    $ids = @()
    if ($idn.principalId) { $ids += $idn.principalId }
    if ($idn.userAssignedIdentities) { $ids += @($idn.userAssignedIdentities.PSObject.Properties.Value | ForEach-Object { $_.principalId }) }
    return @($ids | Where-Object { $_ } | ForEach-Object { "$_".ToLower() } | Sort-Object -Unique)
}
$base = 'https://management.azure.com'
$api = 'api-version=2024-05-01'
$nvRows = @(); $otherRows = @(); $subRows = @(); $principals = @()
$tenantInfo = @{}; $instPrincipals = @{}

foreach ($i in $classic) {
    Write-Host "Inspecting $($i.name)"
    try {
        foreach ($v in Get-Paged "$base$($i.id)/namedValues?$api") {
            # 'Logger-Credentials-…' named values are created by APIM for Application Insights loggers (instrumentation
            # key / connection string). They are kept apart from other secrets: low impact, but often left behind in bulk.
            $nvRows += [pscustomobject]@{
                apim = $i.name; subscriptionId = $i.subscriptionId; namedValue = $v.name; displayName = $v.properties.displayName
                secret = $v.properties.secret; inKeyVault = [bool]$v.properties.keyVault
                loggerCredential = ("$($v.properties.displayName)" -like 'Logger-Credentials*')
            }
        }
        foreach ($kind in 'identityProviders','openidConnectProviders','authorizationServers','backends','loggers','authorizationProviders') {
            foreach ($v in Get-Paged "$base$($i.id)/$($kind)?$api") {
                $otherRows += [pscustomobject]@{ apim = $i.name; subscriptionId = $i.subscriptionId; kind = $kind; name = $v.name; storedIn = '' }
            }
        }
        # Certificates uploaded directly (private key held by APIM) versus referenced from Key Vault
        foreach ($v in Get-Paged "$base$($i.id)/certificates?$api") {
            $otherRows += [pscustomobject]@{ apim = $i.name; subscriptionId = $i.subscriptionId; kind = 'certificates'; name = $v.name
                                             storedIn = if ($v.properties.keyVault) { 'Key Vault' } else { 'APIM' } }
        }
        # APIM subscriptions: their keys live in APIM. Only metadata is read here, never the keys themselves.
        foreach ($v in Get-Paged "$base$($i.id)/subscriptions?$api") {
            $subRows += [pscustomobject]@{ apim = $i.name; subscriptionId = $i.subscriptionId; apimSubscription = $v.name
                                           displayName = $v.properties.displayName; scope = $v.properties.scope; state = $v.properties.state }
        }
        # Direct management API (management tokens) and Git configuration access. Not available on Consumption.
        if ($i.sku -eq 'Consumption') {
            $tenantInfo[$i.id] = [pscustomobject]@{ directMgmtApi = 'n/a'; gitAccess = 'n/a' }
        } else {
            $ta = Get-One "$base$($i.id)/tenant/access?$api"
            $ga = Get-One "$base$($i.id)/tenant/gitAccess?$api"
            $tenantInfo[$i.id] = [pscustomobject]@{
                directMgmtApi = if ($ta) { [bool]$ta.properties.enabled } else { 'unknown' }
                gitAccess     = if ($ga) { [bool]$ga.properties.enabled } else { 'unknown' }
            }
        }
    } catch {
        Write-Warning "$($i.name): $($_.Exception.Message)"
        $script:failures += [pscustomobject]@{ url = "$base$($i.id)/namedValues?$api"; error = "inspection aborted: $($_.Exception.Message)" }
    }

    $p = @(Get-PrincipalIds $i.identity)
    $instPrincipals[$i.id] = $p
    $principals += $p
}
$script:failures | Export-Csv "$out\failed-calls.csv"
if ($script:failures.Count) {
    Write-Warning "$($script:failures.Count) API calls failed - see failed-calls.csv (incomplete results for those instances/objects)"
    $script:failures | Where-Object { $_.url -match '/namedValues\?' } |
        ForEach-Object { Write-Warning "NAMED VALUES NOT CHECKED: $($_.url)" }
}
$nvRows | Export-Csv "$out\named-values.csv"
$otherRows | Export-Csv "$out\other-secret-objects.csv"
$subRows | Export-Csv "$out\apim-subscriptions.csv"
$exposed = @($nvRows | Where-Object { $_.secret -and -not $_.inKeyVault -and -not $_.loggerCredential })
$loggerCreds = @($nvRows | Where-Object { $_.secret -and -not $_.inKeyVault -and $_.loggerCredential })
Write-Host "Secret named values stored in APIM (not Key Vault): $($exposed.Count), plus $($loggerCreds.Count) logger credentials"
Write-Host "Certificates stored in APIM (not Key Vault): $(@($otherRows | Where-Object { $_.kind -eq 'certificates' -and $_.storedIn -eq 'APIM' }).Count)"

# 3. What can the APIM managed identities reach? (RBAC assignments + Key Vault access policies)
$principals = @($principals | Where-Object { $_ } | Sort-Object -Unique)
if ($principals.Count) {
    $list = ($principals | ForEach-Object { "'$_'" }) -join ','
    # AtScopeAboveAndBelow also returns assignments inherited from management groups and the tenant root.
    $rbac = @(Invoke-Graph @"
authorizationresources
| where type =~ 'microsoft.authorization/roleassignments'
| where tolower(tostring(properties.principalId)) in ($list)
| project id, principalId = tolower(tostring(properties.principalId)), scope = tostring(properties.scope),
    roleDefinitionId = tostring(properties.roleDefinitionId)
"@ $subs 'AtScopeAboveAndBelow' | Sort-Object id -Unique)
    $rbac | Export-Csv "$out\identity-role-assignments.csv"

    $vaults = @(Invoke-Graph @"
resources
| where type =~ 'microsoft.keyvault/vaults'
| mv-expand ap = properties.accessPolicies
| where tolower(tostring(ap.objectId)) in ($list)
| project id, vault = name, subscriptionId, objectId = tolower(tostring(ap.objectId)),
    secrets = tostring(ap.permissions.secrets), keys = tostring(ap.permissions.keys)
"@ $subs)
    $vaults | Export-Csv "$out\identity-keyvault-access-policies.csv"
    Write-Host "Role assignments: $($rbac.Count); Key Vault access-policy entries: $($vaults.Count)"
}
# 4. One-line verdict per in-scope instance (also saved to summary.csv, followed by the out-of-scope instances)
$secretKinds = 'certificates','identityProviders','openidConnectProviders','authorizationServers'
Write-Host "`n=== Per-instance summary (in-scope instances) ==="
$summary = foreach ($i in $classic) {
    $mine = @($nvRows | Where-Object { $_.apim -eq $i.name -and $_.subscriptionId -eq $i.subscriptionId })
    $mineOther = @($otherRows | Where-Object { $_.apim -eq $i.name -and $_.subscriptionId -eq $i.subscriptionId })
    $inApim = @($mine | Where-Object { $_.secret -and -not $_.inKeyVault -and -not $_.loggerCredential }).Count
    $loggerInApim = @($mine | Where-Object { $_.secret -and -not $_.inKeyVault -and $_.loggerCredential }).Count
    $inKv = @($mine | Where-Object { $_.inKeyVault }).Count
    $certsInApim = @($mineOther | Where-Object { $_.kind -eq 'certificates' -and $_.storedIn -eq 'APIM' }).Count
    $clientSecretObjs = @($mineOther | Where-Object { $_.kind -in 'identityProviders','openidConnectProviders','authorizationServers' }).Count
    $activeSubs = @($subRows | Where-Object { $_.apim -eq $i.name -and $_.subscriptionId -eq $i.subscriptionId -and $_.state -eq 'active' }).Count
    # Which object kinds failed to list for this instance, e.g. 'namedValues', 'certificates', 'tenant/access'
    $failedKinds = @($script:failures | Where-Object { $_.url -like "*$($i.id)/*" } |
        ForEach-Object { ($_.url -replace '^.*/service/[^/]+/', '') -replace '\?.*$', '' })
    $nvFailed = 'namedValues' -in $failedKinds
    $otherFailed = @($failedKinds | Where-Object { $_ -in $secretKinds }).Count -gt 0
    $ti = $tenantInfo[$i.id]
    $pe = [int]$i.privateEndpoints
    $noNet = ($i.vnetType -eq 'None' -and $pe -eq 0)
    $sc = $scope | Where-Object id -eq $i.id | Select-Object -First 1
    $status = Get-InstanceStatus -Unchecked:($nvFailed -or $otherFailed) -TierFamily $sc.tierFamily -NoNetwork:$noNet `
                                 -SecretsHeld:($inApim -gt 0 -or $certsInApim -gt 0 -or $clientSecretObjs -gt 0)
    $row = [pscustomobject]@{
        status = $status; apim = $i.name; subscriptionId = $i.subscriptionId; sku = $i.sku
        vnetType = $i.vnetType; publicAccess = $i.publicAccess; privateEndpoints = $pe
        secretsInApim = if ($nvFailed) { 'n/a' } else { $inApim }; secretsInKeyVault = if ($nvFailed) { 'n/a' } else { $inKv }
        loggerCredentials = if ($nvFailed) { 'n/a' } else { $loggerInApim }
        certsInApim = if ($otherFailed) { 'n/a' } else { $certsInApim }
        clientSecretObjects = if ($otherFailed) { 'n/a' } else { $clientSecretObjs }
        activeSubscriptions = if ('subscriptions' -in $failedKinds) { 'n/a' } else { $activeSubs }
        directMgmtApi = if ($ti) { $ti.directMgmtApi } else { 'unknown' }
        gitAccess = if ($ti) { $ti.gitAccess } else { 'unknown' }
        hasManagedIdentity = (@($instPrincipals[$i.id]).Count -gt 0)
        tierFamily = $sc.tierFamily; platformVersion = $i.platformVersion; scope = $sc.reason
    }
    $color = switch ($status) { 'UNCHECKED' { 'Red' } 'LIKELY EXPOSED' { 'Yellow' } default { 'Gray' } }
    Write-Host ("{0,-38} {1} [{2}] {3} | vnet={4} public={5} PE={6} | secrets in APIM: {7}, in Key Vault: {8}, logger creds: {9}, certs in APIM: {10}, client-secret objects: {11} | active subscriptions: {12} | direct mgmt API: {13}, git: {14} | identity: {15}" -f `
        (Get-StatusLabel $row.status $sc.tierFamily $i.platformVersion), $row.apim, $row.subscriptionId, $row.sku, $row.vnetType, $row.publicAccess, $row.privateEndpoints,
        $row.secretsInApim, $row.secretsInKeyVault, $row.loggerCredentials, $row.certsInApim, $row.clientSecretObjects, $row.activeSubscriptions,
        $row.directMgmtApi, $row.gitAccess, $row.hasManagedIdentity) -ForegroundColor $color
    $row
}
# Out-of-scope instances are listed with the same columns, so the summary accounts for every instance
$summary = @($summary) + @(foreach ($o in $outOfScope) {
    $a = $apim | Where-Object id -eq $o.id | Select-Object -First 1
    [pscustomobject]@{
        status = 'OUT OF SCOPE'; apim = $o.name; subscriptionId = $o.subscriptionId; sku = $o.sku
        vnetType = $a.vnetType; publicAccess = $a.publicAccess; privateEndpoints = [int]$a.privateEndpoints
        secretsInApim = ''; secretsInKeyVault = ''; loggerCredentials = ''; certsInApim = ''; clientSecretObjects = ''; activeSubscriptions = ''
        directMgmtApi = ''; gitAccess = ''; hasManagedIdentity = ''; tierFamily = $o.tierFamily; platformVersion = $o.platformVersion; scope = $o.reason
    }
})
foreach ($o in $outOfScope) { Write-Host ("{0,-38} {1} {2} ({3})" -f (Get-StatusLabel 'OUT OF SCOPE' $o.tierFamily $o.platformVersion), $o.name, $o.sku, $o.reason) -ForegroundColor DarkGray }
$summary | Export-Csv "$out\summary.csv"
Write-Host @"
Legend: LIKELY EXPOSED = no VNet/private endpoint and/or secrets held by APIM (matches Microsoft's conditions). Secrets held
                 by APIM means secret named values not in Key Vault, certificates uploaded directly, or identity provider /
                 OpenID Connect / authorization server configurations (these may carry client secrets).
        REVIEW = looks network-integrated with no APIM-held secrets, but compare against Microsoft's
                 'Network security' requirements and check Key Vault access (the managed identity may still reach vaults).
        UNCHECKED = named values, certificates or client-secret objects could not be read (see failed-calls.csv).
        OUT OF SCOPE = not listed by Microsoft, or (without a Microsoft list) a v2 or Consumption instance. See scope.csv.
        REVIEW (v2 tier) = listed by Microsoft but now a v2 tier (BasicV2/StandardV2/PremiumV2), probably migrated after the
                 incident. Its secrets may have been exposed while it was Classic; v2 itself is not affected.
        Tier family vs platform: stv2/stv2.1 is the compute platform of the Classic tiers, not the v2 tiers.
        Logger creds = Application Insights logger credentials APIM created itself; shown separately, not used in the status.
        Subscription keys exist on every instance with active subscriptions; direct mgmt API = True means management
        tokens could be issued. Both are listed for rotation planning, not used in the status.
        Git access is often reported as enabled without anyone turning it on; its keys exist either way and can be
        regenerated.
"@

Write-Host "Done. Output in $out"
