#Requires -Version 7
<#
Checks every enabled subscription you can see for Azure API Management Classic instances
and writes CSVs to .\apim-exposure\ . Read-only. Needs Reader on the subscriptions.
Run `az login` first (az CLI).

Author:  Mathias Haas, Fidelity Consulting AB
Contact: bWF0aGlhcy5oYWFzQGZpZGVsaXR5Y29uc3VsdGluZy5zZQ== (base64)
#>
$ErrorActionPreference = 'Stop'
$out = Join-Path $PWD 'apim-exposure'
New-Item -ItemType Directory -Force $out | Out-Null

# Resource Graph through its REST API rather than `az graph query`: this pages through all results and
# accepts authorizationScopeFilter, which is needed to see role assignments inherited from management groups.
function Invoke-Graph([string]$Query, [string[]]$Subs, [string]$ScopeFilter) {
    $tmp = New-TemporaryFile
    try {
        for ($c = 0; $c -lt $Subs.Count; $c += 1000) {
            $chunk = @($Subs[$c..([Math]::Min($c + 999, $Subs.Count - 1))])
            $got = 0; $skip = $null
            do {
                $opts = [ordered]@{ '$top' = 1000; resultFormat = 'objectArray' }
                if ($skip) { $opts['$skipToken'] = $skip }
                if ($ScopeFilter) { $opts['authorizationScopeFilter'] = $ScopeFilter }
                @{ subscriptions = $chunk; query = $Query; options = $opts } | ConvertTo-Json -Depth 5 -Compress |
                    Set-Content $tmp -Encoding utf8
                $raw = az rest --method post --url 'https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-06-01-preview' `
                    --body "@$($tmp.FullName)" --headers 'Content-Type=application/json' -o json 2>&1
                if ($LASTEXITCODE -ne 0) { throw "Resource Graph query failed: $(($raw | Out-String).Trim())" }
                $r = $raw | ConvertFrom-Json
                foreach ($d in @($r.data)) { $got++; $d }
                $skip = $r.'$skipToken'
            } while ($skip)
            if ($r.totalRecords -gt $got) { throw "Result truncated ($got of $($r.totalRecords)) - the query is not being applied as intended." }
        }
    } finally { Remove-Item $tmp -ErrorAction SilentlyContinue }
}

$subs = @(az account list --query "[?state=='Enabled'].id" -o tsv)
Write-Host "Searching $($subs.Count) subscriptions..."

# 1. All APIM instances, with tier, network settings and identity
$q = @"
resources
| where type =~ 'microsoft.apimanagement/service'
| project id, name, subscriptionId, resourceGroup, location,
    sku = tostring(sku.name),
    vnetType = tostring(properties.virtualNetworkType),
    publicAccess = tostring(properties.publicNetworkAccess),
    privateEndpoints = array_length(properties.privateEndpointConnections),
    publicIPs = tostring(properties.publicIPAddresses),
    privateIPs = tostring(properties.privateIPAddresses),
    identity = tostring(identity)
"@
$apim = @(Invoke-Graph $q $subs)
$apim | Export-Csv "$out\apim-instances.csv"
$classic = @($apim | Where-Object { $_.sku -notmatch 'V2$' })
Write-Host "APIM instances: $($apim.Count) total, $($classic.Count) Classic (not v2)"
$classic | Format-Table name, subscriptionId, sku, vnetType, publicAccess, privateEndpoints -AutoSize

# 1b. Preflight: direct per-subscription check. Resource Graph silently hides what you can't read;
# a direct call returns 403 instead, and an empty list here means "really none".
$n = 0
$pre = foreach ($s in $subs) {
    $n++; Write-Host "Preflight $n/$($subs.Count): $s"
    $raw = az rest --method get --url "https://management.azure.com/subscriptions/$s/providers/Microsoft.ApiManagement/service?api-version=2024-05-01" -o json 2>&1
    if ($LASTEXITCODE -eq 0) {
        $direct = @(($raw | ConvertFrom-Json).value).Count
        $viaGraph = @($apim | Where-Object { $_.subscriptionId -eq $s }).Count
        [pscustomobject]@{ subscriptionId = $s; access = 'OK'; apimDirect = $direct; apimViaGraph = $viaGraph
                           mismatch = ($direct -ne $viaGraph); detail = '' }
    } else {
        [pscustomobject]@{ subscriptionId = $s; access = 'DENIED/ERROR'; apimDirect = $null; apimViaGraph = $null
                           mismatch = $true; detail = (($raw | Out-String).Trim() -split "`n")[0] }
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
function Get-Paged([string]$Url) {
    $orig = $Url
    while ($Url) {
        $raw = az rest --method get --url $Url -o json 2>&1
        if ($LASTEXITCODE -ne 0) {
            $script:failures += [pscustomobject]@{ url = $orig; error = ($raw | Out-String).Trim() }
            return
        }
        $r = $raw | ConvertFrom-Json
        $r.value
        $Url = $r.nextLink
    }
}
function Get-One([string]$Url) {
    $raw = az rest --method get --url $Url -o json 2>&1
    if ($LASTEXITCODE -ne 0) {
        $script:failures += [pscustomobject]@{ url = $Url; error = ($raw | Out-String).Trim() }
        return $null
    }
    return ($raw | ConvertFrom-Json)
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
            $nvRows += [pscustomobject]@{
                apim = $i.name; subscriptionId = $i.subscriptionId; namedValue = $v.name
                secret = $v.properties.secret; inKeyVault = [bool]$v.properties.keyVault
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
$exposed = @($nvRows | Where-Object { $_.secret -and -not $_.inKeyVault })
Write-Host "Secret named values stored in APIM (not Key Vault): $($exposed.Count)"
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
# 4. One-line verdict per Classic instance (also saved to summary.csv)
$secretKinds = 'certificates','identityProviders','openidConnectProviders','authorizationServers'
Write-Host "`n=== Per-instance summary (Classic tier only) ==="
$summary = foreach ($i in $classic) {
    $mine = @($nvRows | Where-Object { $_.apim -eq $i.name -and $_.subscriptionId -eq $i.subscriptionId })
    $mineOther = @($otherRows | Where-Object { $_.apim -eq $i.name -and $_.subscriptionId -eq $i.subscriptionId })
    $inApim = @($mine | Where-Object { $_.secret -and -not $_.inKeyVault }).Count
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
    $status = if ($nvFailed -or $otherFailed) { 'UNCHECKED' }
              elseif ($noNet -or $inApim -gt 0 -or $certsInApim -gt 0 -or $clientSecretObjs -gt 0) { 'LIKELY EXPOSED' }
              else { 'REVIEW' }
    $row = [pscustomobject]@{
        status = $status; apim = $i.name; subscriptionId = $i.subscriptionId; sku = $i.sku
        vnetType = $i.vnetType; publicAccess = $i.publicAccess; privateEndpoints = $pe
        secretsInApim = if ($nvFailed) { 'n/a' } else { $inApim }; secretsInKeyVault = if ($nvFailed) { 'n/a' } else { $inKv }
        certsInApim = if ($otherFailed) { 'n/a' } else { $certsInApim }
        clientSecretObjects = if ($otherFailed) { 'n/a' } else { $clientSecretObjs }
        activeSubscriptions = if ('subscriptions' -in $failedKinds) { 'n/a' } else { $activeSubs }
        directMgmtApi = if ($ti) { $ti.directMgmtApi } else { 'unknown' }
        gitAccess = if ($ti) { $ti.gitAccess } else { 'unknown' }
        hasManagedIdentity = (@($instPrincipals[$i.id]).Count -gt 0)
    }
    $color = switch ($status) { 'UNCHECKED' { 'Red' } 'LIKELY EXPOSED' { 'Yellow' } default { 'Gray' } }
    Write-Host ("{0,-15} {1} [{2}] {3} | vnet={4} public={5} PE={6} | secrets in APIM: {7}, in Key Vault: {8}, certs in APIM: {9}, client-secret objects: {10} | active subscriptions: {11} | direct mgmt API: {12}, git: {13} | identity: {14}" -f `
        $row.status, $row.apim, $row.subscriptionId, $row.sku, $row.vnetType, $row.publicAccess, $row.privateEndpoints,
        $row.secretsInApim, $row.secretsInKeyVault, $row.certsInApim, $row.clientSecretObjects, $row.activeSubscriptions,
        $row.directMgmtApi, $row.gitAccess, $row.hasManagedIdentity) -ForegroundColor $color
    $row
}
$summary | Export-Csv "$out\summary.csv"
Write-Host @"
Legend: LIKELY EXPOSED = no VNet/private endpoint and/or secrets held by APIM (matches Microsoft's conditions). Secrets held
                 by APIM means secret named values not in Key Vault, certificates uploaded directly, or identity provider /
                 OpenID Connect / authorization server configurations (these may carry client secrets).
        REVIEW = looks network-integrated with no APIM-held secrets, but compare against Microsoft's
                 'Network security' requirements and check Key Vault access (the managed identity may still reach vaults).
        UNCHECKED = named values, certificates or client-secret objects could not be read (see failed-calls.csv).
        Subscription keys exist on every instance with active subscriptions; direct mgmt API = True means management
        tokens could be issued. Both are listed for rotation planning, not used in the status.
"@

Write-Host "Done. Output in $out"
