#Requires -Version 7
<#
Reviews Key Vault audit logs for signs that the APIM managed identities (or any other caller) read
vault contents around the APIM incident (18-19 Nov 2026). Standalone and read-only.

Needs: Reader on the subscriptions, and Log Analytics Reader on the workspaces that hold the vault logs.
Run `az login` first. Output goes to .\kv-audit\

Author:  Mathias Haas, Fidelity Consulting AB
Contact: bWF0aGlhcy5oYWFzQGZpZGVsaXR5Y29uc3VsdGluZy5zZQ== (base64)
License: MIT (see LICENSE). Provided as is, without warranty.
#>
param(
    [string]$OutDir = (Join-Path $PWD 'kv-audit'),
    [datetime]$WindowStart = '2026-11-16',   # UTC, inclusive: start of the period to scrutinise
    [datetime]$WindowEnd   = '2026-11-21',   # UTC, exclusive
    [int]$LookbackDays = 90                  # how far back to read logs (baseline = everything before WindowStart)
)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force $OutDir | Out-Null

# ARM calls go straight to the REST API with a token from az, not through `az rest`. On Windows az is az.cmd,
# which runs via cmd.exe and mangles URLs containing '&' or '%'.
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
# Returns the parsed response, or an object with _error. Retries throttling (429) and server errors a few times.
function Get-Json([string]$Method, [string]$Url, $Body) {
    for ($try = 1; ; $try++) {
        $p = @{ Method = $Method; Uri = $Url; Headers = @{ Authorization = "Bearer $(Get-ArmToken)" } }
        if ($null -ne $Body) { $p.Body = ($Body | ConvertTo-Json -Depth 10 -Compress); $p.ContentType = 'application/json' }
        try { return (Invoke-RestMethod @p) }
        catch {
            $code = 0; try { $code = [int]$_.Exception.Response.StatusCode } catch { }
            if ($try -lt 4 -and ($code -eq 429 -or $code -ge 500)) { Start-Sleep -Seconds ([Math]::Pow(2, $try)); continue }
            $msg = if ($_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { $_.Exception.Message }
            return [pscustomobject]@{ _error = "HTTP $code $msg" }
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
            $r = Get-Json POST 'https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-06-01-preview' `
                @{ subscriptions = $chunk; query = $Query; options = $opts }
            if ($r._error) { throw "Resource Graph query failed: $($r._error)" }
            foreach ($d in @($r.data)) { $got++; $d }
            $skip = $r.'$skipToken'
        } while ($skip)
        if ($r.totalRecords -gt $got) { throw "Result truncated ($got of $($r.totalRecords))." }
    }
}

function Expand-Json($v) {
    if ($v -is [string]) {
        if (-not $v.Trim()) { return $null }
        try { return $v | ConvertFrom-Json } catch { return $v }
    }
    return $v
}
function Get-Ips($v) {
    $x = Expand-Json $v
    if ($null -eq $x) { return @() }
    @($x) | ForEach-Object { "$_" } | Where-Object { $_ }
}

# ---- 1. APIM Classic instances and their managed identities -------------------------------------
$subs = @(az account list --query "[?state=='Enabled'].id" -o tsv)
Write-Host "Subscriptions: $($subs.Count)"
$apim = @(Invoke-Graph "resources | where type =~ 'microsoft.apimanagement/service' | project id, name, subscriptionId, sku = tostring(sku.name), publicIPs = properties.publicIPAddresses, privateIPs = properties.privateIPAddresses, identity" $subs |
    Where-Object { $_.sku -notmatch 'V2$' })
Write-Host "Classic APIM instances: $($apim.Count)"

$principalMap = @{}
foreach ($i in $apim) {
    $idn = Expand-Json $i.identity
    if (-not $idn -or $idn.type -eq 'None') { continue }
    $ids = @()
    if ($idn.principalId) { $ids += $idn.principalId }
    if ($idn.userAssignedIdentities) { $ids += @($idn.userAssignedIdentities.PSObject.Properties.Value | ForEach-Object { $_.principalId }) }
    foreach ($p in ($ids | Where-Object { $_ })) {
        $k = "$p".ToLower()
        if (-not $principalMap.ContainsKey($k)) { $principalMap[$k] = @() }
        $principalMap[$k] += $i
    }
}
if (-not $principalMap.Count) { Write-Warning 'No managed identities found on Classic APIM instances. Nothing to correlate; stopping.'; return }
Write-Host "Managed identities: $($principalMap.Count)"
$plist = ($principalMap.Keys | ForEach-Object { "'$_'" }) -join ','

# ---- 2. Which vaults can those identities reach? ------------------------------------------------
$vaults = @(Invoke-Graph "resources | where type =~ 'microsoft.keyvault/vaults' | project id, name, subscriptionId, rbacMode = tobool(properties.enableRbacAuthorization)" $subs)
# AtScopeAboveAndBelow also returns assignments inherited from management groups and the tenant root.
$rbac = @(Invoke-Graph "authorizationresources | where type =~ 'microsoft.authorization/roleassignments' | where tolower(tostring(properties.principalId)) in ($plist) | project id, principalId = tolower(tostring(properties.principalId)), scope = tostring(properties.scope), roleDefinitionId = tostring(properties.roleDefinitionId)" $subs 'AtScopeAboveAndBelow' |
    Sort-Object id -Unique)
$aps = @(Invoke-Graph "resources | where type =~ 'microsoft.keyvault/vaults' | mv-expand ap = properties.accessPolicies | where tolower(tostring(ap.objectId)) in ($plist) | project id, principalId = tolower(tostring(ap.objectId))" $subs)
# Management-group ancestry per subscription, to resolve which vaults sit under a management-group-scoped assignment
$subMgs = @{}
foreach ($c in @(Invoke-Graph "resourcecontainers | where type =~ 'microsoft.resources/subscriptions' | project id, subscriptionId, mgChain = properties.managementGroupAncestorsChain" $subs)) {
    $set = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($m in @(Expand-Json $c.mgChain)) { if ($m.name) { [void]$set.Add($m.name) } }
    $subMgs[$c.subscriptionId.ToLower()] = $set
}
Write-Host "Key Vaults visible: $($vaults.Count); role assignments for APIM identities: $($rbac.Count); access-policy entries: $($aps.Count)"

# Classify each role by what it allows on a vault. Wildcards in role definitions are matched with -like.
$kvDataOps = 'Microsoft.KeyVault/vaults/secrets/getSecret/action', 'Microsoft.KeyVault/vaults/keys/decrypt/action',
             'Microsoft.KeyVault/vaults/keys/unwrap/action', 'Microsoft.KeyVault/vaults/keys/sign/action'
$policyWriteOps = 'Microsoft.KeyVault/vaults/write', 'Microsoft.KeyVault/vaults/accessPolicies/write'
$grantOps = @('Microsoft.Authorization/roleAssignments/write')
function Test-Granted($Perms, [string]$AllowProp, [string]$DenyProp, [string[]]$Ops) {
    foreach ($op in $Ops) {
        foreach ($p in @($Perms)) {
            $allow = @($p.$AllowProp | Where-Object { $_ -and $op -like $_ }).Count
            $deny = @($p.$DenyProp | Where-Object { $_ -and $op -like $_ }).Count
            if ($allow -and -not $deny) { return $true }
        }
    }
    return $false
}
$roleCache = @{}
function Get-RoleInfo([string]$RoleDefinitionId) {
    $k = $RoleDefinitionId.ToLower()
    if (-not $roleCache.ContainsKey($k)) {
        $r = Get-Json GET "https://management.azure.com$($RoleDefinitionId)?api-version=2022-04-01"
        $roleCache[$k] = if ($r._error) {
            [pscustomobject]@{ name = "unresolved role $($RoleDefinitionId.Split('/')[-1])"; resolved = $false; data = $false; policyWrite = $false; grant = $false }
        } else {
            $perms = $r.properties.permissions
            [pscustomobject]@{
                name = $r.properties.roleName; resolved = $true
                data = Test-Granted $perms 'dataActions' 'notDataActions' $kvDataOps
                policyWrite = Test-Granted $perms 'actions' 'notActions' $policyWriteOps
                grant = Test-Granted $perms 'actions' 'notActions' $grantOps
            }
        }
    }
    return $roleCache[$k]
}
function Get-VaultsInScope([string]$Scope) {
    $s = $Scope.TrimEnd('/')
    if (-not $s) { return $vaults }   # tenant root scope '/'
    if ($s -match '^/providers/Microsoft\.Management/managementGroups/([^/]+)$') {
        $mg = $Matches[1]
        # Vaults whose subscription sits under that management group; unknown ancestry counts as in scope.
        return @($vaults | Where-Object { $set = $subMgs[$_.subscriptionId.ToLower()]; -not $set -or -not $set.Count -or $set.Contains($mg) })
    }
    # Scope at or above the vault (subscription, resource group, the vault itself), or below it (a single secret/key)
    return @($vaults | Where-Object {
        $_.id -eq $s -or $_.id.StartsWith("$s/", [StringComparison]::OrdinalIgnoreCase) -or $s.StartsWith("$($_.id)/", [StringComparison]::OrdinalIgnoreCase) })
}

$cand = @{}
function Add-Cand($v, $p, $via) {
    $k = $v.id.ToLower()
    if (-not $cand.ContainsKey($k)) {
        $cand[$k] = @{ vault = $v; principals = [System.Collections.Generic.HashSet[string]]::new(); via = [System.Collections.Generic.HashSet[string]]::new() }
    }
    [void]$cand[$k].principals.Add($p); [void]$cand[$k].via.Add($via)
}
foreach ($a in $aps) {
    $v = $vaults | Where-Object { $_.id -eq $a.id } | Select-Object -First 1
    if ($v) { Add-Cand $v $a.principalId $(if ($v.rbacMode) { 'access policy (inactive now: vault uses RBAC)' } else { 'access policy' }) }
}
# A role assignment makes a vault a candidate only if it gives data access on an RBAC vault, or a way to grant itself
# access (role assignments on any vault; vault/access-policy writes on an access-policy vault). Others are listed separately.
$excluded = @()
foreach ($r in $rbac) {
    $role = Get-RoleInfo $r.roleDefinitionId
    $inScope = @(Get-VaultsInScope $r.scope)
    $hit = 0
    foreach ($v in $inScope) {
        $how = if (-not $role.resolved) { 'role could not be resolved' }
               elseif ($v.rbacMode -and $role.data) { 'data access' }
               elseif ($role.grant) { 'can grant itself access' }
               elseif (-not $v.rbacMode -and $role.policyWrite) { 'can grant itself access via access policy' }
        if ($how) { Add-Cand $v $r.principalId "$($role.name) at $($r.scope) ($how)"; $hit++ }
    }
    if ($inScope.Count -and -not $hit) {
        $excluded += [pscustomobject]@{ principalId = $r.principalId; role = $role.name; scope = $r.scope; vaultsInScope = $inScope.Count
                                        reason = 'no Key Vault data access and no way to grant it' }
    }
}
$excluded | Export-Csv "$OutDir\excluded-role-assignments.csv"
Write-Host "Candidate vaults (reachable by an APIM identity as far as you can see): $($cand.Count); role assignments excluded as not granting vault access: $($excluded.Count)"
if (-not $cand.Count) { Write-Warning 'No candidate vaults found. This may just mean you cannot see the role assignments; ask a tenant admin.'; return }

# ---- 3. Was audit logging on, and where does it go? ---------------------------------------------
$n = 0
$logging = foreach ($k in $cand.Keys) {
    $n++; $v = $cand[$k].vault
    Write-Host "Diagnostic settings $n/$($cand.Count): $($v.name)"
    $r = Get-Json GET "https://management.azure.com$($v.id)/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview"
    $ws = $null; $note = ''
    if ($r._error) { $note = "ERROR: $($r._error)" }
    else {
        foreach ($d in @($r.value)) {
            $p = $d.properties
            $audit = @($p.logs | Where-Object { $_.enabled -and ($_.category -eq 'AuditEvent' -or $_.categoryGroup -in 'audit', 'allLogs') }).Count -gt 0
            if ($audit -and $p.workspaceId) { $ws = $p.workspaceId; break }
        }
        if (-not $ws) { $note = if (@($r.value).Count) { 'diagnostic settings exist but AuditEvent does not go to Log Analytics (storage/event hub only?)' } else { 'no diagnostic settings' } }
    }
    [pscustomobject]@{
        vaultId = $v.id; vault = $v.name; subscriptionId = $v.subscriptionId
        principals = ($cand[$k].principals -join ','); via = ($cand[$k].via -join '; ')
        workspaceId = $ws; note = $note
    }
}
$logging | Export-Csv "$OutDir\vault-logging.csv"

# ---- 4. Query the logs --------------------------------------------------------------------------
function Invoke-La([string]$ws, [string]$kql) {
    $r = Get-Json POST "https://management.azure.com$ws/api/query?api-version=2017-01-01-preview" @{ query = $kql; timespan = "P$($LookbackDays)D" }
    if ($r._error) { throw $r._error }
    $t = $r.tables[0]
    # This endpoint returns Columns[].ColumnName; the newer API returns columns[].name. Accept both.
    $cols = @($t.columns | ForEach-Object { if ($_.name) { $_.name } else { $_.ColumnName } })
    if (-not $cols.Count -or -not $cols[0]) { throw "Unexpected response shape from Log Analytics: $($r | ConvertTo-Json -Depth 4 -Compress)" }
    foreach ($row in $t.rows) {
        $o = [ordered]@{}
        for ($c = 0; $c -lt $cols.Count; $c++) { $o[$cols[$c]] = $row[$c] }
        [pscustomobject]$o
    }
}
# Both Key Vault log schemas, normalised. Column names are case-sensitive:
#   AzureDiagnostics: ResourceId, CallerIPAddress, identity_claim_oid_g (or the long objectidentifier claim), id_s
#   AZKVAuditLogs:    _ResourceId, CallerIpAddress, Identity.claim.oid (or the long objectidentifier claim), Id
function Build-Src($vaultIds) {
    $vl = ($vaultIds | ForEach-Object { "'" + $_.ToLower() + "'" }) -join ','
    @"
let vaultIds = dynamic([$vl]);
let src = union isfuzzy=true
  (AzureDiagnostics | where ResourceProvider == 'MICROSOFT.KEYVAULT' and Category == 'AuditEvent'
     | project TimeGenerated, Source = 'AzureDiagnostics', ResourceId = tolower(ResourceId), OperationName,
         CallerIP = tostring(column_ifexists('CallerIPAddress', '')),
         Oid = tolower(coalesce(tostring(column_ifexists('identity_claim_oid_g', '')), tostring(column_ifexists('identity_claim_http_schemas_microsoft_com_identity_claims_objectidentifier_g', '')))),
         ItemId = tostring(column_ifexists('id_s', ''))),
  (AZKVAuditLogs
     | extend Claim = parse_json(tostring(Identity)).claim
     | project TimeGenerated, Source = 'AZKVAuditLogs', ResourceId = tolower(_ResourceId), OperationName,
         CallerIP = tostring(CallerIpAddress),
         Oid = tolower(coalesce(tostring(Claim.oid), tostring(Claim['http://schemas.microsoft.com/identity/claims/objectidentifier']))),
         ItemId = tostring(Id))
  | where ResourceId in (vaultIds);

"@
}
$ws0 = $WindowStart.ToString('yyyy-MM-dd'); $we0 = $WindowEnd.ToString('yyyy-MM-dd')
$cov = @(); $pact = @(); $newc = @(); $qerr = @{}
$byWs = @($logging | Where-Object { $_.workspaceId } | Group-Object workspaceId)
$w = 0
foreach ($g in $byWs) {
    $w++; Write-Host "Querying workspace $w/$($byWs.Count): $($g.Name)"
    $src = Build-Src @($g.Group.vaultId)
    $q1 = $src + "src | summarize Events=count(), First=min(TimeGenerated), Last=max(TimeGenerated), Sources=strcat_array(make_set(Source), ','), MissingIp=countif(isempty(CallerIP)), MissingOid=countif(isempty(Oid)) by ResourceId"
    $q2 = $src + "src | where Oid in (dynamic([$plist])) | summarize Events=count(), First=min(TimeGenerated), Last=max(TimeGenerated) by ResourceId, Oid, CallerIP, OperationName"
    $q3 = $src + "let ops = dynamic(['SecretGet','SecretList','SecretBackup','SecretListVersions','KeyGet','KeyList','KeyBackup','CertificateGet','CertificateList','CertificateBackup']); let base = src | where TimeGenerated < datetime($ws0) | distinct ResourceId, Oid, CallerIP; src | where TimeGenerated >= datetime($ws0) and TimeGenerated < datetime($we0) and OperationName in (ops) | summarize Events=count(), DistinctItems=dcount(ItemId), First=min(TimeGenerated), Last=max(TimeGenerated), Ops=tostring(make_set(OperationName)) by ResourceId, Oid, CallerIP | join kind=leftanti base on ResourceId, Oid, CallerIP | order by Events desc"
    try {
        $cov += @(Invoke-La $g.Name $q1)
        $pact += @(Invoke-La $g.Name $q2)
        $newc += @(Invoke-La $g.Name $q3)
    } catch { $qerr[$g.Name] = "$($_.Exception.Message)"; Write-Warning "Query failed for $($g.Name): $($qerr[$g.Name])" }
}
foreach ($c in @($cov | Where-Object { [int]$_.MissingIp -gt 0 -or [int]$_.MissingOid -gt 0 })) {
    Write-Warning "$($c.ResourceId): $($c.MissingIp) of $($c.Events) log rows have no caller IP and $($c.MissingOid) have no object ID ($($c.Sources)). Check the column mapping in Build-Src for this workspace."
}

# Flag APIM-identity activity coming from an address that is not one of that instance's own IPs
foreach ($row in $pact) {
    $apis = @($principalMap[$row.Oid])
    $exp = @($apis | ForEach-Object { Get-Ips $_.publicIPs; Get-Ips $_.privateIPs })
    $flag = if (-not $row.CallerIP) { 'IP-MISSING (no caller IP in the log row)' }
            elseif (-not $exp.Count) { 'IP-UNVERIFIABLE (instance has no static IP, e.g. Consumption)' }
            elseif ($row.CallerIP -in $exp) { 'expected' } else { 'UNEXPECTED IP' }
    Add-Member -InputObject $row -NotePropertyName Flag -NotePropertyValue $flag -Force
    Add-Member -InputObject $row -NotePropertyName Apim -NotePropertyValue (($apis | ForEach-Object { $_.name }) -join ',') -Force
}
$cov | Export-Csv "$OutDir\log-coverage.csv"
$pact | Export-Csv "$OutDir\apim-identity-activity.csv"
$newc | Export-Csv "$OutDir\new-callers-in-window.csv"

# ---- 5. Verdict per vault -----------------------------------------------------------------------
$verdicts = foreach ($l in $logging) {
    $vid = $l.vaultId.ToLower()
    $c = $cov | Where-Object { $_.ResourceId -eq $vid } | Select-Object -First 1
    $pa = @($pact | Where-Object { $_.ResourceId -eq $vid })
    $nc = @($newc | Where-Object { $_.ResourceId -eq $vid })
    $unexp = @($pa | Where-Object { $_.Flag -eq 'UNEXPECTED IP' }).Count
    $unver = @($pa | Where-Object { $_.Flag -like 'IP-UNVERIFIABLE*' -or $_.Flag -like 'IP-MISSING*' }).Count
    $status = if (-not $l.workspaceId) { 'NO AUDIT LOGGING - cannot assess' }
              elseif ($qerr.ContainsKey($l.workspaceId)) { 'QUERY FAILED - cannot assess' }
              elseif (-not $c) { 'NO LOG DATA IN LOOKBACK - cannot assess' }
              elseif ($unexp -or $nc.Count) { 'SUSPICIOUS - review' }
              elseif ($unver) { 'REVIEW - APIM identity activity, source IPs unverifiable' }
              elseif (([datetimeoffset]$c.First).UtcDateTime -gt $WindowStart) { 'PARTIAL COVERAGE - logs start after window start' }
              else { 'no anomaly found in available logs' }
    [pscustomobject]@{
        status = $status; vault = $l.vault; subscriptionId = $l.subscriptionId
        logsFrom = if ($c) { $c.First } else { $null }; logEvents = if ($c) { $c.Events } else { 0 }
        logSources = if ($c) { $c.Sources } else { '' }
        apimIdentityEvents = ($pa | Measure-Object Events -Sum).Sum; unexpectedIpRows = $unexp
        newCallersInWindow = $nc.Count; note = $l.note
    }
}
$verdicts | Export-Csv "$OutDir\vault-verdicts.csv"

Write-Host "`n=== Per-vault verdicts (window $ws0 to $we0 UTC, lookback $LookbackDays days) ==="
foreach ($v in ($verdicts | Sort-Object status, vault)) {
    $color = switch -Wildcard ($v.status) { 'SUSPICIOUS*' { 'Red' } 'no anomaly*' { 'Green' } default { 'Yellow' } }
    Write-Host ("{0,-58} {1} [{2}] logs from {3:yyyy-MM-dd}, {4} events, APIM-identity events: {5}, new callers in window: {6}" -f `
        $v.status, $v.vault, $v.subscriptionId, $v.logsFrom, $v.logEvents, $v.apimIdentityEvents, $v.newCallersInWindow) -ForegroundColor $color
}
Write-Host @"

How to read this:
  SUSPICIOUS = APIM identity used from an IP that isn't one of its own, or a caller/IP pair never seen before the
               window read secrets/keys/certs inside it. New pairs can be benign (new admin IP, new service);
               look at new-callers-in-window.csv and apim-identity-activity.csv before concluding anything.
  REVIEW     = APIM identity activity whose source IP cannot be checked (no static IP, or no IP in the log row).
  'no anomaly found' only covers the period the logs cover (see logsFrom) and only data that was logged.
  Anything 'cannot assess' / PARTIAL means there is no evidence either way - treat as potentially accessed.
  Absence of events is not proof of safety: the described legacy API had no logging, but its use of a
  vault would still appear in Key Vault's own audit log if diagnostics were on.
  Role assignments that give no vault access (e.g. Reader, or Contributor on an RBAC vault) are listed in
  excluded-role-assignments.csv rather than counted as candidates.
Done. Output in $OutDir
"@
