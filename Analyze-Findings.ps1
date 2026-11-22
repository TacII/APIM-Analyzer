#Requires -Version 7
<#
Follow-up analysis of the output from Check-ApimExposure.ps1 and Check-KeyVaultAudit.ps1. Read-only.

What it does:
  1. Secrets held by APIM - classifies secret named values by type (function key, client secret, Logic App
     signature, subscription key, ...), flags environment mixing (production-looking keys on non-production
     instances and the reverse), the same secret name on production and non-production instances, all-access
     subscriptions, leftover logger credentials and backends with literal (not named-value) credentials.
  2. Flagged Key Vault callers - resolves every caller the audit script flagged in Entra ID, then drills into
     the Key Vault logs per caller: all IP addresses over the log period, client (user agent) before and in the
     window, volume against the caller's own baseline, failed requests, and whether the IP is an Azure address.
     Each caller gets a heuristic verdict (LIKELY BENIGN / LIKELY CI/CD / INVESTIGATE / SUSPICIOUS).
  3. Report - writes analysis-report.md plus CSVs, and a snapshot.json. With -CompareTo <previous output folder>
     the report also lists what changed since that run.

Needs: the output folders of the two scripts, Reader on the subscriptions, Log Analytics Reader on the
workspaces, and directory read access in Entra ID (to resolve object IDs). Run `az login` first.
Output goes to .\incident-analysis\ and contains tenant data - never commit it.

Author:  Mathias Haas, Fidelity Consulting AB
Contact: bWF0aGlhcy5oYWFzQGZpZGVsaXR5Y29uc3VsdGluZy5zZQ== (base64)
License: MIT (see LICENSE). Provided as is, without warranty.
#>
param(
    [string]$ExposureDir = (Join-Path $PWD 'apim-exposure'),
    [string]$AuditDir    = (Join-Path $PWD 'kv-audit'),
    [string]$OutDir      = (Join-Path $PWD 'incident-analysis'),
    [datetime]$WindowStart = '2026-11-16',   # UTC, inclusive - use the same values as Check-KeyVaultAudit.ps1
    [datetime]$WindowEnd   = '2026-11-21',   # UTC, exclusive
    [int]$LookbackDays = 90,
    [string]$CompareTo,                      # previous OutDir; its snapshot.json is compared with this run
    [switch]$SkipLive                        # only use the CSVs: no Entra, Log Analytics or ARM calls
)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force $OutDir | Out-Null
function Read-Csv([string]$Path) { if (Test-Path $Path) { @(Import-Csv $Path) } else { Write-Warning "Not found: $Path"; @() } }
function Test-True($v) { "$v" -eq 'True' }
# make_set values from Log Analytics come back as JSON text from this API version
function Expand-Ops($v) { if ($v -is [string]) { if (-not $v) { return @() }; try { @($v | ConvertFrom-Json) } catch { @($v) } } else { @($v) } }

# ---- ARM / Graph helpers (direct REST with a token from az; see DEVLOG for why not `az rest`) ----------------
$script:tokens = @{}
function Get-Token([string]$Resource) {
    $t = $script:tokens[$Resource]
    if (-not $t -or $t.expires -lt [DateTimeOffset]::UtcNow.AddMinutes(5)) {
        $azArgs = if ($Resource -eq 'graph') { @('--resource-type', 'ms-graph') } else { @('--resource', 'https://management.azure.com/') }
        $r = az account get-access-token @azArgs -o json | ConvertFrom-Json
        if ($LASTEXITCODE -ne 0 -or -not $r.accessToken) { throw "Could not get a $Resource token. Run az login." }
        $exp = if ($r.expires_on) { [DateTimeOffset]::FromUnixTimeSeconds([long]$r.expires_on) } else { [DateTimeOffset]::new([datetime]$r.expiresOn) }
        $t = @{ value = $r.accessToken; expires = $exp }; $script:tokens[$Resource] = $t
    }
    return $t.value
}
function Invoke-Api([string]$Method, [string]$Url, $Body, [string]$Resource = 'arm') {
    for ($try = 1; ; $try++) {
        $p = @{ Method = $Method; Uri = $Url; Headers = @{ Authorization = "Bearer $(Get-Token $Resource)" } }
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
function Get-AllPages([string]$Url) {
    while ($Url) { $r = Invoke-Api GET $Url; if (-not $r.ok) { return }; $r.data.value; $Url = $r.data.nextLink }
}

# ---- Heuristics ------------------------------------------------------------------------------------------
# Environment from a resource or secret name. Names without any marker are assumed to be production.
function Get-Env([string]$Name) {
    $n = "$Name".ToLower()
    if ($n -match '(^|[-_.])(prod|prd|production|live)([-_.]|$)') { return 'prod' }
    if ($n -match '(^|[-_.])(dev|utv|development|sandbox|sbx)([-_.]|$)' -or $n -match 'dev$') { return 'dev' }
    if ($n -match '(^|[-_.])(test|tst|qa|uat|stage|staging|stg|preprod|acc|at|ft|st|xt|it)([-_.]|$)' -or $n -match 'test$') { return 'test' }
    return 'none'
}
function Get-InstanceEnv([string]$Name) { $e = Get-Env $Name; if ($e -eq 'none') { 'prod (assumed)' } else { $e } }
function Test-Prod([string]$EnvValue) { $EnvValue -like 'prod*' }
# Secret type from a named value's display name. First match wins.
$categories = @(
    @{ name = 'Logic App trigger signature';      pattern = 'manual-invoke|_invoke_|logic.?app.*sig' },
    @{ name = 'Client secret (OAuth/app)';        pattern = 'client.?secret|app.?secret' },
    @{ name = 'Config value flagged as secret';   pattern = 'client.?id$|clientid|authorization.?server|issuer|tenant.?id|(^|[-_])url$|resource$' },
    @{ name = 'Subscription key (other APIM / partner)'; pattern = 'subscription.?key|apim.?key|ocp.?apim' },
    @{ name = 'Function key';                     pattern = 'func' },
    @{ name = 'Connection string / SAS';          pattern = 'conn(ection)?.?str|(^|[-_])sas([-_]|$)|account.?key|service.?bus|event.?hub' },
    @{ name = 'Password';                         pattern = 'password|passwd|pwd' },
    @{ name = 'Certificate / private key';        pattern = 'cert|pfx|private.?key' },
    @{ name = 'API key / token (other)';          pattern = 'key|token|secret' }
)
function Get-SecretCategory([string]$Name) {
    foreach ($c in $categories) { if ($Name -match $c.pattern) { return $c.name } }
    return 'Other'
}
# Clients that indicate automation / CI-CD
$ciPattern = 'terraform|go-autorest|kermit|azure-pipelines|azuredevops|vsts|github|pulumi|bicep|arm-deploy'
# Failed operations that are routine noise for common tools (Terraform reads certificate contacts it may not have)
$noiseFailOps = @('CertificateContactsGet')

# =====================================================================================================
# 1. Secrets held by APIM
# =====================================================================================================
$instances = Read-Csv (Join-Path $ExposureDir 'apim-instances.csv')
$summary   = Read-Csv (Join-Path $ExposureDir 'summary.csv')
$nv        = Read-Csv (Join-Path $ExposureDir 'named-values.csv')
$subsCsv   = Read-Csv (Join-Path $ExposureDir 'apim-subscriptions.csv')
$scopeCsv  = Read-Csv (Join-Path $ExposureDir 'scope.csv')
# In-scope instances as decided by Check-ApimExposure.ps1 (Microsoft's list or the tier rule); older output
# without scope.csv falls back to Classic dedicated tiers.
$classic = if ($scopeCsv.Count) {
    $ids = @($scopeCsv | Where-Object { $_.inScope -eq 'True' } | ForEach-Object { $_.id })
    @($instances | Where-Object { $_.id -in $ids })
} else { @($instances | Where-Object { $_.sku -notmatch 'V2$' -and $_.sku -ne 'Consumption' }) }
$envOf = @{}; foreach ($i in $classic) { $envOf[$i.name] = Get-InstanceEnv $i.name }
Write-Host "Instances in scope: $($classic.Count) ($(@($classic | Where-Object { Test-Prod $envOf[$_.name] }).Count) production by name)"
$scopeNames = @($classic.name)
$nv = @($nv | Where-Object { $_.apim -in $scopeNames })
$subsCsv = @($subsCsv | Where-Object { $_.apim -in $scopeNames })

$nvRows = foreach ($v in $nv) {
    $dn = if ($v.displayName) { $v.displayName } else { $v.namedValue }
    $logger = (Test-True $v.loggerCredential) -or $dn -like 'Logger-Credentials*'
    [pscustomobject]@{
        apim = $v.apim; instanceEnv = $envOf[$v.apim]; displayName = $dn
        secret = (Test-True $v.secret); inKeyVault = (Test-True $v.inKeyVault); loggerCredential = $logger
        nameEnv = (Get-Env $dn)
        category = if ($logger) { 'Logger credential' } elseif (Test-True $v.inKeyVault) { 'Key Vault reference' } elseif (Test-True $v.secret) { Get-SecretCategory $dn } else { 'Plain value' }
    }
}
$heldSecrets = @($nvRows | Where-Object { $_.secret -and -not $_.inKeyVault -and -not $_.loggerCredential })
$nvRows | Export-Csv (Join-Path $OutDir 'named-value-categories.csv')

# Environment mixing and reuse
$flags = [System.Collections.Generic.List[object]]::new()
function Add-Flag($Kind, $Apim, $Item, $Detail) { $flags.Add([pscustomobject]@{ kind = $Kind; apim = $Apim; item = $Item; detail = $Detail }) }
$byName = $heldSecrets | Group-Object displayName
foreach ($g in $byName) {
    $prodInst = @($g.Group | Where-Object { Test-Prod $_.instanceEnv })
    $nonProd = @($g.Group | Where-Object { -not (Test-Prod $_.instanceEnv) })
    if ($prodInst.Count -and $nonProd.Count) {
        Add-Flag 'Same secret name in production and non-production' (($g.Group.apim | Sort-Object -Unique) -join ', ') $g.Name 'The same value may be shared across environments. Compare the values (or their hashes) without exposing them.'
        foreach ($r in $nonProd | Where-Object { $_.nameEnv -eq 'none' }) {
            Add-Flag 'Possible production key on non-production instance' $r.apim $r.displayName "Name has no environment marker and also exists on production ($(($prodInst.apim | Sort-Object -Unique) -join ', '))."
        }
    }
}
foreach ($r in $heldSecrets | Where-Object { (Test-Prod $_.instanceEnv) -and $_.nameEnv -in 'test', 'dev' }) {
    Add-Flag 'Production instance holds a non-production-named key' $r.apim $r.displayName 'Production may depend on a test or development key.'
}
foreach ($r in $nvRows | Where-Object { -not $_.secret -and $_.displayName -match 'secret|password|pwd|token|key$|connection' }) {
    Add-Flag 'Plain (non-secret) value with a secret-like name' $r.apim $r.displayName 'Stored in clear text. Check that it holds nothing sensitive.'
}

# Subscriptions: built-in all-access (scope "/") and "all APIs" subscriptions
$subRows = foreach ($s in $subsCsv | Where-Object { $_.state -eq 'active' }) {
    $rel = $s.scope -replace '^.*/service/[^/]+', ''
    $kind = if ($rel -in '', '/') { 'All-access (built-in)' } elseif ($rel -match '^/apis/?$') { 'All APIs' } elseif ($rel -match '/products/') { 'Product' } elseif ($rel -match '/apis/') { 'Single API' } else { "Other ($rel)" }
    [pscustomobject]@{ apim = $s.apim; instanceEnv = $envOf[$s.apim]; subscription = $s.apimSubscription; displayName = $s.displayName; scopeKind = $kind }
}
$subRows | Export-Csv (Join-Path $OutDir 'subscription-scopes.csv')
foreach ($r in $subRows | Where-Object { $_.scopeKind -eq 'All APIs' }) {
    Add-Flag 'Subscription with access to all APIs' $r.apim "$($r.subscription) ($($r.displayName))" 'Regenerate early. Check who uses it, especially personal or tool subscriptions.'
}

# Live: backends (credential structure only, never values) and loggers (which logger credentials are referenced)
$backendRows = @(); $loggerRows = @()
if (-not $SkipLive) {
    foreach ($i in $classic) {
        Write-Host "Backends and loggers: $($i.name)"
        foreach ($b in Get-AllPages "https://management.azure.com$($i.id)/backends?api-version=2024-05-01") {
            $c = $b.properties.credentials; $vals = @(); $kinds = @()
            if ($c.header) { $kinds += 'header'; $vals += @($c.header.PSObject.Properties.Value | ForEach-Object { $_ }) }
            if ($c.query) { $kinds += 'query'; $vals += @($c.query.PSObject.Properties.Value | ForEach-Object { $_ }) }
            if ($c.authorization) { $kinds += "authorization($($c.authorization.scheme))"; $vals += $c.authorization.parameter }
            if ($c.certificate -or $c.certificateIds) { $kinds += 'clientCertificate' }
            if ($b.properties.proxy.password) { $kinds += 'proxyPassword'; $vals += $b.properties.proxy.password }
            $literal = @($vals | Where-Object { $_ -and "$_" -notmatch '^\{\{.+\}\}$' }).Count
            $backendRows += [pscustomobject]@{ apim = $i.name; backend = $b.name; credentialKinds = ($kinds -join ','); values = $vals.Count; literalValues = $literal }
            if ($literal) { Add-Flag 'Backend with literal credential' $i.name $b.name "$literal credential value(s) typed in directly instead of a named value. Rotate and move to a named value or Key Vault." }
        }
        $refs = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase); $loggerCount = 0; $credsVisible = $false
        foreach ($l in Get-AllPages "https://management.azure.com$($i.id)/loggers?api-version=2024-05-01") {
            $loggerCount++
            $cred = $l.properties.credentials
            if ($cred) { $credsVisible = $true; foreach ($m in [regex]::Matches(($cred | ConvertTo-Json -Compress), '\{\{([^}]+)\}\}')) { [void]$refs.Add($m.Groups[1].Value) } }
        }
        $creds = @($nvRows | Where-Object { $_.apim -eq $i.name -and $_.loggerCredential })
        $orphans = if ($credsVisible) { @($creds | Where-Object { -not $refs.Contains($_.displayName) }).Count } else { [Math]::Max(0, $creds.Count - $loggerCount) }
        $loggerRows += [pscustomobject]@{ apim = $i.name; loggers = $loggerCount; loggerCredentials = $creds.Count; leftover = $orphans
                                          method = if ($credsVisible) { 'unreferenced by any logger' } else { 'credentials minus loggers (estimate)' } }
        if ($orphans -ge 5) { Add-Flag 'Leftover logger credentials' $i.name "$orphans of $($creds.Count)" 'Application Insights logger credentials that no logger uses. Low impact; clean up.' }
    }
    $backendRows | Export-Csv (Join-Path $OutDir 'backend-credentials.csv')
    $loggerRows | Export-Csv (Join-Path $OutDir 'logger-credentials.csv')
}
$flags | Export-Csv (Join-Path $OutDir 'flags.csv')
Write-Host "Secrets held by APIM: $($heldSecrets.Count); flags raised: $($flags.Count)"

# =====================================================================================================
# 2. Flagged Key Vault callers
# =====================================================================================================
$newCallers = Read-Csv (Join-Path $AuditDir 'new-callers-in-window.csv')
$apimAct    = Read-Csv (Join-Path $AuditDir 'apim-identity-activity.csv')
$logging    = Read-Csv (Join-Path $AuditDir 'vault-logging.csv')
$verdictsIn = Read-Csv (Join-Path $AuditDir 'vault-verdicts.csv')
$flagged = @(
    $newCallers | Where-Object { $_.Oid } | ForEach-Object { [pscustomobject]@{ oid = $_.Oid.ToLower(); vaultId = $_.ResourceId.ToLower(); ip = $_.CallerIP; source = 'new caller in window' } }
    $apimAct | Where-Object { $_.Flag -eq 'UNEXPECTED IP' } | ForEach-Object { [pscustomobject]@{ oid = $_.Oid.ToLower(); vaultId = $_.ResourceId.ToLower(); ip = $_.CallerIP; source = 'APIM identity from unexpected IP' } }
)
$oids = @($flagged.oid | Sort-Object -Unique)
Write-Host "Flagged callers: $($oids.Count) identities, $($flagged.Count) caller/vault/IP combinations"

$identity = @{}; $drill = @(); $ipHistory = @(); $clientHistory = @()
if ($oids.Count -and -not $SkipLive) {
    # Resolve identities in Entra ID
    for ($k = 0; $k -lt $oids.Count; $k += 1000) {
        $chunk = @($oids[$k..([Math]::Min($k + 999, $oids.Count - 1))])
        $r = Invoke-Api POST 'https://graph.microsoft.com/v1.0/directoryObjects/getByIds' @{ ids = $chunk } 'graph'
        if ($r.ok) {
            foreach ($o in $r.data.value) {
                $type = switch ($o.'@odata.type') { '#microsoft.graph.user' { 'user' } '#microsoft.graph.servicePrincipal' { if ($o.servicePrincipalType -eq 'ManagedIdentity') { 'managedIdentity' } else { 'servicePrincipal' } } default { $o.'@odata.type' } }
                $identity[$o.id.ToLower()] = [pscustomobject]@{ type = $type; name = $o.displayName; upn = $o.userPrincipalName; appId = $o.appId
                    resource = (@($o.alternativeNames) | Where-Object { $_ -like '/subscriptions/*' }) -join ' ' }
            }
        } else { Write-Warning "Entra ID lookup failed (needs directory read access): $($r.error)" }
    }
    foreach ($o in $oids) { if (-not $identity.ContainsKey($o)) { $identity[$o] = [pscustomobject]@{ type = 'NOT FOUND'; name = '(not in directory: deleted, other tenant, or no read access)'; upn = ''; appId = ''; resource = '' } } }

    # Azure public IP ranges (service tag AzureCloud), to tell cloud-hosted callers from others
    $azureNets = @()
    $sub = az account show --query id -o tsv 2>$null
    $st = Invoke-Api GET "https://management.azure.com/subscriptions/$sub/providers/Microsoft.Network/locations/westeurope/serviceTags?api-version=2023-09-01"
    if ($st.ok) {
        $prefixes = @(($st.data.values | Where-Object { $_.name -eq 'AzureCloud' }).properties.addressPrefixes) | Where-Object { $_ -notmatch ':' }
        $azureNets = foreach ($p in $prefixes) {
            $parts = $p.Split('/'); $bits = [int]$parts[1]
            $b = [Net.IPAddress]::Parse($parts[0]).GetAddressBytes(); [Array]::Reverse($b)
            # 4294967295 = 2^32-1 (a 0xFFFFFFFF literal is int32 -1 in PowerShell)
            $mask = if ($bits -eq 0) { [uint64]0 } else { ([uint64]4294967295 -shl (32 - $bits)) -band [uint64]4294967295 }
            [pscustomobject]@{ net = ([uint64][BitConverter]::ToUInt32($b, 0)) -band $mask; mask = $mask }
        }
    } else { Write-Warning "Could not load Azure service tags; Azure-IP check skipped. $($st.error)" }
    function Test-AzureIp([string]$Ip) {
        if (-not $azureNets -or -not $Ip -or $Ip -match ':') { return $null }
        try { $b = [Net.IPAddress]::Parse($Ip).GetAddressBytes() } catch { return $null }
        [Array]::Reverse($b); $v = [uint64][BitConverter]::ToUInt32($b, 0)
        foreach ($n in $azureNets) { if (($v -band $n.mask) -eq $n.net) { return $true } }
        return $false
    }

    # Log Analytics drill-down, per workspace that holds a flagged vault
    $wsOf = @{}; foreach ($l in $logging | Where-Object workspaceId) { $wsOf[$l.vaultId.ToLower()] = $l.workspaceId }
    $ws0 = $WindowStart.ToString('yyyy-MM-dd'); $we0 = $WindowEnd.ToString('yyyy-MM-dd')
    function Invoke-La([string]$Ws, [string]$Kql) {
        $r = Invoke-Api POST "https://management.azure.com$Ws/api/query?api-version=2017-01-01-preview" @{ query = $Kql; timespan = "P$($LookbackDays)D" }
        if (-not $r.ok) { throw $r.error }
        $t = $r.data.tables[0]; $cols = @($t.columns | ForEach-Object { if ($_.name) { $_.name } else { $_.ColumnName } })
        foreach ($row in $t.rows) { $o = [ordered]@{}; for ($c = 0; $c -lt $cols.Count; $c++) { $o[$cols[$c]] = $row[$c] }; [pscustomobject]$o }
    }
    $vol = @(); $shared = @()
    foreach ($g in ($flagged | Where-Object { $wsOf.ContainsKey($_.vaultId) } | Group-Object { $wsOf[$_.vaultId] })) {
        Write-Host "Drilling into workspace $(($g.Name -split '/')[-1])"
        $vl = (@($g.Group.vaultId | Sort-Object -Unique) | ForEach-Object { "'$_'" }) -join ','
        $ol = (@($g.Group.oid | Sort-Object -Unique) | ForEach-Object { "'$_'" }) -join ','
        $il = (@($g.Group.ip | Where-Object { $_ } | Sort-Object -Unique) | ForEach-Object { "'$_'" }) -join ','
        $src = @"
let vaultIds = dynamic([$vl]); let oids = dynamic([$ol]); let ws = datetime($ws0); let we = datetime($we0);
let src = union isfuzzy=true
  (AzureDiagnostics | where ResourceProvider == 'MICROSOFT.KEYVAULT' and Category == 'AuditEvent'
     | project TimeGenerated, ResourceId = tolower(ResourceId), OperationName, CallerIP = tostring(column_ifexists('CallerIPAddress', '')),
         Oid = tolower(coalesce(tostring(column_ifexists('identity_claim_oid_g', '')), tostring(column_ifexists('identity_claim_http_schemas_microsoft_com_identity_claims_objectidentifier_g', '')))),
         ItemId = tostring(column_ifexists('id_s', '')), Http = toint(column_ifexists('httpStatusCode_d', real(null))), Client = tostring(column_ifexists('clientInfo_s', ''))),
  (AZKVAuditLogs | extend Claim = parse_json(tostring(Identity)).claim
     | project TimeGenerated, ResourceId = tolower(_ResourceId), OperationName, CallerIP = tostring(CallerIpAddress),
         Oid = tolower(coalesce(tostring(Claim.oid), tostring(Claim['http://schemas.microsoft.com/identity/claims/objectidentifier']))),
         ItemId = tostring(Id), Http = toint(HttpStatusCode), Client = tostring(ClientInfo))
  | where ResourceId in (vaultIds)
  | extend Item = extract(@'/(secrets|keys|certificates)/([^/]+)', 2, ItemId), InWindow = TimeGenerated >= ws and TimeGenerated < we, Before = TimeGenerated < ws;

"@
        try {
            $ipHistory += @(Invoke-La $g.Name ($src + "src | where Oid in (oids) | summarize Events=count(), First=min(TimeGenerated), Last=max(TimeGenerated), Failed=countif(Http in (401,403)) by Oid, ResourceId, CallerIP"))
            $clientHistory += @(Invoke-La $g.Name ($src + "src | where Oid in (oids) | summarize Events=count(), BeforeWindow=countif(Before), InWindow=countif(InWindow), First=min(TimeGenerated), Last=max(TimeGenerated) by Oid, ResourceId, Client"))
            $vol += @(Invoke-La $g.Name ($src + "src | where Oid in (oids) | summarize BaselineEvents=countif(Before), BaselineDays=dcountif(bin(TimeGenerated, 1d), Before), WindowEvents=countif(InWindow), WindowDays=dcountif(bin(TimeGenerated, 1d), InWindow), BaselineItems=dcountif(Item, Before and isnotempty(Item)), WindowItems=dcountif(Item, InWindow and isnotempty(Item)), WindowFailedOps=make_set_if(OperationName, InWindow and Http in (401,403)), WindowFailed=countif(InWindow and Http in (401,403)), WindowItemSample=make_set_if(Item, InWindow and isnotempty(Item), 15), FirstSeen=min(TimeGenerated) by Oid, ResourceId"))
            if ($il) { $shared += @(Invoke-La $g.Name ($src + "src | where CallerIP in (dynamic([$il])) and isnotempty(Oid) | summarize Events=count(), First=min(TimeGenerated), Last=max(TimeGenerated) by CallerIP, Oid")) }
        } catch { Write-Warning "Log query failed for $($g.Name): $($_.Exception.Message)" }
    }
    $ipHistory | Export-Csv (Join-Path $OutDir 'caller-ip-history.csv')
    $clientHistory | Export-Csv (Join-Path $OutDir 'caller-clients.csv')
    $shared | Export-Csv (Join-Path $OutDir 'flagged-ip-other-callers.csv')

    # Verdict per flagged identity and vault
    $drill = foreach ($f in ($flagged | Group-Object oid, vaultId)) {
        $oid = $f.Group[0].oid; $vid = $f.Group[0].vaultId
        $id = $identity[$oid]
        $v = $vol | Where-Object { $_.Oid -eq $oid -and $_.ResourceId -eq $vid } | Select-Object -First 1
        $ips = @($ipHistory | Where-Object { $_.Oid -eq $oid -and $_.ResourceId -eq $vid })
        $cl = @($clientHistory | Where-Object { $_.Oid -eq $oid -and $_.ResourceId -eq $vid })
        $newClients = @($cl | Where-Object { [int]$_.InWindow -gt 0 -and [int]$_.BeforeWindow -eq 0 })
        $windowClients = @($cl | Where-Object { [int]$_.InWindow -gt 0 } | ForEach-Object { $_.Client })
        $flaggedIps = @($f.Group.ip | Where-Object { $_ } | Sort-Object -Unique)
        $azure = @($flaggedIps | ForEach-Object { Test-AzureIp $_ })
        $isAzureIp = if ($azure -contains $true) { $true } elseif ($azure -contains $false) { $false } else { $null }
        $failOps = @(if ($v) { Expand-Ops $v.WindowFailedOps })
        $realFails = @($failOps | Where-Object { $_ -notin $noiseFailOps })
        $ratio = $null
        if ($v -and [int]$v.BaselineDays -gt 0 -and [int]$v.WindowDays -gt 0 -and [int]$v.BaselineEvents -gt 0) {
            $ratio = [Math]::Round(([double]$v.WindowEvents / [int]$v.WindowDays) / ([double]$v.BaselineEvents / [int]$v.BaselineDays), 1)
        }
        $known = $v -and [int]$v.BaselineEvents -gt 0
        $ci = @($windowClients | Where-Object { $_ -match $ciPattern }).Count -gt 0
        $apimForeign = 'APIM identity from unexpected IP' -in $f.Group.source
        $verdict = if (-not $v) { 'NOT ANALYSED - no log data found for this caller' }
                   elseif ($apimForeign) { 'SUSPICIOUS - APIM managed identity used from an unexpected IP' }
                   elseif ($id.type -eq 'NOT FOUND') { 'SUSPICIOUS - identity not found in the directory' }
                   elseif (-not $known) { 'INVESTIGATE - identity never seen before the window' }
                   elseif ($realFails.Count) { "INVESTIGATE - failed requests in window ($($realFails -join ', '))" }
                   elseif ($newClients.Count) { 'INVESTIGATE - client (user agent) not seen before the window' }
                   elseif ($ratio -and $ratio -gt 3) { "INVESTIGATE - volume $($ratio)x the caller's own baseline" }
                   elseif ($id.type -in 'servicePrincipal', 'managedIdentity' -and ($ci -or $isAzureIp)) { 'LIKELY CI/CD - known identity and client, cloud-hosted; confirm with pipeline runs' }
                   else { 'LIKELY BENIGN - known identity and client from a new IP; confirm with the owner' }
        [pscustomobject]@{
            verdict = $verdict; oid = $oid; identityType = $id.type; identity = $id.name; upn = $id.upn; appId = $id.appId
            vault = ($vid -split '/')[-1]; flaggedIp = ($flaggedIps -join ', '); flaggedIpIsAzure = $isAzureIp
            ipsOverPeriod = $ips.Count; firstSeen = if ($v) { $v.FirstSeen } else { $null }
            baselineEventsPerDay = if ($v -and [int]$v.BaselineDays) { [Math]::Round([double]$v.BaselineEvents / [int]$v.BaselineDays) } else { 0 }
            windowEventsPerDay = if ($v -and [int]$v.WindowDays) { [Math]::Round([double]$v.WindowEvents / [int]$v.WindowDays) } else { 0 }
            volumeRatio = $ratio; baselineItems = if ($v) { $v.BaselineItems } else { 0 }; windowItems = if ($v) { $v.WindowItems } else { 0 }
            windowFailedOps = ($failOps -join ', '); newClientInWindow = ($newClients.Count -gt 0); ciClient = $ci
            windowClients = (($windowClients | Sort-Object -Unique) -join ' | ')
            windowItemSample = if ($v) { (@(Expand-Ops $v.WindowItemSample) -join ', ') } else { '' }
        }
    }
    $drill | Export-Csv (Join-Path $OutDir 'caller-drilldown.csv')
} elseif ($oids.Count) {
    # Offline: list the flagged callers so they still appear in the report and comparisons
    $drill = foreach ($f in ($flagged | Group-Object oid, vaultId)) {
        [pscustomobject]@{ verdict = 'NOT ANALYSED (-SkipLive)'; oid = $f.Group[0].oid; identityType = ''; identity = $f.Group[0].oid
                           vault = ($f.Group[0].vaultId -split '/')[-1]; flaggedIp = (@($f.Group.ip | Sort-Object -Unique) -join ', ') }
    }
}

# =====================================================================================================
# 3. Snapshot, comparison and report
# =====================================================================================================
$snapshot = [ordered]@{
    generated = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); window = "$($WindowStart.ToString('yyyy-MM-dd'))/$($WindowEnd.ToString('yyyy-MM-dd'))"
    instances = @($summary | ForEach-Object { [ordered]@{ apim = $_.apim; status = $_.status; secretsInApim = $_.secretsInApim; activeSubscriptions = $_.activeSubscriptions } })
    heldSecrets = $heldSecrets.Count; activeSubscriptions = @($subRows).Count
    allAccess = @($subRows | Where-Object { $_.scopeKind -like 'All*' }).Count
    vaults = @($verdictsIn | ForEach-Object { [ordered]@{ vault = $_.vault; status = $_.status } })
    callers = @($drill | ForEach-Object { [ordered]@{ key = "$($_.oid)|$($_.vault)"; identity = $_.identity; verdict = $_.verdict } })
    flags = @($flags | ForEach-Object { "$($_.kind)|$($_.apim)|$($_.item)" })
}
$snapshot | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $OutDir 'snapshot.json') -Encoding utf8

$changes = @()
if ($CompareTo) {
    $prevFile = Join-Path $CompareTo 'snapshot.json'
    if (Test-Path $prevFile) {
        $prev = Get-Content $prevFile -Raw | ConvertFrom-Json
        function Compare-Set($Label, $Old, $New, $KeyProp, $ValProp) {
            $o = @{}; foreach ($x in @($Old)) { $o[$x.$KeyProp] = $x.$ValProp }
            $n = @{}; foreach ($x in @($New)) { $n[$x.$KeyProp] = $x.$ValProp }
            foreach ($k in $n.Keys) { if (-not $o.ContainsKey($k)) { "$($Label): new - $k ($($n[$k]))" } elseif ("$($o[$k])" -ne "$($n[$k])") { "$($Label): $k changed from '$($o[$k])' to '$($n[$k])'" } }
            foreach ($k in $o.Keys) { if (-not $n.ContainsKey($k)) { "$($Label): no longer present - $k (was $($o[$k]))" } }
        }
        $changes += Compare-Set 'Instance' $prev.instances $snapshot.instances 'apim' 'status'
        $changes += Compare-Set 'Secrets in APIM' $prev.instances $snapshot.instances 'apim' 'secretsInApim'
        $changes += Compare-Set 'Vault' $prev.vaults $snapshot.vaults 'vault' 'status'
        $changes += Compare-Set 'Caller' $prev.callers $snapshot.callers 'key' 'verdict'
        foreach ($fl in @($snapshot.flags) | Where-Object { $_ -notin @($prev.flags) }) { $changes += "Flag: new - $fl" }
        foreach ($fl in @($prev.flags) | Where-Object { $_ -notin @($snapshot.flags) }) { $changes += "Flag: resolved - $fl" }
        foreach ($m in 'heldSecrets', 'activeSubscriptions', 'allAccess') { if ("$($prev.$m)" -ne "$($snapshot.$m)") { $changes += "Total $($m): $($prev.$m) -> $($snapshot.$m)" } }
        if (-not $changes) { $changes = @('No differences.') }
    } else { Write-Warning "No snapshot.json in $CompareTo; comparison skipped." }
}

function ConvertTo-MdTable($Rows, [string[]]$Cols) {
    if (-not @($Rows).Count) { return '_None._' }
    # Parentheses matter: ',' binds tighter than '+' in PowerShell
    $out = @(('| ' + ($Cols -join ' | ') + ' |'), ('|' + (($Cols | ForEach-Object { '---' }) -join '|') + '|'))
    foreach ($r in $Rows) { $out += '| ' + (($Cols | ForEach-Object { "$($r.$_)" -replace '\|', '/' -replace "`r?`n", ' ' }) -join ' | ') + ' |' }
    $out -join "`n"
}
$catTable = $heldSecrets | Group-Object category | Sort-Object Count -Descending | ForEach-Object {
    [pscustomobject]@{ Category = $_.Name; Total = $_.Count; Production = @($_.Group | Where-Object { Test-Prod $_.instanceEnv }).Count; Instances = (($_.Group.apim | Sort-Object -Unique) -join ', ') }
}
$subTable = $subRows | Group-Object scopeKind | Sort-Object Count -Descending | ForEach-Object {
    [pscustomobject]@{ Scope = $_.Name; Active = $_.Count; Production = @($_.Group | Where-Object { Test-Prod $_.instanceEnv }).Count }
}
$flagTable = $flags | Group-Object kind | ForEach-Object { [pscustomobject]@{ Flag = $_.Name; Count = $_.Count; Examples = ((@($_.Group | Select-Object -First 4) | ForEach-Object { "$($_.apim): $($_.item)" }) -join '; ') } }
$report = @"
# APIM incident follow-up analysis

Generated $($snapshot.generated) by Analyze-Findings.ps1 (read-only). Window $($snapshot.window) UTC.
**Contains tenant data. Do not commit or share outside the incident team.**

## Key numbers

| Item | Value |
|---|---|
| Instances in scope | $($classic.Count) ($(@($classic | Where-Object { Test-Prod $envOf[$_.name] }).Count) production by name)$(if ($scopeCsv.Count) { "; scope source: $(@($scopeCsv.scopeSource | Sort-Object -Unique) -join ', ')" }) |
| Instances out of scope | $(@($scopeCsv | Where-Object { $_.inScope -ne 'True' }).Count) |
| Instances rated LIKELY EXPOSED | $(@($summary | Where-Object status -eq 'LIKELY EXPOSED').Count) |
| Secrets held by APIM (excluding logger credentials) | $($heldSecrets.Count) |
| Active subscriptions | $(@($subRows).Count) (all-access or all-API: $($snapshot.allAccess)) |
| Flags raised | $($flags.Count) |
| Flagged Key Vault callers analysed | $(@($drill).Count) |

## Secrets held by APIM, by type

Types are inferred from display names; review the list in named-value-categories.csv.

$(ConvertTo-MdTable $catTable @('Category','Total','Production','Instances'))

## Subscriptions by scope

$(ConvertTo-MdTable $subTable @('Scope','Active','Production'))

## Flags

Details in flags.csv. Environment is inferred from names; names without a marker are assumed to be production.

$(ConvertTo-MdTable $flagTable @('Flag','Count','Examples'))

## Flagged Key Vault callers

Heuristic verdicts. A known identity and client from a new IP is usually benign, but a stolen credential of the
same identity would look similar - always confirm with the owner, sign-in logs or pipeline history.

$(ConvertTo-MdTable $drill @('verdict','identityType','identity','vault','flaggedIp','flaggedIpIsAzure','ipsOverPeriod','baselineEventsPerDay','windowEventsPerDay','windowItems','windowFailedOps'))

$(if ($CompareTo) { "## Changes since previous run`n`nCompared with $CompareTo.`n`n" + ((@($changes) | ForEach-Object { "- $_" }) -join "`n") })

## Limits

- Exposure follows Microsoft's published criteria; nothing here proves access did or did not happen.
- Only vaults with audit logging can be drilled into, and only for the retention period of their workspace.
- User agents can be spoofed; volume and IP heuristics are indicators, not evidence.
- Environment and secret types are inferred from names.
"@
$report | Set-Content (Join-Path $OutDir 'analysis-report.md') -Encoding utf8

Write-Host "`n=== Flagged callers ==="
foreach ($d in $drill) {
    $color = switch -Wildcard ($d.verdict) { 'SUSPICIOUS*' { 'Red' } 'INVESTIGATE*' { 'Yellow' } default { 'Green' } }
    Write-Host ("{0} | {1} ({2}) | {3} | IP {4}" -f $d.verdict, $d.identity, $d.identityType, $d.vault, $d.flaggedIp) -ForegroundColor $color
}
if ($changes) { Write-Host "`n=== Changes since previous run ==="; $changes | ForEach-Object { Write-Host "- $_" } }
Write-Host "`nDone. Report: $(Join-Path $OutDir 'analysis-report.md')"
