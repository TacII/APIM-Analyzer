#Requires -Version 7
<#
Maps every internet ingress pathway to the in-scope Azure API Management (APIM) Classic instances and rates how
permissive each one is: open or broad NSG rules on the APIM subnet, Application Gateway and Front Door WAF policies
(disabled, detection-only, permissive custom rules, bypassable), Traffic Manager and Azure Firewall DNAT paths,
and the instance's own network mode (none / external / internal VNet, private endpoints, public network access).
Read-only. Needs Reader on the subscriptions and Apim-Helpers.ps1 alongside this script. Run `az login` first (az CLI).
Output goes to .\ingress-exposure\ .

Why: Microsoft's November 2026 notice says a Classic instance may have been accessed if it lacked the network
integration from the "Network security" section of the recommended secret management practices. The service
configuration (management) endpoint on port 3443 and the public gateway/portal/Git endpoints on 443 are the
pathways that matter. This script shows, per instance, who on the internet could reach them and through what.

Scope: apim-exposure/scope.csv from Check-ApimExposure.ps1 when present (Microsoft's impacted-resources list or
the tier rule), validated as in the audit and analysis scripts; otherwise the shared tier rule, which retains an
unrecognized SKU for review. -AllInstances analyses every instance you can see.

Current state vs. the exposure window: everything above is today's configuration. The Activity Log is read for
changes since -ChangesSince (default 1 Nov 2026) to the instance, its subnets and NSGs, and the front ends and WAF
policies that reach it, so an instance that was locked down after the incident is flagged rather than looking safe.

Author:  Tim Kidd (ingress analysis), building on the APIM incident tools by Mathias Haas, Fidelity Consulting AB
License: MIT (see LICENSE). Provided as is, without warranty.
#>
param(
    [string]$OutDir = (Join-Path $PWD 'ingress-exposure'),
    [string]$ExposureDir = (Join-Path $PWD 'apim-exposure'),   # scope.csv and summary.csv from Check-ApimExposure.ps1
    [int]$TightPrefixLength = 24,      # IPv4: a source range whose prefix length is at least this counts as tight ("small CIDR"); wider is BROAD
    [int]$TightPrefixLengthV6 = 48,    # IPv6: same idea
    [switch]$IncludeConsumption,       # without a scope file: treat Consumption instances as in scope too
    [switch]$AllInstances,             # analyse every APIM instance, in scope or not
    [switch]$SkipPolicy,               # do not read APIM global policies (ip-filter / X-Azure-FDID checks)
    [switch]$CheckGatewayPatch,        # also ask each gateway's status endpoint (every region) for its runtime build and compare with NSM's patched thresholds
    [datetime]$ChangesSince = '2026-11-01',   # UTC; Activity Log changes to ingress-relevant resources since then are flagged (max 90 days back)
    [switch]$SkipChangeHistory,        # do not read the Activity Log
    [string]$TenantId                 # Entra tenant to read; default: the tenant of the current az account (subscriptions in other tenants are skipped)
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Apim-Helpers.ps1')
New-Item -ItemType Directory -Force $OutDir | Out-Null

# ---- ARM / Resource Graph helpers (direct REST with a token from az; see docs/DEVLOG.md for why not `az rest`) ----
$script:armToken = $null
function Get-ArmToken {
    if (-not $script:armToken -or $script:armToken.expires -lt [DateTimeOffset]::UtcNow.AddMinutes(5)) {
        $azArgs = @('account', 'get-access-token', '--resource', 'https://management.azure.com/')
        if ($script:tenantId) { $azArgs += @('--tenant', $script:tenantId) }
        $t = Invoke-AzJson $azArgs
        if (-not $t.accessToken) { throw 'Could not get an Azure Resource Manager token. Run az login.' }
        $exp = if ($t.expires_on) { [DateTimeOffset]::FromUnixTimeSeconds([long]$t.expires_on) } else { [DateTimeOffset]::new([datetime]$t.expiresOn) }
        $script:armToken = @{ value = $t.accessToken; expires = $exp }
    }
    return $script:armToken.value
}
# Seconds the server asks us to wait (Retry-After as seconds or as a date), or $null when it does not say
function Get-RetryAfterSeconds($Response) {
    if (-not $Response) { return $null }
    $h = $null; try { $h = $Response.Headers } catch { }
    if (-not $h) { return $null }
    try {
        $ra = $h.RetryAfter   # HttpResponseHeaders (PowerShell 7)
        if ($ra -and $null -ne $ra.Delta) { return [int][Math]::Ceiling($ra.Delta.TotalSeconds) }
        if ($ra -and $null -ne $ra.Date) { return [int][Math]::Max(0, [Math]::Ceiling(($ra.Date - [DateTimeOffset]::UtcNow).TotalSeconds)) }
    } catch { }
    $raw = $null
    try { $raw = $h['Retry-After'] } catch { }
    if ("$raw" -match '^\s*(\d+)\s*$') { return [int]$Matches[1] }
    return $null
}
# A dropped or reset connection, a DNS hiccup or a timeout: no HTTP status, worth another try
function Test-TransportError($Exception) {
    $names = 'System.Net.Http.HttpRequestException', 'System.IO.IOException', 'System.Net.Sockets.SocketException', 'System.TimeoutException', 'System.Threading.Tasks.TaskCanceledException'
    for ($e = $Exception; $e; $e = $e.InnerException) {
        for ($t = $e.GetType(); $t; $t = $t.BaseType) {
            if ($t.FullName -in $names) { return $true }
            if ($t.FullName -eq 'System.Net.WebException' -and -not $e.Response) { return $true }
        }
    }
    return $false
}
# Seconds to wait before attempt $Try + 1, or $null to give up. Throttling (429) waits as long as Retry-After asks,
# or 5, 10, 20, 40, 60 seconds: the Activity Log allows 50 requests per 30 seconds per subscription, so shorter
# backoffs run out before the window resets. Server errors and transport errors back off 2, 4, 8, 16, 32 seconds.
function Get-RetryDelay($Exception, [int]$Code, [int]$Try, [int]$MaxTries = 6) {
    if ($Try -ge $MaxTries) { return $null }
    if ($Code -eq 429) {
        $after = Get-RetryAfterSeconds $(try { $Exception.Response } catch { $null })
        if ($null -ne $after) { return [int][Math]::Min([Math]::Max($after, 1), 120) }
        return [int][Math]::Min(5 * [Math]::Pow(2, $Try - 1), 60)
    }
    if ($Code -ge 500 -or ($Code -eq 0 -and (Test-TransportError $Exception))) { return [int][Math]::Pow(2, $Try) }
    return $null
}
# Returns @{ ok; data } or @{ ok = $false; error }. Retries throttling (429), server errors and dropped connections.
# GET only, plus the Resource Graph query POST: this script never changes anything.
function Invoke-Arm([string]$Method, [string]$Url, $Body) {
    # The bearer token goes to Azure Resource Manager only, also when following a nextLink taken from a response
    $u = $null
    if (-not [uri]::TryCreate("$Url", [UriKind]::Absolute, [ref]$u) -or $u.Scheme -ne 'https' -or $u.Host -ne 'management.azure.com') {
        return [pscustomobject]@{ ok = $false; error = "refused: not an https://management.azure.com URL, the token is not sent there ($Url)" }
    }
    for ($try = 1; ; $try++) {
        $p = @{ Method = $Method; Uri = $Url; Headers = @{ Authorization = "Bearer $(Get-ArmToken)" } }
        if ($null -ne $Body) { $p.Body = ($Body | ConvertTo-Json -Depth 10 -Compress); $p.ContentType = 'application/json' }
        try { return [pscustomobject]@{ ok = $true; data = (Invoke-RestMethod @p) } }
        catch {
            $code = 0; try { $code = [int]$_.Exception.Response.StatusCode } catch { }
            $wait = Get-RetryDelay $_.Exception $code $try
            if ($null -ne $wait) { Start-Sleep -Seconds $wait; continue }
            $msg = if ($_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { $_.Exception.Message }
            return [pscustomobject]@{ ok = $false; error = "HTTP $code $msg" }
        }
    }
}
function Invoke-Graph([string]$Query, [string[]]$Subs) {
    for ($c = 0; $c -lt $Subs.Count; $c += 1000) {
        $chunk = @($Subs[$c..([Math]::Min($c + 999, $Subs.Count - 1))])
        $got = 0; $skip = $null
        $tokens = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        do {
            $opts = [ordered]@{ '$top' = 1000; resultFormat = 'objectArray' }
            if ($skip) { $opts['$skipToken'] = $skip }
            $res = Invoke-Arm POST 'https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-06-01-preview' `
                @{ subscriptions = $chunk; query = $Query; options = $opts }
            if (-not $res.ok) { throw "Resource Graph query failed: $($res.error)" }
            $r = $res.data
            Assert-ResponseCollection $r 'data' 'Resource Graph'
            foreach ($d in @($r.data)) { $got++; $d }
            $next = $r.'$skipToken'
            if ($next -and -not $tokens.Add("$next")) { throw 'Resource Graph repeated a continuation token; paging aborted.' }
            $skip = $next
            if ("$($r.resultTruncated)" -eq 'true' -and -not $skip) { throw 'Resource Graph truncated results without a continuation token.' }
        } while ($skip)
        if ($r.totalRecords -gt $got) { throw "Result truncated ($got of $($r.totalRecords)) - the query is not being applied as intended." }
    }
}
$script:failures = @()
# When a resource provider in some cloud or region rejects the api-version this script asks for, retry once with
# an older GA version before giving up.
$script:apiFallbacks = @(
    @{ provider = 'Microsoft.Cdn'; version = '2026-10-01'; fallback = '2024-02-01' }
    @{ provider = 'Microsoft.Network'; version = '2024-05-01'; fallback = '2023-09-01' }
)
function Invoke-ArmGet([string]$Url) {
    $res = Invoke-Arm GET $Url
    if (-not $res.ok -and $res.error -match 'api-version|InvalidApiVersion|NoRegisteredProviderFound|InvalidResourceType') {
        foreach ($f in $script:apiFallbacks) {
            if ($Url -match "/providers/$($f.provider)/" -and $Url -match "api-version=$($f.version)") {
                $retry = Invoke-Arm GET ($Url -replace "api-version=$($f.version)", "api-version=$($f.fallback)")
                if ($retry.ok) { return $retry }
                $res.error = "$($res.error) (retry with api-version $($f.fallback): $($retry.error))"
                break
            }
        }
    }
    return $res
}
function Get-Paged([string]$Url) {
    $orig = $Url
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    while ($Url) {
        if (-not $seen.Add($Url)) { $script:failures += [pscustomobject]@{ url = $orig; error = 'Repeated nextLink; paging aborted.' }; return }
        $res = Invoke-ArmGet $Url
        if (-not $res.ok) { $script:failures += [pscustomobject]@{ url = $orig; error = $res.error }; return }
        try { Assert-ResponseCollection $res.data 'value' $Url }
        catch { $script:failures += [pscustomobject]@{ url = $orig; error = $_.Exception.Message }; return }
        $res.data.value
        $Url = $res.data.nextLink
    }
}
function Get-One([string]$Url) {
    $res = Invoke-ArmGet $Url
    if (-not $res.ok) { $script:failures += [pscustomobject]@{ url = $Url; error = $res.error }; return $null }
    return $res.data
}
function Expand-Json($v) {
    if ($v -is [string]) { if (-not $v.Trim()) { return $null }; try { return $v | ConvertFrom-Json } catch { return $v } }
    return $v
}
# Subscription ID of a resource ID, lower case
function Get-SubOfId([string]$Id) { if ("$Id" -match '^/subscriptions/([^/]+)/') { $Matches[1].ToLower() } else { '' } }

# ---- Pure functions: IP ranges, ports, source classification ---------------------------------------------------
# These have no Azure dependency and are covered by tests/Ingress.Tests.ps1.

# Parses '203.0.113.0/24', '203.0.113.7' or '2001:db8::/32'. Returns $null for anything that is not an IP or CIDR
# (service tags, '*', words). network/block are BigIntegers so IPv4 and IPv6 share one code path.
function ConvertTo-IpInfo([string]$Value) {
    $v = "$Value".Trim()
    if (-not $v -or ($v -notmatch '[.:]')) { return $null }
    $parts = $v.Split('/')
    if ($parts.Count -gt 2) { return $null }
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($parts[0], [ref]$ip)) { return $null }
    $family = if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) { 6 } else { 4 }
    $bits = if ($family -eq 6) { 128 } else { 32 }
    $prefix = $bits
    if ($parts.Count -eq 2) {
        $p = 0
        if (-not [int]::TryParse($parts[1], [ref]$p) -or $p -lt 0 -or $p -gt $bits) { return $null }
        $prefix = $p
    }
    $n = [System.Numerics.BigInteger]::Zero
    foreach ($b in $ip.GetAddressBytes()) { $n = $n * 256 + [int]$b }   # big-endian
    $block = [System.Numerics.BigInteger]::Pow(2, $bits - $prefix)
    $network = [System.Numerics.BigInteger]::Divide($n, $block) * $block
    [pscustomobject]@{ text = $v; family = $family; prefixLength = $prefix; network = $network; block = $block; addresses = $block }
}
function Test-PrefixContains($Outer, $Inner) {
    if (-not $Outer -or -not $Inner -or $Outer.family -ne $Inner.family -or $Inner.prefixLength -lt $Outer.prefixLength) { return $false }
    return [System.Numerics.BigInteger]::Divide($Inner.network, $Outer.block) -eq [System.Numerics.BigInteger]::Divide($Outer.network, $Outer.block)
}
function Test-PrefixOverlaps($A, $B) { return (Test-PrefixContains $A $B) -or (Test-PrefixContains $B $A) }
# RFC 1918, CGNAT, loopback, link-local and IPv6 unique-local / link-local: not reachable from the internet.
$script:privateRanges = @('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '0.0.0.0/8', 'fc00::/7', 'fe80::/10', '::1/128') |
    ForEach-Object { ConvertTo-IpInfo $_ }
function Test-PrivateRange($Info) {
    if (-not $Info) { return $false }
    foreach ($r in $script:privateRanges) { if (Test-PrefixContains $r $Info) { return $true } }
    return $false
}

# Classifies one NSG/WAF/firewall source value. Classes, from most to least permissive:
#   OPEN          the whole internet: '*', 'Internet', 0.0.0.0/0, ::/0, 'Any'
#   BROAD         a public range wider than the tight threshold, or the AzureCloud tags (any Azure customer)
#   AZURE-SHARED  a multi-tenant Azure service tag (AzureFrontDoor.Backend, AppService, ...): any tenant's instance of that service
#   TIGHT         a public range at or below the threshold ("small CIDR"), or a single public address
#   CONTROL-PLANE Microsoft-operated management traffic: ApiManagement, GatewayManager, AzureLoadBalancer, AzureTrafficManager
#   VNET          the VirtualNetwork tag
#   PRIVATE       RFC 1918 / CGNAT / link-local ranges (not internet-routable)
#   ASG           an application security group
#   UNKNOWN       an unrecognised value (treated as moderately permissive so that it is reviewed)
$script:classSeverity = @{ 'OPEN' = 5; 'BROAD' = 4; 'AZURE-SHARED' = 3; 'UNKNOWN' = 3; 'TIGHT' = 2; 'CONTROL-PLANE' = 1; 'VNET' = 1; 'PRIVATE' = 1; 'ASG' = 1; 'NONE' = 0 }
$script:controlPlaneTags = 'ApiManagement', 'GatewayManager', 'AzureLoadBalancer', 'AzureTrafficManager', 'AzurePlatformDNS', 'AzurePlatformIMDS', 'AzurePlatformLKM'
function Get-SourceClass([string]$Source, [int]$Tight4 = 24, [int]$Tight6 = 48) {
    $s = "$Source".Trim()
    $row = { param($class, $detail, $addresses, $prefix) [pscustomobject]@{ source = $s; class = $class; severity = $script:classSeverity[$class]; detail = $detail; addresses = $addresses; prefixLength = $prefix } }
    if (-not $s) { return & $row 'UNKNOWN' 'empty source' '' $null }
    if ($s -in '*', 'Internet', 'Any') { return & $row 'OPEN' 'any internet address' '' $null }
    if ($s -like 'ASG:*') { return & $row 'ASG' 'application security group (VNet-internal)' '' $null }
    $info = ConvertTo-IpInfo $s
    if ($info) {
        if ($info.prefixLength -eq 0) { return & $row 'OPEN' 'any address (/0)' $info.addresses 0 }
        if (Test-PrivateRange $info) { return & $row 'PRIVATE' 'private range, not internet-routable' $info.addresses $info.prefixLength }
        $tight = if ($info.family -eq 6) { $Tight6 } else { $Tight4 }
        if ($info.prefixLength -ge $tight) { return & $row 'TIGHT' "public range of $($info.addresses) address(es)" $info.addresses $info.prefixLength }
        return & $row 'BROAD' "public range of $($info.addresses) addresses (/$($info.prefixLength) is wider than /$tight)" $info.addresses $info.prefixLength
    }
    # Service tags, optionally region-suffixed: 'ApiManagement.WestEurope', 'AzureCloud.EastUS'
    $base = ($s -split '\.')[0]
    if ($s -eq 'VirtualNetwork') { return & $row 'VNET' 'VirtualNetwork tag (VNet, peered VNets, on-premises via gateway)' '' $null }
    if ($base -in $script:controlPlaneTags) { return & $row 'CONTROL-PLANE' "Microsoft-operated service tag $s" '' $null }
    if ($base -eq 'AzureCloud') { return & $row 'BROAD' "service tag ${s}: all Azure public addresses, including other customers' resources" '' $null }
    if ($s -match '^[A-Za-z][A-Za-z0-9]*(\.[A-Za-z0-9]+)*$') { return & $row 'AZURE-SHARED' "service tag ${s}: any tenant's resources of that service" '' $null }
    return & $row 'UNKNOWN' 'unrecognised source value' '' $null
}
# Severity label for a set of classes (the most permissive wins)
function Get-WorstClass([string[]]$Classes) {
    $best = 'NONE'
    foreach ($c in @($Classes | Where-Object { $_ })) { if ($script:classSeverity[$c] -gt $script:classSeverity[$best]) { $best = $c } }
    return $best
}

# NSG port syntax: '*', '443', '80-443', and comma-separated mixes of those
function Get-PortRanges($Values) {
    foreach ($v in @($Values)) {
        foreach ($piece in "$v".Split(',')) {
            $p = $piece.Trim()
            if (-not $p) { continue }
            if ($p -eq '*') { [pscustomobject]@{ from = 0; to = 65535 } }
            elseif ($p -match '^(\d+)\s*-\s*(\d+)$') { [pscustomobject]@{ from = [int]$Matches[1]; to = [int]$Matches[2] } }
            elseif ($p -match '^\d+$') { [pscustomobject]@{ from = [int]$p; to = [int]$p } }
        }
    }
}
function Test-PortHit($Ranges, [int]$Port) {
    foreach ($r in @($Ranges)) { if ($Port -ge $r.from -and $Port -le $r.to) { return $true } }
    return $false
}
function Test-TcpProtocol([string]$Protocol) { return ("$Protocol" -eq '*' -or "$Protocol" -ieq 'Tcp') }

# ---- NSG evaluation ----------------------------------------------------------------------------------------------
# Normalises an NSG resource (custom + default rules) into flat rule objects. When the resource carries no default
# rules (older exports, test fixtures), the three standard inbound defaults are synthesised.
function Get-NsgRules($Nsg) {
    $rows = @()
    foreach ($set in @(@{ list = $Nsg.rules; default = $false }, @{ list = $Nsg.defaultRules; default = $true })) {
        foreach ($r in @($set.list)) {
            if (-not $r) { continue }
            $p = $r.properties
            $sources = @(); $dests = @(); $portVals = @()
            if ($p.sourceAddressPrefix) { $sources += "$($p.sourceAddressPrefix)" }
            $sources += @($p.sourceAddressPrefixes | ForEach-Object { "$_" } | Where-Object { $_ })
            $sources += @($p.sourceApplicationSecurityGroups | Where-Object { $_ } | ForEach-Object { 'ASG:' + (Get-ResourceName $_.id) })
            if ($p.destinationAddressPrefix) { $dests += "$($p.destinationAddressPrefix)" }
            $dests += @($p.destinationAddressPrefixes | ForEach-Object { "$_" } | Where-Object { $_ })
            $dests += @($p.destinationApplicationSecurityGroups | Where-Object { $_ } | ForEach-Object { 'ASG:' + (Get-ResourceName $_.id) })
            if ($p.destinationPortRange) { $portVals += "$($p.destinationPortRange)" }
            $portVals += @($p.destinationPortRanges | ForEach-Object { "$_" } | Where-Object { $_ })
            $srcPortVals = @()
            if ($p.sourcePortRange) { $srcPortVals += "$($p.sourcePortRange)" }
            $srcPortVals += @($p.sourcePortRanges | ForEach-Object { "$_" } | Where-Object { $_ })
            $rows += [pscustomobject]@{
                nsg = $Nsg.name; nsgId = $Nsg.id; name = $r.name; priority = [int]$p.priority; direction = "$($p.direction)"; access = "$($p.access)"
                protocol = "$($p.protocol)"; sources = @($sources); destinations = @($dests); ports = @(Get-PortRanges $portVals)
                portText = ($portVals -join ','); sourcePorts = @(Get-PortRanges $srcPortVals); sourcePortText = ($srcPortVals -join ',')
                isDefault = $set.default; description = "$($p.description)"
            }
        }
    }
    if (-not @($rows | Where-Object { $_.isDefault -and $_.direction -eq 'Inbound' }).Count) {
        $mk = { param($name, $prio, $access, $src, $dst) [pscustomobject]@{ nsg = $Nsg.name; nsgId = $Nsg.id; name = $name; priority = $prio; direction = 'Inbound'; access = $access
            protocol = '*'; sources = @($src); destinations = @($dst); ports = @(Get-PortRanges '*'); portText = '*'; sourcePorts = @(Get-PortRanges '*'); sourcePortText = '*'
            isDefault = $true; description = 'default rule (synthesised)' } }
        $rows += & $mk 'AllowVNetInBound' 65000 'Allow' 'VirtualNetwork' 'VirtualNetwork'
        $rows += & $mk 'AllowAzureLoadBalancerInBound' 65001 'Allow' 'AzureLoadBalancer' '*'
        $rows += & $mk 'DenyAllInBound' 65500 'Deny' '*' '*'
    }
    $rows | Sort-Object priority, name
}
# Does the rule's destination describe the target subnet? Unknown or unresolvable destinations count as a match,
# except service tags other than VirtualNetwork and application security groups (APIM instances are not in an ASG).
# An allow counts on any overlap (conservative). With -RequireFullCover, as used for deny rules, the destinations
# together must contain every target prefix: a deny aimed at part of the subnet does not shadow the instance.
function Test-DestinationHit($Rule, $TargetPrefixes, [switch]$RequireFullCover) {
    $d = @($Rule.destinations)
    if (-not $d.Count) { return $true }
    $targets = @($TargetPrefixes | Where-Object { $_ } | ForEach-Object { ConvertTo-IpInfo $_ } | Where-Object { $_ })   # @($null) would count as one element
    $dests = @()
    foreach ($x in $d) {
        if ($x -in '*', 'VirtualNetwork', 'Any') { return $true }
        if ($x -like 'ASG:*') { continue }
        $info = ConvertTo-IpInfo $x
        if (-not $info) { continue }
        if ($info.prefixLength -eq 0 -or -not $targets.Count) { return $true }
        $dests += $info
    }
    if (-not $dests.Count) { return $false }
    if ($RequireFullCover) {
        foreach ($t in $targets) { if (-not @($dests | Where-Object { Test-PrefixContains $_ $t }).Count) { return $false } }
        return $true
    }
    foreach ($t in $targets) { foreach ($x in $dests) { if (Test-PrefixOverlaps $x $t) { return $true } } }
    return $false
}
# Does a port list cover every port? A deny limited to some source ports cannot shadow an allow: clients pick their port.
function Test-PortsCoverAll($Ranges) {
    if (-not @($Ranges).Count) { return $true }
    foreach ($r in @($Ranges)) { if ($r.from -le 0 -and $r.to -ge 65535) { return $true } }
    return $false
}
# How a deny source relates to an allow source, for the question "is this still reachable from the internet?":
#   covers   the deny blocks every internet address the allow admits
#   overlaps the deny blocks part of them
#   none     unrelated, or unresolvable (service tags are opaque)
function Get-SourceRelation([string]$DenySource, [string]$AllowSource) {
    $d = "$DenySource".Trim(); $a = "$AllowSource".Trim()
    if ($d -in '*', 'Any') { return 'covers' }
    $di = ConvertTo-IpInfo $d; $ai = ConvertTo-IpInfo $a
    $aOpen = ($a -in '*', 'Internet', 'Any') -or ($ai -and $ai.prefixLength -eq 0)
    $aPublicCidr = $ai -and $ai.prefixLength -gt 0 -and -not (Test-PrivateRange $ai)
    if ($d -eq 'Internet') { if ($aOpen -or $aPublicCidr) { return 'covers' }; return 'none' }
    if ($di) {
        if ($di.prefixLength -eq 0) {
            if ($ai) { if ($ai.family -eq $di.family) { return 'covers' } else { return 'none' } }
            if ($aOpen) { if ($di.family -eq 4) { return 'covers' } else { return 'overlaps' } }
            return 'none'
        }
        if ($ai) { if (Test-PrefixContains $di $ai) { return 'covers' }; if (Test-PrefixContains $ai $di) { return 'overlaps' }; return 'none' }
        if ($aOpen) { return 'overlaps' }
        return 'none'
    }
    if ($d -ieq $a) { return 'covers' }
    $dBase = ($d -split '\.')[0]; $aBase = ($a -split '\.')[0]
    if ($dBase -ieq $aBase -and $d -notmatch '\.') { return 'covers' }     # a base tag covers its regional variants
    if ($dBase -ieq $aBase) { return 'overlaps' }
    if ($d -eq 'VirtualNetwork' -and $aOpen) { return 'overlaps' }
    return 'none'
}
# Every inbound Allow rule that admits TCP traffic to $Port, one row per source value, with the higher-priority deny
# rules that shadow it (for internet addresses) or restrict part of it. Rows with effective = $true matter.
function Get-NsgPortExposure($Rules, [int]$Port, [int]$Tight4 = 24, [int]$Tight6 = 48, $TargetPrefixes) {
    $inbound = @($Rules | Where-Object { $_.direction -ieq 'Inbound' } | Sort-Object priority)
    $hits = @($inbound | Where-Object { (Test-TcpProtocol $_.protocol) -and (Test-PortHit $_.ports $Port) -and (Test-DestinationHit $_ $TargetPrefixes) })
    foreach ($r in @($hits | Where-Object { $_.access -ieq 'Allow' })) {
        foreach ($s in @($r.sources)) {
            $cls = Get-SourceClass $s $Tight4 $Tight6
            $shadow = ''; $partial = @()
            foreach ($d in @($hits | Where-Object { $_.access -ieq 'Deny' -and $_.priority -lt $r.priority })) {
                # A deny shadows the allow only when it covers every address of the instance and every client source port
                $full = (Test-DestinationHit $d $TargetPrefixes -RequireFullCover) -and (Test-PortsCoverAll $d.sourcePorts)
                foreach ($ds in @($d.sources)) {
                    $rel = Get-SourceRelation $ds $s
                    if ($rel -eq 'covers' -and $full) { $shadow = "$($d.name) (priority $($d.priority), source $ds)"; break }
                    if ($rel -in 'covers', 'overlaps') { $partial += "$($d.name) (priority $($d.priority), source $ds$(if (-not $full) { ', only part of the destination or source ports' }))" }
                }
                if ($shadow) { break }
            }
            [pscustomobject]@{
                nsg = $r.nsg; nsgId = $r.nsgId; port = $Port; rule = $r.name; priority = $r.priority; isDefault = $r.isDefault
                protocol = $r.protocol; ports = $r.portText; source = $s; sourceClass = $cls.class; severity = $cls.severity
                addresses = "$($cls.addresses)"; detail = $cls.detail; effective = (-not $shadow)
                shadowedBy = $shadow; partiallyDeniedBy = ($partial -join '; ')
            }
        }
    }
}
function Get-PortExposureClass($Rows) { Get-WorstClass @($Rows | Where-Object { $_.effective } | ForEach-Object { $_.sourceClass }) }

# What an effective allow on the APIM subnet means, against Microsoft's NSG reference for Classic tiers in a VNet:
#   3443 from ApiManagement (External and Internal), 80/443 from Internet (External only), 443 from
#   AzureTrafficManager (External), 6390 from AzureLoadBalancer. Anything wider on 3443 exposes the service
#   configuration (management) endpoint; anything on 80/443 is the public path to the gateway, developer portal,
#   Git and management hostnames.
function Get-ApimRuleAssessment([int]$Port, [string]$Class, [string]$Source, [string]$VnetType) {
    $base = ("$Source" -split '\.')[0]
    switch ($Port) {
        3443 {
            if ($base -eq 'ApiManagement') { return 'expected: Azure control plane to the management endpoint (Microsoft reference)' }
            switch ($Class) {
                'OPEN' { return 'OPEN: the service configuration (management) endpoint on 3443 is reachable from the whole internet' }
                'BROAD' { return 'BROAD: a wide range can reach the service configuration (management) endpoint on 3443' }
                'TIGHT' { return 'tight range on 3443: not needed by Azure (the control plane uses the ApiManagement tag); confirm who it is' }
                'AZURE-SHARED' { return 'unexpected service tag on 3443: any tenant using that service could reach the management endpoint' }
                'UNKNOWN' { return 'unrecognised source on 3443; review' }
                'CONTROL-PLANE' { return "Microsoft-operated tag $Source on 3443: the reference uses ApiManagement; confirm it is needed" }
                default { return 'VNet-internal access to the management endpoint on 3443 (not an internet path)' }
            }
        }
        { $_ -in 80, 443 } {
            if ($base -eq 'AzureTrafficManager') { return 'expected: Traffic Manager probes (Microsoft reference, External mode)' }
            if ($VnetType -ieq 'Internal') {
                if ($Class -in 'OPEN', 'BROAD', 'TIGHT', 'AZURE-SHARED', 'UNKNOWN') { return "allow from $Class source, but Internal mode has no public VIP on $Port (reachable only via a front end such as Application Gateway or Front Door)" }
                return "VNet-internal access to the gateway on $Port (Internal mode)"
            }
            switch ($Class) {
                'OPEN' { return "OPEN: gateway, developer portal, Git and management hostnames on $Port are reachable from the whole internet (Microsoft's reference allows this for client traffic; it is the public ingress path)" }
                'BROAD' { return "BROAD: a wide range can reach the gateway and the other hostnames on $Port" }
                'TIGHT' { return "tight: only a small range can reach port $Port" }
                'AZURE-SHARED' { return "AZURE-SHARED: any tenant's instance of that service (for example any Front Door) can reach port $Port; pair with an X-Azure-FDID check-header policy" }
                'UNKNOWN' { return "unrecognised source on $Port; review" }
                default { return "VNet-internal access on $Port (not an internet path)" }
            }
        }
        6390 { if ($base -eq 'AzureLoadBalancer') { return 'expected: Azure infrastructure load balancer (Microsoft reference)' }; return "port 6390 (infrastructure) open to $Class source; the reference expects AzureLoadBalancer only" }
        default { return "other port ($Port) allowed from $Class source" }
    }
}

# ---- WAF assessment ----------------------------------------------------------------------------------------------
# Reads an Application Gateway WAF policy or a Front Door WAF policy and rates it. A custom rule that matches on the
# client address (RemoteAddr / SocketAddr with IPMatch) is classified by the width of its ranges: an Allow for an
# open or broad range skips the managed rules for most of the internet; a Block with a negated match is an
# allowlist, which is the restrictive shape.
$script:ipVariables = 'RemoteAddr', 'SocketAddr', 'ClientAddr'
function Get-WafCustomRuleRows($Policy, [string]$Kind, [int]$Tight4 = 24, [int]$Tight6 = 48) {
    $p = $Policy.properties
    $rules = if ($Kind -eq 'FrontDoor') { @($p.customRules.rules) } else { @($p.customRules) }
    foreach ($r in @($rules | Where-Object { $_ })) {
        $enabled = if ($Kind -eq 'FrontDoor') { "$($r.enabledState)" -ne 'Disabled' } else { "$($r.state)" -ne 'Disabled' }
        $conds = @(); $ipValues = @(); $ipNegated = $false; $hasIp = $false; $nonIp = 0
        foreach ($c in @($r.matchConditions | Where-Object { $_ })) {
            $vars = if ($Kind -eq 'FrontDoor') { @("$($c.matchVariable)") } else { @($c.matchVariables | ForEach-Object { "$($_.variableName)" }) }
            $vals = if ($Kind -eq 'FrontDoor') { @($c.matchValue) } else { @($c.matchValues) }
            # The Application Gateway schema spells the flag 'negationConditon'; accept both spellings.
            $neg = [bool]($c.negateCondition -or $c.negationCondition -or $c.negationConditon)
            $isIp = @($vars | Where-Object { $_ -in $script:ipVariables }).Count -gt 0 -and "$($c.operator)" -ieq 'IPMatch'
            if ($isIp) { $hasIp = $true; $ipValues += @($vals | ForEach-Object { "$_" }); if ($neg) { $ipNegated = $true } } else { $nonIp++ }
            $conds += "$(if ($neg) { 'NOT ' })$($vars -join '/') $($c.operator) [$((@($vals | ForEach-Object { "$_" }) | Select-Object -First 6) -join ', ')$(if (@($vals).Count -gt 6) { ', ...' })]"
        }
        $classes = @($ipValues | ForEach-Object { (Get-SourceClass $_ $Tight4 $Tight6).class })
        $ipClass = Get-WorstClass $classes
        $action = "$($r.action)"; $type = "$($r.ruleType)"
        $assessment = if (-not $enabled) { 'disabled: no effect' }
            elseif ($type -ieq 'RateLimitRule') { "rate limit ($action)" }
            elseif ($action -ieq 'Allow' -and -not $hasIp) { 'ALLOW BYPASS: matching requests skip the managed rules, with no source-address restriction' }
            elseif ($action -ieq 'Allow' -and $ipNegated) { "ALLOW BYPASS: everything except $ipClass ranges skips the managed rules" }
            elseif ($action -ieq 'Allow') { if ($ipClass -in 'OPEN', 'BROAD', 'AZURE-SHARED', 'UNKNOWN') { "PERMISSIVE ALLOW: $ipClass source range skips the managed rules" } else { "allow for a $ipClass range (those sources skip the managed rules)" } }
            elseif ($action -ieq 'Block' -and $hasIp -and $ipNegated -and $nonIp -eq 0) { if ($ipClass -in 'OPEN', 'BROAD', 'AZURE-SHARED', 'UNKNOWN') { "ALLOWLIST (broad): blocks everything except $ipClass ranges" } else { "ALLOWLIST: blocks everything except $ipClass ranges" } }
            elseif ($action -ieq 'Block' -and $hasIp -and -not $ipNegated) { "blocklist for $ipClass ranges" }
            elseif ($action -ieq 'Block') { 'block on request content' }
            elseif ($action -ieq 'Log') { 'log only' }
            else { "$action rule" }
        [pscustomobject]@{
            policyId = $Policy.id; policy = $Policy.name; kind = $Kind; rule = "$($r.name)"; priority = [int]$r.priority; enabled = $enabled
            ruleType = $type; action = $action; conditions = ($conds -join ' AND '); ipMatch = $hasIp; ipNegated = $ipNegated
            ipClass = $(if ($hasIp) { $ipClass } else { '' }); assessment = $assessment
        }
    }
}
function Get-WafAssessment($Policy, [string]$Kind, [int]$Tight4 = 24, [int]$Tight6 = 48) {
    $p = $Policy.properties
    $state = if ($Kind -eq 'FrontDoor') { "$($p.policySettings.enabledState)" } else { "$($p.policySettings.state)" }
    if (-not $state) { $state = 'Enabled' }
    $mode = "$($p.policySettings.mode)"
    $body = "$($p.policySettings.requestBodyCheck)"
    $rows = @(Get-WafCustomRuleRows $Policy $Kind $Tight4 $Tight6)
    $sets = @(); $disabledRules = 0; $weakenedRules = 0; $disabledGroups = 0; $exclusions = @($p.managedRules.exclusions | Where-Object { $_ }).Count
    foreach ($ms in @($p.managedRules.managedRuleSets | Where-Object { $_ })) {
        $sets += "$($ms.ruleSetType) $($ms.ruleSetVersion)$(if ($ms.ruleSetAction) { " ($($ms.ruleSetAction))" })"
        $exclusions += @($ms.exclusions | Where-Object { $_ }).Count
        foreach ($g in @($ms.ruleGroupOverrides | Where-Object { $_ })) {
            $exclusions += @($g.exclusions | Where-Object { $_ }).Count
            if (-not @($g.rules | Where-Object { $_ }).Count) { $disabledGroups++; continue }
            foreach ($rule in @($g.rules | Where-Object { $_ })) {
                $exclusions += @($rule.exclusions | Where-Object { $_ }).Count
                $st = if ($Kind -eq 'FrontDoor') { "$($rule.enabledState)" } else { "$($rule.state)" }
                if ($st -ine 'Enabled') { $disabledRules++ }      # an override without a state disables the rule
                elseif ("$($rule.action)" -in 'Log', 'Allow') { $weakenedRules++ }
            }
        }
    }
    $verdict = if ($state -ieq 'Disabled') { 'WAF DISABLED' } elseif ($mode -ieq 'Detection') { 'DETECTION ONLY' } elseif ($mode -ieq 'Prevention') { 'PREVENTION' } else { "UNKNOWN MODE ($mode)" }
    $permissive = @($rows | Where-Object { $_.assessment -like 'ALLOW BYPASS*' -or $_.assessment -like 'PERMISSIVE ALLOW*' })
    $allowlists = @($rows | Where-Object { $_.assessment -like 'ALLOWLIST*' -and $_.enabled })
    $allowlistClass = if ($allowlists.Count) { Get-WorstClass @($allowlists | ForEach-Object { $_.ipClass }) } else { '' }
    # Prevention mode blocks nothing without rules that block, and a custom Allow that matches every request skips them all
    $blocking = @($rows | Where-Object { $_.enabled -and $_.action -ieq 'Block' -and $_.ruleType -ine 'RateLimitRule' })
    $allowAll = @($rows | Where-Object { $_.enabled -and $_.action -ieq 'Allow' -and $_.ruleType -ine 'RateLimitRule' -and
        (($_.ipMatch -and -not $_.ipNegated -and $_.ipClass -eq 'OPEN') -or -not $_.conditions -or $_.conditions -match '(^| AND )(NOT )?\S+ Any \[') })
    if ($verdict -eq 'PREVENTION') {
        if ($allowAll.Count) { $verdict = 'PREVENTION (custom allow admits everyone)' }
        elseif (-not $sets.Count -and -not $blocking.Count) { $verdict = 'PREVENTION (no blocking rules)' }
    }
    $notes = @()
    if ($permissive.Count) { $notes += "$($permissive.Count) custom rule(s) let traffic skip the managed rules" }
    if ($allowlists.Count) { $notes += "allowlist custom rule(s) admit only $allowlistClass ranges" }
    if ($disabledRules -or $disabledGroups) { $notes += "$disabledRules managed rule(s) and $disabledGroups rule group(s) disabled" }
    if ($weakenedRules) { $notes += "$weakenedRules managed rule(s) set to Log/Allow" }
    if ($exclusions) { $notes += "$exclusions exclusion(s)" }
    if ($body -in 'False', 'Disabled') { $notes += 'request body inspection off' }
    if (-not $sets.Count) { $notes += 'no managed rule set' }
    [pscustomobject]@{
        policyId = $Policy.id; policy = $Policy.name; kind = $Kind; state = $state; mode = $mode; verdict = $verdict
        requestBodyCheck = $body; managedRuleSets = ($sets -join '; '); disabledRules = $disabledRules; disabledRuleGroups = $disabledGroups
        weakenedRules = $weakenedRules; exclusions = $exclusions; customRules = $rows.Count; permissiveAllows = $permissive.Count
        allowlist = ($allowlists.Count -gt 0); allowlistClass = $allowlistClass; notes = ($notes -join '; '); customRuleRows = $rows
    }
}
# The legacy inline WAF configuration on an Application Gateway (no separate policy resource)
function Get-LegacyWafAssessment($Gateway) {
    $c = $Gateway.properties.webApplicationFirewallConfiguration
    if (-not $c) { return $null }
    $verdict = if (-not [bool]$c.enabled) { 'WAF DISABLED' } elseif ("$($c.firewallMode)" -ieq 'Detection') { 'DETECTION ONLY' } elseif ("$($c.firewallMode)" -ieq 'Prevention') { 'PREVENTION' } else { "UNKNOWN MODE ($($c.firewallMode))" }
    $groups = @($c.disabledRuleGroups | Where-Object { $_ })
    $notes = @(); if ($groups.Count) { $notes += "$($groups.Count) rule group(s) with disabled rules" }
    if (@($c.exclusions | Where-Object { $_ }).Count) { $notes += "$(@($c.exclusions | Where-Object { $_ }).Count) exclusion(s)" }
    if ($c.PSObject.Properties['requestBodyCheck'] -and -not [bool]$c.requestBodyCheck) { $notes += 'request body inspection off' }
    [pscustomobject]@{
        policyId = "$($Gateway.id) (inline configuration)"; policy = "$($Gateway.name) inline WAF configuration"; kind = 'AppGatewayLegacy'; state = $(if ([bool]$c.enabled) { 'Enabled' } else { 'Disabled' })
        mode = "$($c.firewallMode)"; verdict = $verdict; requestBodyCheck = "$($c.requestBodyCheck)"; managedRuleSets = "$($c.ruleSetType) $($c.ruleSetVersion)"
        disabledRules = [int]($groups | ForEach-Object { @($_.rules | Where-Object { $null -ne $_ }).Count } | Measure-Object -Sum).Sum
        disabledRuleGroups = @($groups | Where-Object { -not @($_.rules | Where-Object { $null -ne $_ }).Count }).Count
        weakenedRules = 0; exclusions = @($c.exclusions | Where-Object { $_ }).Count; customRules = 0; permissiveAllows = 0; allowlist = $false; allowlistClass = ''
        notes = ($notes -join '; '); customRuleRows = @()
    }
}
# Verdict of a pathway that goes through a WAF: how much of the internet reaches the APIM instance through it.
# Returns one of the source classes, so WAF-fronted pathways compare with NSG rows.
function Get-WafPathwayClass($Assessment) {
    if (-not $Assessment) { return 'OPEN' }
    if ($Assessment.allowlist -and $Assessment.verdict -eq 'PREVENTION' -and $Assessment.state -ieq 'Enabled') { return $Assessment.allowlistClass }
    return 'OPEN'
}

# ---- APIM endpoints, reach per network mode, global policy ------------------------------------------------------
$script:endpointGroups = @{ Proxy = 'gateway'; DeveloperPortal = 'developer portal'; Portal = 'developer portal (legacy)'; Management = 'management hostname'; Scm = 'git'; ConfigurationApi = 'configuration API' }
# Every hostname an instance answers on: the default *.azure-api.net names plus the custom hostnames.
function Get-ApimHosts($Apim) {
    $n = "$($Apim.name)"
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $rows = @()
    $defaults = [ordered]@{ Proxy = "$n.azure-api.net"; DeveloperPortal = "$n.developer.azure-api.net"; Portal = "$n.portal.azure-api.net"
                            Management = "$n.management.azure-api.net"; Scm = "$n.scm.azure-api.net"; ConfigurationApi = "$n.configuration.azure-api.net" }
    foreach ($k in $defaults.Keys) { if ($seen.Add($defaults[$k])) { $rows += [pscustomobject]@{ type = $k; endpoint = $script:endpointGroups[$k]; host = $defaults[$k]; isDefault = $true } } }
    foreach ($h in @(Expand-Json $Apim.hostnames | Where-Object { $_ })) {
        $hn = "$($h.hostName)".Trim().TrimEnd('.')
        if (-not $hn) { continue }
        $t = "$($h.type)"
        $grp = if ($script:endpointGroups.ContainsKey($t)) { $script:endpointGroups[$t] } else { $t }
        if ($seen.Add($hn)) { $rows += [pscustomobject]@{ type = $t; endpoint = $grp; host = $hn; isDefault = $false } }
    }
    $rows
}
# All IP addresses of an instance (primary and additional locations), lower-case
function Get-ApimIps($Apim) {
    $ips = @()
    $ips += @(Expand-Json $Apim.publicIPs | ForEach-Object { "$_" } | Where-Object { $_ })
    $ips += @(Expand-Json $Apim.privateIPs | ForEach-Object { "$_" } | Where-Object { $_ })
    foreach ($loc in @(Expand-Json $Apim.additionalLocations | Where-Object { $_ })) {
        $ips += @($loc.publicIPAddresses | ForEach-Object { "$_" } | Where-Object { $_ })
        $ips += @($loc.privateIPAddresses | ForEach-Object { "$_" } | Where-Object { $_ })
    }
    @($ips | ForEach-Object { $_.Trim().ToLower() } | Sort-Object -Unique)
}
# Does an address (FQDN or IP) used by a front end point at this instance? Returns the endpoint name or $null.
function Resolve-ApimTarget([string]$Address, $Hosts, $Ips) {
    $a = "$Address".Trim().TrimEnd('.').ToLower()
    if (-not $a) { return $null }
    foreach ($h in @($Hosts)) { if ("$($h.host)".ToLower() -eq $a) { return $h.endpoint } }
    if (@($Ips) -contains $a) { return 'ip (any hostname)' }
    return $null
}
# Where the instance's own endpoints can be reached from, per network mode. $Nsg443 / $Nsg3443 are the effective
# source classes on the APIM subnet (Get-PortExposureClass): 'NONE' when nothing allows the port. "management" is
# the service configuration endpoint on port 3443 (Azure's control plane, and formerly the direct management API);
# "gateway" stands for the 443 endpoints: gateway, developer portal, Git and the management hostname.
function Get-ApimReach([string]$VnetType, [string]$PublicAccess, [int]$PrivateEndpoints, [string]$Nsg443, [string]$Nsg3443, [bool]$HasNsg) {
    $map = { param($c) switch ($c) { 'OPEN' { 'INTERNET' } 'BROAD' { 'BROAD' } 'AZURE-SHARED' { 'AZURE-SHARED' } 'UNKNOWN' { 'BROAD (unrecognised source)' } 'TIGHT' { 'TIGHT' }
                                     'CONTROL-PLANE' { 'CONTROL-PLANE ONLY' } 'NONE' { 'PRIVATE (no inbound allow)' } default { 'PRIVATE' } } }
    $mode = if ($VnetType) { $VnetType } else { 'None' }
    if ($mode -ieq 'External' -or $mode -ieq 'Internal') {
        if (-not $HasNsg) {
            $mgmt = 'INTERNET (no NSG restricts port 3443 on the public VIP)'
            $gw = if ($mode -ieq 'External') { 'INTERNET (no NSG on the APIM subnet)' } else { 'PRIVATE (Internal mode: no public VIP for 443)' }
        } else {
            $mgmt = & $map $Nsg3443
            $gw = if ($mode -ieq 'External') { & $map $Nsg443 } else { 'PRIVATE (Internal mode: no public VIP for 443)' }
        }
        return [pscustomobject]@{ mode = $mode; gateway = $gw; management = $mgmt; basis = "NSG on the APIM subnet ($mode mode)" }
    }
    if ($PublicAccess -ieq 'Disabled') {
        $gw = if ($PrivateEndpoints -gt 0) { 'PRIVATE (public network access disabled; private endpoint only)' } else { 'PRIVATE (public network access disabled, no private endpoint)' }
        return [pscustomobject]@{ mode = $mode; gateway = $gw; basis = 'publicNetworkAccess = Disabled'
                                  management = 'PRIVATE (public network access disabled; Azure Policy counts this as closing the service configuration endpoints)' }
    }
    return [pscustomobject]@{ mode = $mode; gateway = 'INTERNET'; management = 'INTERNET'; basis = "no VNet integration ($mode): every endpoint is on the public VIP" }
}
function Get-ReachClass([string]$Reach) {
    switch -Wildcard ("$Reach") {
        'INTERNET*' { 'OPEN' } 'BROAD*' { 'BROAD' } 'AZURE-SHARED*' { 'AZURE-SHARED' } 'TIGHT*' { 'TIGHT' }
        'CONTROL-PLANE*' { 'CONTROL-PLANE' } 'PRIVATE*' { 'PRIVATE' } default { 'UNKNOWN' }
    }
}
# Class of an ip-filter address-range (from/to). Policy expressions cannot be evaluated.
function Get-RangeClass([string]$From, [string]$To, [int]$Tight4 = 24, [int]$Tight6 = 48) {
    $f = ConvertTo-IpInfo $From; $t = ConvertTo-IpInfo $To
    if (-not $f -or -not $t -or $f.family -ne $t.family) { return 'UNKNOWN' }
    $count = $t.network - $f.network + 1
    if ($count -le 0) { return 'UNKNOWN' }
    $bits = if ($f.family -eq 6) { 128 } else { 32 }
    $tight = if ($f.family -eq 6) { $Tight6 } else { $Tight4 }
    if ($count -ge [System.Numerics.BigInteger]::Pow(2, $bits - 1)) { return 'OPEN' }
    $fRange = $script:privateRanges | Where-Object { Test-PrefixContains $_ $f } | Select-Object -First 1
    if ($fRange -and (Test-PrefixContains $fRange $t)) { return 'PRIVATE' }   # both ends inside the same private range
    if ($count -le [System.Numerics.BigInteger]::Pow(2, $bits - $tight)) { return 'TIGHT' }
    return 'BROAD'
}
# Reads the global policy XML for ingress controls: ip-filter allowlists and the X-Azure-FDID check-header that
# makes the gateway accept only your own Front Door. Policies run at the gateway for API requests only; they do
# not protect the management endpoint (3443), the developer portal or Git.
function Get-PolicyIngressControls([string]$Xml, [int]$Tight4 = 24, [int]$Tight6 = 48) {
    $result = [pscustomobject]@{ parsed = $false; ipFilterAction = ''; ipFilterEntries = 0; ipFilterClass = ''; ipFilterConditional = $false; fdidCheck = $false; fdidConditional = $false; note = '' }
    if (-not "$Xml".Trim()) { $result.note = 'empty policy'; return $result }
    try { $doc = [xml]$Xml } catch { $result.note = "policy XML could not be parsed: $($_.Exception.Message)"; return $result }
    $result.parsed = $true
    $isConditional = { param($node) $p = $node.ParentNode; while ($p -and $p.NodeType -eq 'Element') { if ($p.Name -in 'when', 'otherwise') { return $true }; $p = $p.ParentNode }; return $false }
    $allowClasses = @(); $entries = 0; $actions = @(); $conditional = $false
    foreach ($f in @($doc.SelectNodes('//inbound//ip-filter'))) {
        $action = "$($f.GetAttribute('action'))".ToLower(); $actions += $action
        if (& $isConditional $f) { $conditional = $true }
        foreach ($a in @($f.SelectNodes('address'))) { $entries++; if ($action -eq 'allow') { $allowClasses += (Get-SourceClass "$($a.InnerText)" $Tight4 $Tight6).class } }
        foreach ($r in @($f.SelectNodes('address-range'))) { $entries++; if ($action -eq 'allow') { $allowClasses += Get-RangeClass "$($r.GetAttribute('from'))" "$($r.GetAttribute('to'))" $Tight4 $Tight6 } }
    }
    $result.ipFilterEntries = $entries; $result.ipFilterConditional = $conditional
    if ('allow' -in $actions) { $result.ipFilterAction = 'allow'; $result.ipFilterClass = Get-WorstClass $allowClasses }
    elseif ($actions.Count) { $result.ipFilterAction = 'forbid' }
    $checks = @($doc.SelectNodes('//inbound//check-header') | Where-Object { "$($_.GetAttribute('name'))" -ieq 'X-Azure-FDID' })
    $result.fdidCheck = $checks.Count -gt 0
    $result.fdidConditional = @($checks | Where-Object { & $isConditional $_ }).Count -eq $checks.Count -and $checks.Count -gt 0
    return $result
}
# A WAF in front of the gateway is bypassable when the gateway is also reachable directly from the internet and
# nothing makes it accept only traffic from the WAF: an unconditional X-Azure-FDID check, an ip-filter allowlist,
# or an NSG that admits only the WAF's own addresses. An NSG that admits AzureFrontDoor.Backend admits every tenant's
# Front Door, so it does not count.
function Test-WafBypass([string]$DirectGatewayClass, [bool]$FdidCheck, [string]$PolicyAllowClass) {
    if ($FdidCheck) { return $false }
    if ($PolicyAllowClass -and $PolicyAllowClass -notin 'OPEN', 'BROAD', 'AZURE-SHARED', 'UNKNOWN') { return $false }
    return $DirectGatewayClass -in 'OPEN', 'BROAD', 'AZURE-SHARED', 'UNKNOWN'
}
# One status per instance from its pathway rows (sourceClass, wafVerdict, bypassable):
#   OPEN      the management endpoint or a 443 endpoint is reachable from the whole internet with nothing in front
#             of it that blocks (a WAF in detection mode, a disabled WAF or a bypassable WAF do not count)
#   BROAD     the widest unmitigated pathway admits a wide range, a multi-tenant service tag or an unknown source
#   FILTERED  only tight ranges, or open pathways that all sit behind a WAF in prevention mode that cannot be bypassed
#   PRIVATE   nothing beyond the Azure control plane, the VNet or private ranges
function Get-IngressStatus($Pathways, [bool]$Unchecked) {
    if ($Unchecked) { return 'UNCHECKED' }
    $worst = 'NONE'; $mitigated = $false
    foreach ($p in @($Pathways)) {
        $c = "$($p.sourceClass)"
        if ("$($p.wafVerdict)" -eq 'PREVENTION' -and -not $p.bypassable) { if ($script:classSeverity[$c] -ge 2) { $mitigated = $true }; continue }
        if ($script:classSeverity[$c] -gt $script:classSeverity[$worst]) { $worst = $c }
    }
    switch ($worst) {
        'OPEN' { return 'OPEN' }
        { $_ -in 'BROAD', 'AZURE-SHARED', 'UNKNOWN' } { return 'BROAD' }
        'TIGHT' { return 'FILTERED' }
        default { if ($mitigated) { return 'FILTERED' }; return 'PRIVATE' }
    }
}

# =====================================================================================================
# Discovery: instances in scope, their networks and NSGs, the front ends that can forward to them
# =====================================================================================================
$base = 'https://management.azure.com'
$netApi = 'api-version=2024-05-01'; $cdnApi = 'api-version=2026-10-01'; $apimApi = 'api-version=2024-05-01'
# One tenant per run (Get-EnabledSubscription in Apim-Helpers.ps1): only that tenant's enabled subscriptions are read and
# the rest are listed and skipped. Pass -TenantId <id> after `az login --tenant <id>` to read another tenant.
$script:tenantId = Get-AzTenantId $TenantId
$subs = @(Get-EnabledSubscription -TenantId $script:tenantId)
Write-Host "Tenant $($script:tenantId): $($subs.Count) subscription(s). Reading APIM instances, networks, NSGs, gateways, Front Doors, Traffic Manager profiles and firewalls..."

$allApim = @(Invoke-Graph @"
resources
| where type =~ 'microsoft.apimanagement/service'
| project id, name, subscriptionId, resourceGroup, location, sku = tostring(sku.name),
    platformVersion = tostring(properties.platformVersion), vnetType = tostring(properties.virtualNetworkType),
    publicAccess = tostring(properties.publicNetworkAccess), privateEndpointConnections = properties.privateEndpointConnections,
    publicIPs = properties.publicIPAddresses, privateIPs = properties.privateIPAddresses,
    subnetId = tostring(properties.virtualNetworkConfiguration.subnetResourceId), publicIpId = tostring(properties.publicIpAddressId),
    hostnames = properties.hostnameConfigurations, additionalLocations = properties.additionalLocations,
    gatewayUrl = tostring(properties.gatewayUrl), developerPortalStatus = tostring(properties.developerPortalStatus),
    gatewayRegionalUrl = tostring(properties.gatewayRegionalUrl), disableGateway = tostring(properties.disableGateway)
"@ $subs)

# Scope: scope.csv from Check-ApimExposure.ps1 when present, validated and applied by Select-ApimInstance as in the audit
# and analysis scripts (an unrecognized SKU is always retained for review); otherwise the shared tier rule. -AllInstances
# takes everything.
$scopeFile = Join-Path $ExposureDir 'scope.csv'
$hasScopeFile = Test-Path -LiteralPath $scopeFile
$scopeRows = if ($hasScopeFile) { @(Import-Csv -LiteralPath $scopeFile) } else { @() }
$selected = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
if (-not $AllInstances) {
    foreach ($s in @(Select-ApimInstance $allApim $scopeFile -IncludeConsumption:$IncludeConsumption)) { [void]$selected.Add("$($s.id)".TrimEnd('/')) }
}
$scopeOf = @{}
foreach ($a in $allApim) {
    $key = "$($a.id)".TrimEnd('/')
    # Tier family and fallback reason from the shared rule. Select-ApimInstance has already warned about an unknown SKU.
    $dec = if ($AllInstances) { Get-ScopeDecision $a $null -IncludeConsumption:$IncludeConsumption }
           else { & { $WarningPreference = 'SilentlyContinue'; Get-ScopeDecision $a $null -IncludeConsumption:$IncludeConsumption } }
    $sc = if ($hasScopeFile) { $scopeRows | Where-Object { "$($_.id)".TrimEnd('/') -ieq $key } | Select-Object -First 1 } else { $null }
    $reason = if ($AllInstances) { 'all instances (-AllInstances)' }
              elseif ($sc -and $dec.tierFamily -ne 'Unknown') { "scope.csv$(if ($sc.reason) { ": $($sc.reason)" })" }
              else { $dec.reason }
    $scopeOf["$($a.id)".ToLower()] = [pscustomobject]@{ inScope = ($AllInstances -or $selected.Contains($key)); reason = $reason; tierFamily = $dec.tierFamily }
}
$apim = @($allApim | Where-Object { $scopeOf["$($_.id)".ToLower()].inScope })
Write-Host "APIM instances: $($allApim.Count) visible, $($apim.Count) analysed ($(if ($AllInstances) { 'all instances' } elseif ($hasScopeFile) { "scope from $scopeFile" } else { 'tier rule' }))"
if (-not $apim.Count) { Write-Warning 'No instances to analyse.'; return }

# Direct management API and Git flags from Check-ApimExposure.ps1, when its summary exists
$summaryFile = Join-Path $ExposureDir 'summary.csv'
$flagsOf = @{}
if (Test-Path $summaryFile) {
    foreach ($r in @(Import-Csv $summaryFile)) { $flagsOf["$($r.apim)|$($r.subscriptionId)".ToLower()] = $r }
    Write-Host "Direct management API / Git flags from $summaryFile"
}

# Subnets (with their NSG and prefixes), NSGs and public IP addresses
$subnets = @{}
foreach ($s in @(Invoke-Graph "resources | where type =~ 'microsoft.network/virtualnetworks' | mv-expand s = properties.subnets limit 2000 | project subnetId = tostring(s.id), nsgId = tostring(s.properties.networkSecurityGroup.id), prefix = tostring(s.properties.addressPrefix), prefixes = s.properties.addressPrefixes" $subs)) {
    $pf = @(); if ($s.prefix) { $pf += "$($s.prefix)" }; $pf += @($s.prefixes | ForEach-Object { "$_" } | Where-Object { $_ })
    $subnets["$($s.subnetId)".ToLower()] = [pscustomobject]@{ id = "$($s.subnetId)"; nsgId = "$($s.nsgId)"; prefixes = @($pf | Sort-Object -Unique) }
}
$nsgs = @{}
foreach ($n in @(Invoke-Graph "resources | where type =~ 'microsoft.network/networksecuritygroups' | project id, name, subscriptionId, rules = properties.securityRules, defaultRules = properties.defaultSecurityRules" $subs)) { $nsgs["$($n.id)".ToLower()] = $n }
$publicIps = @{}
foreach ($p in @(Invoke-Graph "resources | where type =~ 'microsoft.network/publicipaddresses' | project id, ip = tostring(properties.ipAddress)" $subs)) { $publicIps["$($p.id)".ToLower()] = "$($p.ip)" }
Write-Host "Subnets: $($subnets.Count), NSGs: $($nsgs.Count), public IPs: $($publicIps.Count)"

# Front ends that may forward to an APIM instance
$gateways = @(Invoke-Graph "resources | where type =~ 'microsoft.network/applicationgateways' | project id, name, subscriptionId, resourceGroup, location, properties" $subs)
$agwPolicies = @{}
foreach ($p in @(Invoke-Graph "resources | where type =~ 'microsoft.network/applicationgatewaywebapplicationfirewallpolicies' | project id, name, subscriptionId, properties" $subs)) { $agwPolicies["$($p.id)".ToLower()] = $p }
$fdPolicies = @{}
foreach ($p in @(Invoke-Graph "resources | where type =~ 'microsoft.network/frontdoorwebapplicationfirewallpolicies' | project id, name, subscriptionId, sku = tostring(sku.name), properties" $subs)) { $fdPolicies["$($p.id)".ToLower()] = $p }
$classicFds = @(Invoke-Graph "resources | where type =~ 'microsoft.network/frontdoors' | project id, name, subscriptionId, properties" $subs)
$afdProfiles = @(Invoke-Graph "resources | where type =~ 'microsoft.cdn/profiles' and tostring(sku.name) in~ ('Standard_AzureFrontDoor', 'Premium_AzureFrontDoor') | project id, name, subscriptionId, resourceGroup, sku = tostring(sku.name)" $subs)
$tmProfiles = @(Invoke-Graph "resources | where type =~ 'microsoft.network/trafficmanagerprofiles' | project id, name, subscriptionId, fqdn = tostring(properties.dnsConfig.fqdn), relativeName = tostring(properties.dnsConfig.relativeName), status = tostring(properties.profileStatus), endpoints = properties.endpoints" $subs)
$firewalls = @(Invoke-Graph "resources | where type =~ 'microsoft.network/azurefirewalls' | project id, name, subscriptionId, properties" $subs)
$fwPolicies = @(Invoke-Graph "resources | where type =~ 'microsoft.network/firewallpolicies' | project id, name, subscriptionId, basePolicyId = tostring(properties.basePolicy.id), firewalls = properties.firewalls" $subs)
$ipGroups = @{}
foreach ($g in @(Invoke-Graph "resources | where type =~ 'microsoft.network/ipgroups' | project id, addresses = properties.ipAddresses" $subs)) { $ipGroups["$($g.id)".ToLower()] = @($g.addresses | ForEach-Object { "$_" } | Where-Object { $_ }) }
$privateEndpoints = @(Invoke-Graph "resources | where type =~ 'microsoft.network/privateendpoints' | project id, name, subscriptionId, subnetId = tostring(properties.subnet.id), connections = properties.privateLinkServiceConnections, manualConnections = properties.manualPrivateLinkServiceConnections" $subs)
Write-Host "Application Gateways: $($gateways.Count) (WAF policies: $($agwPolicies.Count)); Front Door Standard/Premium profiles: $($afdProfiles.Count); classic Front Doors: $($classicFds.Count) (WAF policies: $($fdPolicies.Count)); Traffic Manager profiles: $($tmProfiles.Count); Azure Firewalls: $($firewalls.Count) (policies: $($fwPolicies.Count)); private endpoints: $($privateEndpoints.Count)"

# Front Door Standard/Premium child resources are not in Resource Graph: list them per profile.
$afd = @{}
foreach ($pr in $afdProfiles) {
    Write-Host "Front Door profile: $($pr.name)"
    $afd["$($pr.id)".ToLower()] = [pscustomobject]@{
        profile = $pr
        endpoints = @(Get-Paged "$base$($pr.id)/afdEndpoints?$cdnApi")
        originGroups = @(Get-Paged "$base$($pr.id)/originGroups?$cdnApi")
        customDomains = @(Get-Paged "$base$($pr.id)/customDomains?$cdnApi")
        securityPolicies = @(Get-Paged "$base$($pr.id)/securityPolicies?$cdnApi")
        origins = @(); routes = @()
    }
    $entry = $afd["$($pr.id)".ToLower()]
    foreach ($og in $entry.originGroups) { $entry.origins += @(Get-Paged "$base$($og.id)/origins?$cdnApi" | ForEach-Object { Add-Member -InputObject $_ -NotePropertyName originGroupId -NotePropertyValue $og.id -Force -PassThru }) }
    foreach ($ep in $entry.endpoints) { $entry.routes += @(Get-Paged "$base$($ep.id)/routes?$cdnApi" | ForEach-Object { Add-Member -InputObject $_ -NotePropertyName endpointId -NotePropertyValue $ep.id -Force -PassThru }) }
}
# Azure Firewall policy rule collection groups (child resources): NAT rules with their collection's action
$fwPolicyNat = @{}   # policyId (lower) -> NAT rules
foreach ($pol in $fwPolicies) {
    $rules = @()
    foreach ($g in @(Get-Paged "$base$($pol.id)/ruleCollectionGroups?$netApi")) {
        foreach ($c in @($g.properties.ruleCollections | Where-Object { "$($_.ruleCollectionType)" -ieq 'FirewallPolicyNatRuleCollection' -and "$($_.action.type)" -ieq 'DNAT' })) {
            foreach ($r in @($c.rules | Where-Object { $_ })) { $rules += [pscustomobject]@{ collection = "$($g.name)/$($c.name)"; rule = $r } }
        }
    }
    $fwPolicyNat["$($pol.id)".ToLower()] = $rules
}
# Expand IP group references in firewall rule sources
function Expand-FirewallSources($Rule) {
    $src = @($Rule.sourceAddresses | ForEach-Object { "$_" } | Where-Object { $_ })
    foreach ($g in @($Rule.sourceIpGroups | ForEach-Object { "$_" } | Where-Object { $_ })) {
        $k = $g.ToLower()
        if ($ipGroups.ContainsKey($k)) { $src += $ipGroups[$k] } else { $src += "ipgroup:$(Get-ResourceName $g)" }
    }
    @($src | Sort-Object -Unique)
}

# Patch level of the gateway runtime, per the Norwegian NSM advisory of 20 Nov 2026 (NSM deler tiltak mot sårbarhet i
# Azure API Management): https://<gateway>/internal-status-0123456789abcdef reports RuntimeVersion; 0.52.x is patched
# from build 31936, 0.53.x from 31938. NSM gives builds such as 0.52.4150.0 and 0.53.4608.0 as "other patterns" of the
# v2 / Consumption tiers, which were not vulnerable. So the verdict depends on the tier, not on the version alone:
#   v2 / Consumption          not applicable (no probe needed)
#   Classic, 5-digit build    patched / NOT PATCHED against the threshold
#   Classic, short build      UNRECOGNISED: NSM's v2/Consumption pattern on a Classic SKU; verify with Microsoft
#   anything but 0.52 / 0.53  UNRECOGNISED: outside NSM's thresholds; verify with Microsoft
# Microsoft has not documented this endpoint, so an unreadable answer is 'unknown', never 'patched'.
function Get-GatewayPatchStatus([string]$Version, [string]$TierFamily = 'Classic') {
    if ($TierFamily -in 'v2', 'Classic (Consumption)') { return "not applicable ($TierFamily tier: not vulnerable per NSM)" }
    $v = "$Version".Trim()
    if (-not $v) { return 'unknown (no RuntimeVersion)' }
    if ($v -notmatch '^0\.(52|53)\.(\d+)(\.|$)') { return "UNRECOGNISED ($v): outside NSM's 0.52 / 0.53 thresholds; verify with Microsoft" }
    $minor = $Matches[1]; $build = [long]$Matches[2]
    $need = if ($minor -eq '52') { 31936 } else { 31938 }
    if ($build -ge $need) { return "patched ($v)" }
    if ($build -lt 10000) { return "UNRECOGNISED ($v): NSM lists this build pattern for v2 / Consumption, but the tier is $TierFamily; verify with Microsoft" }
    return "NOT PATCHED ($v; needs 0.$minor.$need or later)"
}
function Get-UrlHost([string]$Url) {
    $u = $null
    if ($Url -and [uri]::TryCreate($Url.Trim(), [UriKind]::Absolute, [ref]$u)) { return $u.Host }
    return ''
}
# Gateways to probe for the runtime build. The default hostname is routed to the nearest region, so in a multi-region
# deployment every region's own gateway (gatewayRegionalUrl) is probed as well: regions can run different builds.
# A region whose gateway is disabled is listed but not probed.
function Get-GatewayProbeTargets($Apim) {
    $rows = @([pscustomobject]@{ region = "$($Apim.location) (default hostname)"; host = "$($Apim.name).azure-api.net"; disabled = $false })
    $extra = @(Expand-Json $Apim.additionalLocations | Where-Object { $_ })
    if ($extra.Count) {
        $rows += [pscustomobject]@{ region = "$($Apim.location)"; host = (Get-UrlHost "$($Apim.gatewayRegionalUrl)"); disabled = ("$($Apim.disableGateway)" -ieq 'true') }
        foreach ($l in $extra) {
            $rows += [pscustomobject]@{ region = "$($l.location)"; host = (Get-UrlHost "$($l.gatewayRegionalUrl)"); disabled = ("$($l.disableGateway)" -ieq 'true') }
        }
    }
    $rows
}
# One verdict per instance from its per-gateway statuses: the worst one wins, and 'patched' needs every probed gateway.
function Get-PatchSummary([string[]]$Statuses) {
    $all = @($Statuses | Where-Object { $_ })
    $s = @($all | Where-Object { $_ -notlike 'not probed*' -and $_ -notlike 'not applicable*' })
    if (-not $s.Count) { return $(if ($all.Count) { $all[0] } else { '' }) }
    foreach ($p in 'NOT PATCHED', 'UNRECOGNISED', 'unknown') {
        $hit = @($s | Where-Object { $_ -clike "$p*" })
        if ($hit.Count) { return "$p in $($hit.Count) of $($s.Count) gateway(s): $($hit[0])" }
    }
    return "patched (all $($s.Count) gateway(s))"
}

# ---- Change history: was the configuration different during the exposure window? ----
# Does an Activity Log event change how the instance can be reached? Only successful writes and deletes count.
# $Watched: the instance's subnets and NSGs and the front ends and WAF policies that reach it; the resource and all its
# children count (an NSG rule is a child of the NSG). For the instance itself only the service, its private endpoint
# connections, the global policy (ip-filter / X-Azure-FDID) and the tenant access settings (direct management API, Git)
# count: API, product and other content deployments do not change ingress.
# APIM's own change records (operation names in capitals, no caller) carry the service itself as resourceId, also for
# a change to an API, a subscription or a named value. So for the instance the operation decides, not the resourceId.
function Test-IngressChange($Entry, [string]$ApimId, [string[]]$Watched) {
    if ("$($Entry.status.value)" -ine 'Succeeded') { return $false }
    $op = "$($Entry.operationName.value)".Trim().ToLowerInvariant()
    if ($op -notmatch '/(write|delete)$' -and $op -notmatch '/applynetworkconfigurationupdates/action$') { return $false }
    $rid = "$($Entry.resourceId)".Trim().TrimEnd('/').ToLowerInvariant()
    if (-not $rid) { return $false }
    $a = "$ApimId".Trim().TrimEnd('/').ToLowerInvariant()
    if ($a -and ($rid -eq $a -or $rid.StartsWith("$a/"))) {
        return ($op -match '^microsoft\.apimanagement/service/(write|delete|applynetworkconfigurationupdates/action|policies/(write|delete))$' -or
                $op -match '^microsoft\.apimanagement/service/(privateendpointconnections|tenant)/')
    }
    foreach ($w in @($Watched | Where-Object { $_ })) {
        $wl = "$w".Trim().TrimEnd('/').ToLowerInvariant()
        if ($rid -eq $wl -or $rid.StartsWith("$wl/")) { return $true }
    }
    return $false
}
# One change can appear twice: Azure Resource Manager's record (mixed case, with a caller) and APIM's own (capitals,
# no caller, the service as resourceId), sharing a correlationId. Keep one per correlationId and operation, preferring
# the record that names a caller and the more specific resourceId. Events without a correlationId are all kept.
function Select-UniqueChange($Entries) {
    $byKey = [ordered]@{}; $rest = @()
    foreach ($e in @($Entries)) {
        $cid = "$($e.correlationId)".Trim()
        if (-not $cid) { $rest += $e; continue }
        $k = "$($cid.ToLowerInvariant())|$("$($e.operationName.value)".Trim().ToLowerInvariant())"
        $cur = $byKey[$k]
        if (-not $cur) { $byKey[$k] = $e; continue }
        $better = (-not "$($cur.caller)".Trim() -and "$($e.caller)".Trim()) -or
                  ("$($cur.caller)".Trim() -eq "$($e.caller)".Trim() -and "$($e.resourceId)".Length -gt "$($cur.resourceId)".Length)
        if ($better) { $byKey[$k] = $e }
    }
    @($byKey.Values) + $rest
}
# Activity Log query for one resource group (the API filters by resource group, not by a resource and its children)
function Get-ActivityLogUrl([string]$SubscriptionId, [string]$ResourceGroup, [datetime]$From, [datetime]$To) {
    $fmt = "yyyy-MM-dd'T'HH:mm:ss'Z'"; $inv = [cultureinfo]::InvariantCulture
    $filter = "eventTimestamp ge '$($From.ToString($fmt, $inv))' and eventTimestamp le '$($To.ToString($fmt, $inv))' and resourceGroupName eq '$ResourceGroup'"
    "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Insights/eventtypes/management/values?api-version=2015-04-01" +
        "&`$filter=$([uri]::EscapeDataString($filter))&`$select=$([uri]::EscapeDataString('eventTimestamp,operationName,resourceId,status,caller,correlationId'))"
}
# Activity Log timestamps as sortable UTC text (ConvertFrom-Json may already have turned them into DateTime values)
function Format-EventTime($Value) {
    if ($Value -is [datetime]) { return (ConvertTo-UtcDate $Value).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [cultureinfo]::InvariantCulture) }
    if ($Value -is [DateTimeOffset]) { return $Value.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [cultureinfo]::InvariantCulture) }
    return "$Value"
}
function Get-ResourceGroupKey([string]$Id) {
    if ("$Id" -match '^/subscriptions/([^/]+)/resourceGroups/([^/]+)') { return "$($Matches[1])|$($Matches[2])".ToLowerInvariant() }
    return ''
}
$changesFrom = ConvertTo-UtcDate $ChangesSince
$changesTo = [datetime]::UtcNow
if (-not $SkipChangeHistory) {
    if ($changesFrom -ge $changesTo) { throw 'ChangesSince must be in the past.' }
    if ($changesFrom -lt $changesTo.AddDays(-89)) {
        Write-Warning "The Activity Log keeps 90 days; reading changes from $($changesTo.AddDays(-89).ToString('yyyy-MM-dd')) instead of $($changesFrom.ToString('yyyy-MM-dd'))."
        $changesFrom = $changesTo.AddDays(-89)
    }
}
$activityCache = @{}   # 'sub|rg' -> @{ ok; events }
function Get-ResourceGroupEvents([string]$Key) {
    if (-not $activityCache.ContainsKey($Key)) {
        $sub, $rg = $Key -split '\|', 2
        $before = $script:failures.Count
        $events = @(Get-Paged (Get-ActivityLogUrl $sub $rg $changesFrom $changesTo))
        $activityCache[$Key] = [pscustomobject]@{ ok = ($script:failures.Count -eq $before); events = $events }
    }
    $activityCache[$Key]
}

# =====================================================================================================
# Analysis per instance
# =====================================================================================================
$nsgRows = @(); $pathways = @(); $policyRows = @(); $summary = @(); $patchRows = @(); $changeRows = @()
$wafCache = @{}; $wafUse = @{}
function New-UnknownWaf([string]$PolicyId, [string]$Kind) {
    [pscustomobject]@{ policyId = $PolicyId; policy = (Get-ResourceName $PolicyId); kind = $Kind; state = 'unknown'; mode = ''; verdict = 'UNKNOWN (policy not visible)'
        requestBodyCheck = ''; managedRuleSets = ''; disabledRules = ''; disabledRuleGroups = ''; weakenedRules = ''; exclusions = ''; customRules = ''; permissiveAllows = ''
        allowlist = $false; allowlistClass = ''; notes = 'the WAF policy resource is not readable with this account'; customRuleRows = @() }
}
function Get-WafFor([string]$PolicyId, [string]$Kind, [string]$UsedBy) {
    if (-not $PolicyId) { return $null }
    $k = $PolicyId.ToLower()
    if (-not $wafCache.ContainsKey($k)) {
        $pol = if ($Kind -eq 'FrontDoor') { $fdPolicies[$k] } else { $agwPolicies[$k] }
        $wafCache[$k] = if ($pol) { Get-WafAssessment $pol $Kind $TightPrefixLength $TightPrefixLengthV6 } else { New-UnknownWaf $PolicyId $Kind }
        $wafUse[$k] = [System.Collections.Generic.HashSet[string]]::new()
    }
    if ($UsedBy) { [void]$wafUse[$k].Add($UsedBy) }
    return $wafCache[$k]
}
# The inline WAF configuration of a gateway has no policy resource; keep it in the same table under the gateway's ID.
function Register-LegacyWaf($Gateway, $Assessment, [string]$UsedBy) {
    if (-not $Assessment) { return $null }
    $k = "$($Gateway.id)|inline".ToLower()
    if (-not $wafCache.ContainsKey($k)) { $wafCache[$k] = $Assessment; $wafUse[$k] = [System.Collections.Generic.HashSet[string]]::new() }
    if ($UsedBy) { [void]$wafUse[$k].Add($UsedBy) }
    return $wafCache[$k]
}
function New-Pathway($Apim, [string]$Pathway, [string]$Via, [string]$ViaId, [string]$Endpoint, [string]$Frontend, [string]$Port, [string]$Source, [string]$SourceClass, $Waf, [string]$WafVerdict, [bool]$Bypassable, [string]$Detail) {
    [pscustomobject]@{
        apim = $Apim.name; subscriptionId = $Apim.subscriptionId; pathway = $Pathway; via = $Via; endpoint = $Endpoint; frontend = $Frontend; port = $Port
        source = $Source; sourceClass = $SourceClass; severity = $script:classSeverity[$SourceClass]
        wafVerdict = $WafVerdict; wafPolicy = $(if ($Waf) { $Waf.policy } else { '' }); wafNotes = $(if ($Waf) { $Waf.notes } else { '' })
        bypassable = $Bypassable; detail = $Detail; viaId = $ViaId
    }
}
$fwPolicyById = @{}; foreach ($pol in $fwPolicies) { $fwPolicyById["$($pol.id)".ToLower()] = $pol }

foreach ($a in $apim) {
    Write-Host "Analysing $($a.name) [$($a.sku), $(if ($a.vnetType) { $a.vnetType } else { 'None' })]"
    $sc = $scopeOf["$($a.id)".ToLower()]
    $hosts = @(Get-ApimHosts $a); $ips = @(Get-ApimIps $a)
    $peCount = @(Expand-Json $a.privateEndpointConnections | Where-Object { $_ }).Count
    $flags = $flagsOf["$($a.name)|$($a.subscriptionId)".ToLower()]
    $injected = "$($a.vnetType)" -in 'External', 'Internal'

    # ---- APIM subnet NSGs, one per location ----
    $locations = @([pscustomobject]@{ location = "$($a.location)"; subnetId = "$($a.subnetId)" })
    foreach ($loc in @(Expand-Json $a.additionalLocations | Where-Object { $_ })) { $locations += [pscustomobject]@{ location = "$($loc.location)"; subnetId = "$($loc.virtualNetworkConfiguration.subnetResourceId)" } }
    $nsgNames = @(); $missingNsg = 0; $evaluated = 0; $notVisible = @(); $mine = @()
    if ($injected) {
        foreach ($loc in $locations) {
            if (-not $loc.subnetId) { $nsgNames += "$($loc.location): no subnet recorded"; $notVisible += $loc.location; continue }
            $sn = $subnets["$($loc.subnetId)".ToLower()]
            if (-not $sn) { $nsgNames += "$($loc.location): subnet not visible"; $notVisible += $loc.location; continue }
            if (-not $sn.nsgId) { $nsgNames += "$($loc.location): NO NSG"; $missingNsg++; continue }
            $nsg = $nsgs["$($sn.nsgId)".ToLower()]
            if (-not $nsg) { $nsgNames += "$($loc.location): NSG not visible"; $notVisible += $loc.location; continue }
            $nsgNames += "$($loc.location): $($nsg.name)"
            $evaluated++
            $rules = @(Get-NsgRules $nsg)
            foreach ($port in 80, 443, 3443, 6390) {
                foreach ($row in @(Get-NsgPortExposure $rules $port $TightPrefixLength $TightPrefixLengthV6 $sn.prefixes)) {
                    $mine += [pscustomobject]@{
                        apim = $a.name; subscriptionId = $a.subscriptionId; location = $loc.location; vnetType = $a.vnetType; nsg = $row.nsg; port = $port
                        rule = $row.rule; priority = $row.priority; isDefault = $row.isDefault; protocol = $row.protocol; ports = $row.ports; source = $row.source
                        sourceClass = $row.sourceClass; addresses = $row.addresses; effective = $row.effective; shadowedBy = $row.shadowedBy; partiallyDeniedBy = $row.partiallyDeniedBy
                        assessment = $(if ($row.effective) { Get-ApimRuleAssessment $port $row.sourceClass $row.source $a.vnetType } else { "shadowed by $($row.shadowedBy)" })
                        nsgId = $row.nsgId
                    }
                }
            }
            # Other ports that an open or broad allow rule admits (not APIM listeners; deny shadowing not evaluated here)
            foreach ($r in @($rules | Where-Object { $_.direction -ieq 'Inbound' -and $_.access -ieq 'Allow' -and -not $_.isDefault -and (Test-TcpProtocol $_.protocol) -and (Test-DestinationHit $_ $sn.prefixes) })) {
                if ((Test-PortHit $r.ports 80) -or (Test-PortHit $r.ports 443) -or (Test-PortHit $r.ports 3443) -or (Test-PortHit $r.ports 6390)) { continue }
                foreach ($s in @($r.sources)) {
                    $cls = Get-SourceClass $s $TightPrefixLength $TightPrefixLengthV6
                    if ($cls.class -notin 'OPEN', 'BROAD') { continue }
                    $mine += [pscustomobject]@{
                        apim = $a.name; subscriptionId = $a.subscriptionId; location = $loc.location; vnetType = $a.vnetType; nsg = $r.nsg; port = 'other'
                        rule = $r.name; priority = $r.priority; isDefault = $false; protocol = $r.protocol; ports = $r.portText; source = $s
                        sourceClass = $cls.class; addresses = "$($cls.addresses)"; effective = $true; shadowedBy = ''; partiallyDeniedBy = ''
                        assessment = "other port(s) $($r.portText) allowed from a $($cls.class) source: not an APIM listener, but review (deny rules not evaluated for this row)"
                        nsgId = $r.nsgId
                    }
                }
            }
        }
    }
    $nsgRows += $mine
    $class443 = Get-WorstClass @($mine | Where-Object { $_.port -eq 443 -and $_.effective } | ForEach-Object { $_.sourceClass })
    $class3443 = Get-WorstClass @($mine | Where-Object { $_.port -eq 3443 -and $_.effective } | ForEach-Object { $_.sourceClass })
    # A location without an NSG is open; a location that could not be read is reported but does not hide what the others show
    $hasNsg = $injected -and $evaluated -gt 0 -and $missingNsg -eq 0
    $unchecked = $injected -and $evaluated -eq 0 -and $missingNsg -eq 0
    $reach = Get-ApimReach "$($a.vnetType)" "$($a.publicAccess)" $peCount $class443 $class3443 $hasNsg
    if ($unchecked) { $reach.management = 'UNKNOWN (subnet or NSG not visible)'; if ($a.vnetType -ieq 'External') { $reach.gateway = 'UNKNOWN (subnet or NSG not visible)' } }
    elseif ($notVisible.Count) { $reach.management += " (not checked: $($notVisible -join ', '))"; if ($a.vnetType -ieq 'External') { $reach.gateway += " (not checked: $($notVisible -join ', '))" } }
    # Consumption and v2 tiers have no dedicated service configuration endpoint on 3443. An unrecognized SKU is
    # analysed as if it had one (it is retained for review; the scope reason says so).
    $dedicatedMgmt = $sc.tierFamily -in 'Classic', 'Unknown'
    if (-not $dedicatedMgmt) { $reach.management = "n/a ($($sc.tierFamily): no dedicated management endpoint on 3443)" }

    # ---- Global policy: ip-filter allowlists and the X-Azure-FDID check ----
    $pol = $null
    if (-not $SkipPolicy) {
        # format=xml: policy expressions come back XML-escaped, so the document parses. rawxml leaves them as written
        # (for example @(a < b && c)), which is not valid XML.
        $pres = Get-One "$base$($a.id)/policies/policy?format=xml&$apimApi"
        if ($pres) {
            if ("$($pres.properties.format)" -like '*link*') { $pol = Get-PolicyIngressControls ''; $pol.note = "global policy is a link ($($pres.properties.format)); not read" }
            else { $pol = Get-PolicyIngressControls "$($pres.properties.value)" $TightPrefixLength $TightPrefixLengthV6 }
        } else { $pol = Get-PolicyIngressControls ''; $pol.note = 'global policy could not be read (see failed-calls.csv)' }
        $policyRows += [pscustomobject]@{ apim = $a.name; subscriptionId = $a.subscriptionId; parsed = $pol.parsed; ipFilterAction = $pol.ipFilterAction; ipFilterEntries = $pol.ipFilterEntries
                                          ipFilterClass = $pol.ipFilterClass; ipFilterConditional = $pol.ipFilterConditional; fdidCheck = $pol.fdidCheck; fdidConditional = $pol.fdidConditional; note = $pol.note }
    }
    $policyAllow = if ($pol -and $pol.ipFilterAction -eq 'allow' -and -not $pol.ipFilterConditional -and $pol.ipFilterClass) { $pol.ipFilterClass } else { '' }
    $fdid = [bool]($pol -and $pol.fdidCheck -and -not $pol.fdidConditional)

    # ---- Direct pathways: the instance's own public VIP ----
    $gwClass = Get-ReachClass $reach.gateway; $mgClass = if ($dedicatedMgmt) { Get-ReachClass $reach.management } else { 'NONE' }
    $policyKnown = [bool]($pol -and $pol.parsed)
    $bypassText = if ($policyKnown) { '; WAF BYPASSABLE: the instance is also reachable directly and does not check X-Azure-FDID or filter source addresses' }
                  else { '; WAF BYPASSABLE: the instance is also reachable directly; its global policy was not read, so an X-Azure-FDID check or ip-filter could not be confirmed' }
    $gwEffective = if ($policyAllow -and $script:classSeverity[$policyAllow] -lt $script:classSeverity[$gwClass]) { $policyAllow } else { $gwClass }
    $mgDetail = "$($reach.basis)" + $(if ($flags) { "; direct management API enabled: $($flags.directMgmtApi), Git access: $($flags.gitAccess)" })
    $pathways += New-Pathway $a 'direct (public VIP)' $a.name $a.id 'management endpoint (3443)' $(if ($a.publicIPs) { (@(Expand-Json $a.publicIPs) -join ' ') } else { '' }) '3443' $reach.management $mgClass $null 'n/a' $false $mgDetail
    $gwDetail = "$($reach.basis)" + $(if ($policyAllow) { "; API requests limited by an ip-filter policy to $policyAllow ranges (developer portal, Git and management hostnames are not covered by policies)" }) + $(if ($fdid) { '; X-Azure-FDID check-header in the global policy' })
    $pathways += New-Pathway $a 'direct (public VIP)' $a.name $a.id 'gateway, developer portal, Git and management hostnames (443)' (($hosts | Where-Object { $_.type -eq 'Proxy' } | ForEach-Object { $_.host }) -join ' ') '443' $reach.gateway $gwClass $null 'n/a' $false $gwDetail

    # ---- Application Gateways whose backend pools point at this instance ----
    foreach ($gw in $gateways) {
        $gp = $gw.properties
        $matchedPools = @{}
        foreach ($pool in @($gp.backendAddressPools | Where-Object { $_ })) {
            foreach ($addr in @($pool.properties.backendAddresses | Where-Object { $_ })) {
                $ep = Resolve-ApimTarget "$($addr.fqdn)" $hosts $ips
                if (-not $ep) { $ep = Resolve-ApimTarget "$($addr.ipAddress)" $hosts $ips }
                if ($ep) { $matchedPools["$($pool.id)".ToLower()] = $ep }
            }
        }
        if (-not $matchedPools.Count) { continue }
        $tier = "$($gp.sku.tier)"; $wafTier = $tier -match 'WAF'
        $legacy = Get-LegacyWafAssessment $gw
        $frontends = @{}
        foreach ($f in @($gp.frontendIPConfigurations | Where-Object { $_ })) {
            $pip = "$($f.properties.publicIPAddress.id)"
            $frontends["$($f.id)".ToLower()] = [pscustomobject]@{ public = [bool]$pip; address = $(if ($pip) { $publicIps["$pip".ToLower()] } else { "$($f.properties.privateIPAddress)" }) }
        }
        $ports = @{}; foreach ($fp in @($gp.frontendPorts | Where-Object { $_ })) { $ports["$($fp.id)".ToLower()] = [int]$fp.properties.port }
        $listeners = @{}; foreach ($l in @($gp.httpListeners | Where-Object { $_ })) { $listeners["$($l.id)".ToLower()] = $l }
        $maps = @{}; foreach ($m in @($gp.urlPathMaps | Where-Object { $_ })) { $maps["$($m.id)".ToLower()] = $m }
        $agwSubnetId = "$(@($gp.gatewayIPConfigurations)[0].properties.subnet.id)"
        $agwSn = if ($agwSubnetId) { $subnets[$agwSubnetId.ToLower()] } else { $null }
        $agwNsg = if ($agwSn -and $agwSn.nsgId) { $nsgs[$agwSn.nsgId.ToLower()] } else { $null }
        $agwRules = if ($agwNsg) { @(Get-NsgRules $agwNsg) } else { @() }
        foreach ($rr in @($gp.requestRoutingRules | Where-Object { $_ })) {
            $rp = $rr.properties
            $hits = @()
            if ($rp.backendAddressPool.id) { $hits += [pscustomobject]@{ poolId = "$($rp.backendAddressPool.id)"; pathPolicyId = ''; paths = '' } }
            if ($rp.urlPathMap.id) {
                $m = $maps["$($rp.urlPathMap.id)".ToLower()]
                if ($m) {
                    if ($m.properties.defaultBackendAddressPool.id) { $hits += [pscustomobject]@{ poolId = "$($m.properties.defaultBackendAddressPool.id)"; pathPolicyId = ''; paths = '(default path)' } }
                    foreach ($prl in @($m.properties.pathRules | Where-Object { $_ })) {
                        if ($prl.properties.backendAddressPool.id) { $hits += [pscustomobject]@{ poolId = "$($prl.properties.backendAddressPool.id)"; pathPolicyId = "$($prl.properties.firewallPolicy.id)"; paths = (@($prl.properties.paths) -join ' ') } }
                    }
                }
            }
            foreach ($h in @($hits | Where-Object { $matchedPools.ContainsKey("$($_.poolId)".ToLower()) })) {
                $l = $listeners["$($rp.httpListener.id)".ToLower()]
                if (-not $l) { continue }
                $lp = $l.properties
                $fe = $frontends["$($lp.frontendIPConfiguration.id)".ToLower()]
                $port = $ports["$($lp.frontendPort.id)".ToLower()]
                $hostText = (@(@($lp.hostName) + @($lp.hostNames)) | Where-Object { $_ }) -join ' '
                # The most specific WAF policy wins: path rule, then listener, then gateway, then the inline configuration
                $policyId = if ($h.pathPolicyId) { $h.pathPolicyId } elseif ($lp.firewallPolicy.id) { "$($lp.firewallPolicy.id)" } else { "$($gp.firewallPolicy.id)" }
                $waf = if (-not $wafTier) { $null } elseif ($policyId) { Get-WafFor $policyId 'AppGateway' $a.name } else { Register-LegacyWaf $gw $legacy $a.name }
                $wafVerdict = if (-not $wafTier) { "NO WAF ($tier tier)" } elseif ($waf) { $waf.verdict } else { 'NO WAF (no policy on a WAF tier)' }
                if ($fe -and $fe.public) {
                    $cls = if ($agwRules.Count) { Get-PortExposureClass (Get-NsgPortExposure $agwRules $port $TightPrefixLength $TightPrefixLengthV6 $agwSn.prefixes) } else { 'OPEN' }
                    if ($cls -eq 'NONE') { $cls = 'PRIVATE' }
                    $src = if ($agwRules.Count) { "internet, filtered by NSG $($agwNsg.name) on the gateway subnet" } else { 'internet (no NSG on the gateway subnet)' }
                } else { $cls = 'VNET'; $src = 'private frontend (VNet only)' }
                $bypass = if ($waf -and $wafVerdict -eq 'PREVENTION' -and $fe -and $fe.public) { Test-WafBypass $gwEffective $fdid $policyAllow } else { $false }
                $frontendText = "$(if ($fe) { $fe.address }):$port$(if ($hostText) { " ($hostText)" })"
                $detail = "listener $($l.name) -> rule $($rr.name)$(if ($h.paths) { " paths $($h.paths)" }) -> pool $(Get-ResourceName $h.poolId) ($($matchedPools["$($h.poolId)".ToLower()]))$(if ($bypass) { $bypassText })"
                $pathways += New-Pathway $a 'Application Gateway' $gw.name $gw.id $matchedPools["$($h.poolId)".ToLower()] $frontendText "$port" $src $cls $waf $wafVerdict $bypass $detail
            }
        }
    }

    # ---- Front Door Standard/Premium: origins that point at this instance, through their routes and domains ----
    foreach ($entry in $afd.Values) {
        $matchedOg = @{}
        foreach ($o in @($entry.origins)) {
            $op = $o.properties
            if ("$($op.enabledState)" -eq 'Disabled') { continue }
            $pl = "$($op.sharedPrivateLinkResource.privateLink.id)"
            $ep = Resolve-ApimTarget "$($op.hostName)" $hosts $ips
            if (-not $ep -and $pl -and ($pl -ieq "$($a.id)")) { $ep = 'gateway (Private Link origin)' }
            if ($ep) { $matchedOg["$($o.originGroupId)".ToLower()] = [pscustomobject]@{ endpoint = $ep; origin = "$($o.name)"; privateLink = [bool]($pl -and ($pl -ieq "$($a.id)")) } }
        }
        if (-not $matchedOg.Count) { continue }
        $domainHost = @{}
        foreach ($d in @($entry.customDomains)) { $domainHost["$($d.id)".ToLower()] = "$($d.properties.hostName)" }
        $disabledEndpoints = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($ep in @($entry.endpoints)) { $domainHost["$($ep.id)".ToLower()] = "$($ep.properties.hostName)"; if ("$($ep.properties.enabledState)" -eq 'Disabled') { [void]$disabledEndpoints.Add("$($ep.id)".ToLower()) } }
        $wafByDomain = @{}
        foreach ($sp in @($entry.securityPolicies)) {
            $prm = $sp.properties.parameters
            if ("$($prm.type)" -ine 'WebApplicationFirewall') { continue }
            foreach ($as in @($prm.associations | Where-Object { $_ })) { foreach ($d in @($as.domains | Where-Object { $_ })) { $wafByDomain["$($d.id)".ToLower()] = "$($prm.wafPolicy.id)" } }
        }
        foreach ($rt in @($entry.routes | Where-Object { $matchedOg.ContainsKey("$($_.properties.originGroup.id)".ToLower()) })) {
            $rp = $rt.properties
            if ("$($rp.enabledState)" -eq 'Disabled' -or $disabledEndpoints.Contains("$($rt.endpointId)".ToLower())) { continue }
            $og = $matchedOg["$($rp.originGroup.id)".ToLower()]
            $domainIds = @()
            if ("$($rp.linkToDefaultDomain)" -ne 'Disabled') { $domainIds += "$($rt.endpointId)" }
            $domainIds += @($rp.customDomains | Where-Object { $_ } | ForEach-Object { "$($_.id)" })
            foreach ($did in $domainIds) {
                $policyId = $wafByDomain["$did".ToLower()]
                $waf = if ($policyId) { Get-WafFor $policyId 'FrontDoor' $a.name } else { $null }
                $wafVerdict = if ($waf) { $waf.verdict } else { 'NO WAF' }
                $bypass = if ($waf -and $wafVerdict -eq 'PREVENTION') { Test-WafBypass $gwEffective $fdid $policyAllow } else { $false }
                $hostName = if ($domainHost.ContainsKey("$did".ToLower())) { $domainHost["$did".ToLower()] } else { Get-ResourceName $did }
                $detail = "route $($rt.name) patterns $(@($rp.patternsToMatch) -join ' ') -> origin $($og.origin)$(if ($og.privateLink) { ' over Private Link' })$(if ($bypass) { $bypassText })"
                $pathways += New-Pathway $a 'Front Door' $entry.profile.name $entry.profile.id $og.endpoint $hostName '443/80' 'internet (Front Door anycast edge)' 'OPEN' $waf $wafVerdict $bypass $detail
            }
        }
    }

    # ---- Classic Front Door ----
    foreach ($fd in $classicFds) {
        $fp = $fd.properties
        $matchedPools = @{}
        foreach ($bp in @($fp.backendPools | Where-Object { $_ })) {
            # Classic Front Door backends are plain objects: address and enabledState sit directly on the item
            foreach ($b in @($bp.properties.backends | Where-Object { $_ })) {
                if ("$($b.enabledState)" -eq 'Disabled') { continue }
                $ep = Resolve-ApimTarget "$($b.address)" $hosts $ips
                if ($ep) { $matchedPools["$($bp.id)".ToLower()] = $ep }
            }
        }
        if (-not $matchedPools.Count) { continue }
        $feWaf = @{}; $feHost = @{}
        foreach ($fe in @($fp.frontendEndpoints | Where-Object { $_ })) { $feWaf["$($fe.id)".ToLower()] = "$($fe.properties.webApplicationFirewallPolicyLink.id)"; $feHost["$($fe.id)".ToLower()] = "$($fe.properties.hostName)" }
        foreach ($rr in @($fp.routingRules | Where-Object { $_ })) {
            $rp = $rr.properties
            if ("$($rp.enabledState)" -eq 'Disabled') { continue }
            $poolId = "$($rp.routeConfiguration.backendPool.id)"
            if (-not $poolId -or -not $matchedPools.ContainsKey($poolId.ToLower())) { continue }
            foreach ($fe in @($rp.frontendEndpoints | Where-Object { $_ })) {
                $k = "$($fe.id)".ToLower()
                $policyId = $feWaf[$k]
                $waf = if ($policyId) { Get-WafFor $policyId 'FrontDoor' $a.name } else { $null }
                $wafVerdict = if ($waf) { $waf.verdict } else { 'NO WAF' }
                $bypass = if ($waf -and $wafVerdict -eq 'PREVENTION') { Test-WafBypass $gwEffective $fdid $policyAllow } else { $false }
                $detail = "routing rule $($rr.name) patterns $(@($rp.patternsToMatch) -join ' ') -> pool $(Get-ResourceName $poolId)$(if ($bypass) { $bypassText })"
                $pathways += New-Pathway $a 'Front Door (classic)' $fd.name $fd.id $matchedPools[$poolId.ToLower()] $feHost[$k] '443/80' 'internet (Front Door anycast edge)' 'OPEN' $waf $wafVerdict $bypass $detail
            }
        }
    }

    # ---- Traffic Manager: DNS only, so the exposure is the target's own ----
    foreach ($tm in $tmProfiles) {
        if ("$($tm.status)" -eq 'Disabled') { continue }
        foreach ($e in @(Expand-Json $tm.endpoints | Where-Object { $_ })) {
            $ep = $e.properties
            if ("$($ep.endpointStatus)" -eq 'Disabled') { continue }
            $hit = Resolve-ApimTarget "$($ep.target)" $hosts $ips
            if (-not $hit -and "$($ep.targetResourceId)" -ieq "$($a.id)") { $hit = 'gateway (Azure endpoint)' }
            if (-not $hit) { continue }
            $fqdn = if ($tm.fqdn) { $tm.fqdn } else { "$($tm.relativeName).trafficmanager.net" }
            $pathways += New-Pathway $a 'Traffic Manager' $tm.name $tm.id $hit $fqdn 'DNS' "DNS answer only; clients then connect to $($ep.target) directly" $gwClass $null 'n/a' $false "endpoint $($e.name) ($($ep.endpointMonitorStatus)); exposure equals the instance's own 443 reach"
        }
    }

    # ---- Azure Firewall DNAT rules that translate to this instance ----
    foreach ($fw in $firewalls) {
        $fwp = $fw.properties
        $fwIps = @()
        foreach ($ic in @($fwp.ipConfigurations | Where-Object { $_ })) { $pipId = "$($ic.properties.publicIPAddress.id)"; if ($pipId -and $publicIps.ContainsKey($pipId.ToLower())) { $fwIps += $publicIps[$pipId.ToLower()] } }
        $fwIps += @($fwp.hubIPAddresses.publicIPs.addresses | Where-Object { $_ } | ForEach-Object { "$($_.address)" })
        $natRules = @()
        foreach ($c in @($fwp.natRuleCollections | Where-Object { "$($_.properties.action.type)" -ieq 'Dnat' })) {
            foreach ($r in @($c.properties.rules | Where-Object { $_ })) { $natRules += [pscustomobject]@{ collection = "$($c.name) (inline)"; rule = $r } }
        }
        $polId = "$($fwp.firewallPolicy.id)"; $seen = @{}
        while ($polId -and -not $seen.ContainsKey($polId.ToLower())) {
            $seen[$polId.ToLower()] = $true
            foreach ($nr in @($fwPolicyNat[$polId.ToLower()])) { $natRules += [pscustomobject]@{ collection = "$(Get-ResourceName $polId)/$($nr.collection)"; rule = $nr.rule } }
            $polId = if ($fwPolicyById.ContainsKey($polId.ToLower())) { "$($fwPolicyById[$polId.ToLower()].basePolicyId)" } else { '' }
        }
        foreach ($n in $natRules) {
            $r = $n.rule
            $ep = Resolve-ApimTarget "$($r.translatedAddress)" $hosts $ips
            if (-not $ep) { $ep = Resolve-ApimTarget "$($r.translatedFqdn)" $hosts $ips }
            if (-not $ep) { continue }
            if ("$($r.translatedPort)" -eq '3443') { $ep = 'management endpoint (3443)' }
            $srcs = @(Expand-FirewallSources $r)
            $cls = Get-WorstClass @($srcs | ForEach-Object { (Get-SourceClass $_ $TightPrefixLength $TightPrefixLengthV6).class })
            $dst = "$(@($r.destinationAddresses) -join ' '):$(@($r.destinationPorts) -join ',')"
            $pathways += New-Pathway $a 'Azure Firewall DNAT' $fw.name $fw.id $ep "$($fwIps -join ' ') $dst".Trim() (@($r.destinationPorts) -join ',') ($srcs -join ' ') $cls $null 'n/a' $false "rule $($r.name) in $($n.collection) translates to $($r.translatedAddress)$($r.translatedFqdn):$($r.translatedPort)"
        }
    }

    # ---- Inbound private endpoints (private paths, listed for completeness) ----
    foreach ($pe in $privateEndpoints) {
        foreach ($c in @(@(Expand-Json $pe.connections) + @(Expand-Json $pe.manualConnections) | Where-Object { $_ })) {
            if ("$($c.properties.privateLinkServiceId)" -ine "$($a.id)") { continue }
            $pathways += New-Pathway $a 'private endpoint' $pe.name $pe.id 'gateway (Private Link)' (Get-ResourceName $pe.subnetId) '443' 'the VNet of the private endpoint' 'PRIVATE' $null 'n/a' $false "connection $($c.name): $($c.properties.privateLinkServiceConnectionState.status)"
        }
    }

    # ---- Optional: gateway runtime patch level (NSM advisory) ----
    $patch = ''
    if ($CheckGatewayPatch) {
        $statuses = @()
        if ($sc.tierFamily -in 'v2', 'Classic (Consumption)') {
            $p = Get-GatewayPatchStatus '' $sc.tierFamily
            $patchRows += [pscustomobject]@{ apim = $a.name; subscriptionId = $a.subscriptionId; region = "$($a.location)"; gateway = ''; runtimeVersion = ''; patchStatus = $p; note = 'not probed' }
            $statuses += $p
        } else {
            foreach ($t in @(Get-GatewayProbeTargets $a)) {
                $ver = ''; $note = ''
                if ($t.disabled) { $p = 'not probed (gateway disabled in this region)' }
                elseif (-not $t.host) { $p = 'unknown (no regional gateway URL in the resource data)' }
                else {
                    try {
                        $resp = Invoke-RestMethod -Uri "https://$($t.host)/internal-status-0123456789abcdef" -TimeoutSec 20 -ErrorAction Stop
                        $ver = "$($resp.RuntimeVersion)"
                        if (-not $ver -and $resp.Version) { $note = "status endpoint answered without RuntimeVersion (Version=$($resp.Version))" }
                    } catch {
                        $note = "status endpoint not reachable from here: $(($_.Exception.Message -split "`n")[0])"
                        if ("$($a.vnetType)" -ieq 'Internal') { $note += '; Internal mode: the gateway resolves to a private address, so rerun -CheckGatewayPatch from a machine inside (or peered with) the VNet' }
                    }
                    $p = if ($ver) { Get-GatewayPatchStatus $ver $sc.tierFamily } elseif ($note) { "unknown ($note)" } else { Get-GatewayPatchStatus '' $sc.tierFamily }
                }
                $patchRows += [pscustomobject]@{ apim = $a.name; subscriptionId = $a.subscriptionId; region = $t.region; gateway = $t.host; runtimeVersion = $ver; patchStatus = $p; note = $note }
                $statuses += $p
            }
        }
        $patch = Get-PatchSummary $statuses
    }

    $mineP = @($pathways | Where-Object { $_.apim -eq $a.name -and $_.subscriptionId -eq $a.subscriptionId })

    # ---- Change history since -ChangesSince (Activity Log) ----
    $changes = ''
    if (-not $SkipChangeHistory) {
        $watched = @()
        foreach ($loc in $locations) {
            if (-not $loc.subnetId) { continue }
            $watched += "$($loc.subnetId)"
            $sn = $subnets["$($loc.subnetId)".ToLower()]
            if ($sn -and $sn.nsgId) { $watched += "$($sn.nsgId)" }
        }
        foreach ($p in @($mineP | Where-Object { $_.pathway -in 'Application Gateway', 'Front Door', 'Front Door (classic)', 'Azure Firewall DNAT', 'private endpoint' })) {
            $watched += "$($p.viaId)"
            if ($p.pathway -eq 'Azure Firewall DNAT') {
                $fwPol = "$(($firewalls | Where-Object { "$($_.id)" -ieq "$($p.viaId)" } | Select-Object -First 1).properties.firewallPolicy.id)"
                if ($fwPol) { $watched += $fwPol }
            }
        }
        foreach ($k in @($wafUse.Keys)) { if ($k -notlike '*|inline' -and $wafUse[$k].Contains("$($a.name)")) { $watched += $k } }
        $watched = @($watched | Where-Object { $_ } | ForEach-Object { "$_".TrimEnd('/').ToLowerInvariant() } | Sort-Object -Unique)
        $rgKeys = @(@("$($a.id)") + $watched | ForEach-Object { Get-ResourceGroupKey $_ } | Where-Object { $_ } | Sort-Object -Unique)
        $found = @(); $unread = @()
        foreach ($rk in $rgKeys) {
            $res = Get-ResourceGroupEvents $rk
            if (-not $res.ok) { $unread += ($rk -split '\|')[1]; continue }
            $found += @($res.events | Where-Object { Test-IngressChange $_ "$($a.id)" $watched })
        }
        $found = @(Select-UniqueChange $found | Sort-Object { Format-EventTime $_.eventTimestamp })
        foreach ($e in $found) {
            $changeRows += [pscustomobject]@{
                apim = $a.name; subscriptionId = $a.subscriptionId; time = (Format-EventTime $e.eventTimestamp); operation = "$($e.operationName.value)"
                resource = (Get-ResourceName "$($e.resourceId)"); caller = "$($e.caller)"; resourceId = "$($e.resourceId)"; correlationId = "$($e.correlationId)"
            }
        }
        $since = $changesFrom.ToString('yyyy-MM-dd')
        $changes = if ($found.Count) { "CHANGED: $($found.Count) change(s) since $since, last $(Format-EventTime $found[-1].eventTimestamp)" } elseif ($unread.Count) { "unknown (Activity Log not readable for $($unread -join ', '))" } else { "no changes since $since" }
        if ($found.Count -and $unread.Count) { $changes += " (Activity Log not readable for $($unread -join ', '))" }
    }

    # ---- Status and summary ----
    $status = Get-IngressStatus $mineP $unchecked
    $wafP = @($mineP | Where-Object { $_.wafVerdict -ne 'n/a' })
    $summary += [pscustomobject]@{
        ingressStatus = $status; apim = $a.name; subscriptionId = $a.subscriptionId; sku = $a.sku; tierFamily = $sc.tierFamily; platformVersion = $a.platformVersion
        vnetType = $(if ($a.vnetType) { $a.vnetType } else { 'None' }); publicAccess = $(if ($a.publicAccess) { $a.publicAccess } else { 'Enabled' }); privateEndpoints = $peCount
        managementReach = $reach.management; gatewayReach = $reach.gateway; nsg = ($nsgNames -join '; ')
        nsg3443 = $(if ($injected) { $class3443 } else { '' }); nsg443 = $(if ($injected) { $class443 } else { '' })
        openPathways = @($mineP | Where-Object { $_.sourceClass -eq 'OPEN' -and -not ($_.wafVerdict -eq 'PREVENTION' -and -not $_.bypassable) }).Count
        broadPathways = @($mineP | Where-Object { $_.sourceClass -in 'BROAD', 'AZURE-SHARED', 'UNKNOWN' }).Count
        wafFronted = $wafP.Count; wafVerdicts = (@($wafP | ForEach-Object { $_.wafVerdict } | Sort-Object -Unique) -join '; ')
        wafBypassable = (@($mineP | Where-Object { $_.bypassable }).Count -gt 0)
        ipFilter = $(if ($pol -and $pol.ipFilterAction) { "$($pol.ipFilterAction) ($($pol.ipFilterClass))$(if ($pol.ipFilterConditional) { ' conditional' })" } elseif ($SkipPolicy) { 'not read' } else { 'none' })
        fdidCheck = $(if ($pol) { $pol.fdidCheck } else { '' })
        directMgmtApi = $(if ($flags) { $flags.directMgmtApi } else { '' }); gitAccess = $(if ($flags) { $flags.gitAccess } else { '' })
        gatewayPatch = $patch; changesSince = $(if ($SkipChangeHistory) { 'not read (-SkipChangeHistory)' } else { $changes }); scope = $sc.reason; basis = $reach.basis
    }
}

# =====================================================================================================
# Output: CSVs, Markdown report, console summary
# =====================================================================================================
$script:failures | Export-Csv (Join-Path $OutDir 'failed-calls.csv')
if ($script:failures.Count) { Write-Warning "$($script:failures.Count) API call(s) failed - see failed-calls.csv (results for those resources are incomplete)" }
$summary | Export-Csv (Join-Path $OutDir 'ingress-summary.csv')
$pathwaysOut = @($pathways | Sort-Object apim, @{ Expression = 'severity'; Descending = $true }, pathway |
    Select-Object apim, subscriptionId, pathway, via, endpoint, frontend, port, source, sourceClass, severity, wafVerdict, wafPolicy, wafNotes, bypassable, detail, viaId)
$pathwaysOut | Export-Csv (Join-Path $OutDir 'ingress-pathways.csv')
$nsgRows | Export-Csv (Join-Path $OutDir 'nsg-inbound-rules.csv')
$policyRows | Export-Csv (Join-Path $OutDir 'apim-policy-controls.csv')
$wafPolicyRows = @(foreach ($k in $wafCache.Keys) {
    $w = $wafCache[$k]
    [pscustomobject]@{ policy = $w.policy; kind = $w.kind; usedBy = (@($wafUse[$k]) -join ', '); state = $w.state; mode = $w.mode; verdict = $w.verdict
                       requestBodyCheck = $w.requestBodyCheck; managedRuleSets = $w.managedRuleSets; disabledRules = $w.disabledRules; disabledRuleGroups = $w.disabledRuleGroups
                       weakenedRules = $w.weakenedRules; exclusions = $w.exclusions; customRules = $w.customRules; permissiveAllows = $w.permissiveAllows
                       allowlist = $w.allowlist; allowlistClass = $w.allowlistClass; notes = $w.notes; policyId = $w.policyId }
})
$wafPolicyRows | Sort-Object kind, policy | Export-Csv (Join-Path $OutDir 'waf-policies.csv')
$wafRuleRows = @(foreach ($k in $wafCache.Keys) { foreach ($r in @($wafCache[$k].customRuleRows)) { $r | Select-Object policy, kind, rule, priority, enabled, ruleType, action, conditions, ipMatch, ipNegated, ipClass, assessment, policyId } })
$wafRuleRows | Export-Csv (Join-Path $OutDir 'waf-custom-rules.csv')
if ($CheckGatewayPatch) { $patchRows | Export-Csv (Join-Path $OutDir 'gateway-patch-status.csv') }
if (-not $SkipChangeHistory) { $changeRows | Export-Csv (Join-Path $OutDir 'network-changes.csv') }
$changed = @($summary | Where-Object { "$($_.changesSince)" -like 'CHANGED*' })
$changeUnknown = @($summary | Where-Object { "$($_.changesSince)" -like 'unknown*' })

function ConvertTo-MdTable($Rows, [string[]]$Cols) {
    $rows = @($Rows | Where-Object { $_ })
    if (-not $rows.Count) { return '_None._' }
    $out = @(('| ' + ($Cols -join ' | ') + ' |'), ('|' + (($Cols | ForEach-Object { '---' }) -join '|') + '|'))
    foreach ($r in $rows) { $out += '| ' + (($Cols | ForEach-Object { "$($r.$_)" -replace '\|', '/' -replace "`r?`n", ' ' }) -join ' | ') + ' |' }
    $out -join "`n"
}
$permissive = @($pathwaysOut | Where-Object { ($_.sourceClass -in 'OPEN', 'BROAD', 'AZURE-SHARED', 'UNKNOWN') -and -not ($_.wafVerdict -eq 'PREVENTION' -and -not $_.bypassable) })
$nsgFindings = @($nsgRows | Where-Object { $_.effective -and $_.sourceClass -in 'OPEN', 'BROAD', 'AZURE-SHARED', 'UNKNOWN' -and ($_.port -in 3443, 443, 80, 'other') } | Sort-Object apim, port, priority)
$mgmtOpen = @($summary | Where-Object { $_.managementReach -like 'INTERNET*' -or $_.managementReach -like 'BROAD*' -or $_.managementReach -like 'AZURE-SHARED*' })
$weakWaf = @($wafPolicyRows | Where-Object { $_.verdict -ne 'PREVENTION' -or [int]"0$($_.permissiveAllows)" -gt 0 })
$generated = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$report = @"
# APIM internet ingress exposure

Generated $generated by Check-IngressExposure.ps1 (read-only). Tight-range threshold: IPv4 /$TightPrefixLength and smaller, IPv6 /$TightPrefixLengthV6 and smaller.
**Contains tenant data. Do not commit or share outside the incident team.**

Why this matters: Microsoft's notice ties exposure to missing network integration. The service configuration (management)
endpoint listens on port 3443 of every Classic instance's public VIP, and the gateway, developer portal, Git and management
hostnames answer on 443. This report shows who on the internet can reach them, through what, and how permissive each path is.

## Key numbers

| Item | Value |
|---|---|
| Instances analysed | $($summary.Count) |
| OPEN (management endpoint or a 443 endpoint reachable from the whole internet with nothing blocking; a WAF that is detection-only, disabled, without blocking rules or bypassable does not block) | $(@($summary | Where-Object ingressStatus -eq 'OPEN').Count) |
| BROAD (the widest unmitigated pathway admits a wide range, a multi-tenant service tag or an unknown source) | $(@($summary | Where-Object ingressStatus -eq 'BROAD').Count) |
| FILTERED (tight ranges only, or a prevention-mode WAF that cannot be bypassed) | $(@($summary | Where-Object ingressStatus -eq 'FILTERED').Count) |
| PRIVATE (control plane, VNet and private ranges only) | $(@($summary | Where-Object ingressStatus -eq 'PRIVATE').Count) |
| UNCHECKED (subnet or NSG not visible) | $(@($summary | Where-Object ingressStatus -eq 'UNCHECKED').Count) |
| Instances whose management endpoint (3443) is reachable from the internet, from broad ranges or from a multi-tenant service tag | $($mgmtOpen.Count) |
| Permissive pathways (open, broad or unknown sources not behind an effective WAF) | $($permissive.Count) |
| NSG allow rules admitting open, broad or multi-tenant sources on 3443 / 443 / 80 / other ports | $($nsgFindings.Count) |
| WAF policies in use | $($wafPolicyRows.Count) (not in prevention mode or with permissive allows: $($weakWaf.Count)) |
| Instances with a bypassable WAF | $(@($summary | Where-Object { $_.wafBypassable -eq $true }).Count) |
| Instances whose ingress configuration changed since $($changesFrom.ToString('yyyy-MM-dd')) (today's state may not be the state during the exposure window) | $(if ($SkipChangeHistory) { 'not read' } else { "$($changed.Count)$(if ($changeUnknown.Count) { " (Activity Log not readable for $($changeUnknown.Count) more)" })" }) |

## Per instance

$(ConvertTo-MdTable ($summary | Sort-Object @{ Expression = { switch ($_.ingressStatus) { 'OPEN' { 0 } 'BROAD' { 1 } 'UNCHECKED' { 2 } 'FILTERED' { 3 } default { 4 } } } }, apim) @('ingressStatus','apim','sku','vnetType','publicAccess','privateEndpoints','managementReach','gatewayReach','nsg3443','nsg443','wafVerdicts','wafBypassable','ipFilter','fdidCheck','directMgmtApi','gitAccess','gatewayPatch','changesSince'))

$(if (-not $SkipChangeHistory) { "## Changes since $($changesFrom.ToString('yyyy-MM-dd'))`n`nEverything above is today's configuration. These successful writes and deletes in the Activity Log touched an instance (service settings, private endpoint connections, global policy, tenant access), its subnets or NSGs, or a front end or WAF policy that reaches it. An instance listed here may have been more exposed during the incident than the tables above show: check what each change did before relying on its status. Details, including the caller, are in network-changes.csv.`n`n" + (ConvertTo-MdTable $changeRows @('apim','time','operation','resource','caller')) + $(if ($changeUnknown.Count) { "`n`nActivity Log not readable (no evidence either way): $(($changeUnknown | ForEach-Object { $_.apim }) -join ', '). See failed-calls.csv." }) })

## Permissive pathways

Every way in from the internet that is open, broad or unknown and not behind a prevention-mode WAF. Details in ingress-pathways.csv.

$(ConvertTo-MdTable $permissive @('apim','pathway','via','endpoint','frontend','port','source','sourceClass','wafVerdict','bypassable','detail'))

## NSG rules on the APIM subnets that admit wide sources

Effective allow rules (not shadowed by a higher-priority deny) whose source is open, broad, a multi-tenant service tag or unrecognised. Microsoft's reference for a VNet-injected Classic instance is 3443 from the ApiManagement tag, 80/443 from Internet (External mode only) and 6390 from AzureLoadBalancer. All evaluated rows are in nsg-inbound-rules.csv.

$(ConvertTo-MdTable $nsgFindings @('apim','location','nsg','port','rule','priority','source','sourceClass','addresses','partiallyDeniedBy','assessment'))

## WAF policies

$(ConvertTo-MdTable ($wafPolicyRows | Sort-Object kind, policy) @('policy','kind','usedBy','verdict','mode','state','managedRuleSets','customRules','permissiveAllows','allowlist','allowlistClass','disabledRules','disabledRuleGroups','exclusions','notes'))

Custom rules are listed in waf-custom-rules.csv. A custom Allow rule for an open or broad source range skips the managed rules for most of the internet; a Block rule with a negated address match is an allowlist.

$(if ($CheckGatewayPatch) { "## Gateway runtime patch level`n`nPer the Norwegian NSM advisory (20 Nov 2026): 0.52.x is patched from build 31936, 0.53.x from 31938; builds such as 0.52.4150.0 or 0.53.4608.0 are NSM's v2 / Consumption pattern, which was not vulnerable. The thresholds are applied to Classic tiers only; a v2 or Consumption instance is not probed. UNRECOGNISED means the answer fits neither rule for the instance's tier: verify with Microsoft. Multi-region instances are probed per region. Microsoft has not documented this endpoint; 'unknown' is not 'patched'.`n`n" + (ConvertTo-MdTable $patchRows @('apim','region','gateway','runtimeVersion','patchStatus','note')) })

## What to do with an OPEN or BROAD instance

- **Management endpoint (3443) open or broad:** in External or Internal mode, change the NSG so port 3443 is allowed only from the ApiManagement service tag (Microsoft's reference rule). Without VNet injection, the only ways to take the service configuration endpoints off the internet are an inbound private endpoint with public network access disabled, or moving to internal VNet mode.
- **443 endpoints open with no front end:** that is the default public gateway. If the APIs are meant to be private, use internal mode or a private endpoint with public access disabled. If they are public, put a WAF in front (Application Gateway WAF or Front Door) in prevention mode and make the instance accept only that front end (X-Azure-FDID check-header for Front Door, an ip-filter policy or an NSG allow for AzureFrontDoor.Backend or the gateway subnet). Otherwise the WAF can be bypassed by calling the instance directly.
- **WAF in detection mode or disabled:** it logs and blocks nothing. Switch to prevention after reviewing the log.
- **Custom WAF allow rules for wide ranges:** they skip the managed rules. Narrow them to the specific sources that need the exception.
- **Direct management API or Git access enabled:** disable both unless used; regenerate their keys either way (see Check-ApimExposure.ps1 output).
- Microsoft's own checklist is the "Network security" section of Secure your Azure API Management deployment (learn.microsoft.com/azure/api-management/secure-api-management).

## Limits

- The statuses describe today's configuration, not the configuration during the exposure window. The Activity Log check flags later changes but does not reconstruct the earlier state; it reads 90 days at most and covers the resources listed above, not, for example, a route table or a DNS record.
- Reachability is inferred from configuration, not probed. Service tags are opaque: their address ranges are not expanded.
- The subnet NSG is evaluated for internet reachability only. Partial denies are reported, not subtracted, and two partial denies that together cover an allow are not combined.
- A Front Door security policy that covers only some path patterns of a route is credited for the whole route.
- Only the global policy is read; product, API and operation policies may add or remove restrictions for parts of the gateway. Policies never protect the management endpoint, the developer portal or Git.
- Whether disabling public network access also closes the developer portal, Git and management hostnames is not documented by Microsoft; this report treats it as closing them.
- Front ends that reach the instance over paths this script does not read (for example a reverse proxy on a VM, or a non-Azure CDN) are not seen.
- Front Door Standard/Premium child resources, firewall policy rule collection groups and the APIM global policy are read with direct ARM calls; a failed call lands in failed-calls.csv and leaves that path unassessed.
"@
$report | Set-Content (Join-Path $OutDir 'ingress-report.md') -Encoding utf8

Write-Host "`n=== Internet ingress per instance ==="
foreach ($s in ($summary | Sort-Object @{ Expression = { switch ($_.ingressStatus) { 'OPEN' { 0 } 'BROAD' { 1 } 'UNCHECKED' { 2 } 'FILTERED' { 3 } default { 4 } } } }, apim)) {
    $color = switch ($s.ingressStatus) { 'OPEN' { 'Red' } 'BROAD' { 'Yellow' } 'UNCHECKED' { 'Magenta' } 'FILTERED' { 'Cyan' } default { 'Green' } }
    Write-Host ("{0,-10} {1} [{2}, {3}, public access {4}, PE {5}] | management endpoint: {6} | 443 endpoints: {7} | NSG 3443={8} 443={9} | WAF: {10}{11} | ip-filter: {12}, FDID check: {13}{14}" -f `
        $s.ingressStatus, $s.apim, $s.sku, $s.vnetType, $s.publicAccess, $s.privateEndpoints, $s.managementReach, $s.gatewayReach,
        $(if ($s.nsg3443) { $s.nsg3443 } else { '-' }), $(if ($s.nsg443) { $s.nsg443 } else { '-' }),
        $(if ($s.wafVerdicts) { $s.wafVerdicts } else { 'none' }), $(if ($s.wafBypassable) { ' (BYPASSABLE)' } else { '' }),
        $s.ipFilter, $s.fdidCheck, $(if ($s.gatewayPatch) { " | patch: $($s.gatewayPatch)" } else { '' })) -ForegroundColor $color
    if ("$($s.changesSince)" -like 'CHANGED*' -or "$($s.changesSince)" -like 'unknown*') { Write-Host "           $($s.apim): $($s.changesSince)" -ForegroundColor Yellow }
}
if ($changed.Count) { Write-Warning "$($changed.Count) instance(s) had ingress-relevant changes since $($changesFrom.ToString('yyyy-MM-dd')): $(($changed | ForEach-Object { $_.apim }) -join ', '). Their status reflects today's configuration, which may be tighter than during the exposure window. See network-changes.csv." }
Write-Host @"

Legend: OPEN      = the management endpoint (3443) or a 443 endpoint is reachable from the whole internet with nothing in front of it
                    that blocks. A WAF in detection mode, a disabled WAF or a bypassable WAF does not count as blocking.
        BROAD     = the widest unmitigated pathway admits a wide range (wider than /$TightPrefixLength), a multi-tenant service tag such as
                    AzureCloud or AzureFrontDoor.Backend, or an unrecognised source.
        FILTERED  = only tight ranges, or open pathways that all sit behind a prevention-mode WAF that cannot be bypassed.
        PRIVATE   = nothing beyond the Azure control plane (ApiManagement tag), the VNet or private ranges.
        UNCHECKED = the APIM subnet or its NSG could not be read.
        Management endpoint = the service configuration endpoint on port 3443 (Azure control plane; formerly also the direct
                    management API). CONTROL-PLANE ONLY means the NSG admits only Microsoft-operated service tags; ApiManagement is
                    Microsoft's reference (any other Microsoft-operated tag on 3443 is listed for review). 443 endpoints = gateway,
                    developer portal, Git and the management hostname.
        BYPASSABLE = a WAF fronts the gateway, but the instance also answers directly from the internet and neither checks
                    X-Azure-FDID nor filters source addresses, so the WAF can be skipped.
Output: ingress-summary.csv, ingress-pathways.csv, nsg-inbound-rules.csv, waf-policies.csv, waf-custom-rules.csv,
        apim-policy-controls.csv$(if ($CheckGatewayPatch) { ', gateway-patch-status.csv' })$(if (-not $SkipChangeHistory) { ', network-changes.csv' }), failed-calls.csv and ingress-report.md in $OutDir
"@
