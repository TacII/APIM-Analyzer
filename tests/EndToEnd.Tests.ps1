#Requires -Version 7
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
End-to-end test for Check-IngressExposure.ps1: runs the script's real main flow (discovery, per-instance analysis,
CSV and report output) against the synthetic tenant in fixtures/ingress-tenant.json. Only the Azure calls are
replaced: az, Resource Graph (Invoke-Graph) and the ARM reads (Get-Paged, Get-One). No Azure access needed.

The fixture holds eleven instances: no VNet with and without a private endpoint, External with Microsoft's
reference NSG behind an Application Gateway WAF, Internal locked down behind Front Door Premium over Private Link,
Internal with port 3443 open to the internet, External with a broad partner range and Traffic Manager, Internal
reached through Azure Firewall DNAT rules, a v2 and a Consumption instance that the tier rule leaves out, one with
an unrecognized SKU that is retained for review, and one in a subscription of another tenant that is never read.

Run:  Invoke-Pester ./tests
#>

BeforeAll {
    . (Join-Path $PSScriptRoot '../Apim-Helpers.ps1')   # the script dot-sources it at its top, which the loader below skips
    $scriptPath = Join-Path $PSScriptRoot '../Check-IngressExposure.ps1'
    $script:scriptText = Get-Content $scriptPath -Raw
    $ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $scriptPath), [ref]$null, [ref]$null)
    $stubbed = 'Get-ArmToken', 'Invoke-Arm', 'Invoke-ArmGet', 'Invoke-Graph', 'Get-Paged', 'Get-One'
    foreach ($d in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
        if ($d.Name -in $stubbed) { continue }
        . ([scriptblock]::Create($d.Extent.Text))
    }
    $lines = $script:scriptText -split "`n"
    $discoveryLine = ($lines | Select-String -SimpleMatch '# Discovery:' | Select-Object -First 1).LineNumber
    foreach ($a in ($ast.FindAll({ $args[0] -is [System.Management.Automation.Language.AssignmentStatementAst] -and $args[0].Left.Extent.Text -like '$script:*' }, $false) |
            Where-Object { $_.Extent.StartLineNumber -lt $discoveryLine } | Sort-Object { $_.Extent.StartLineNumber })) {
        . ([scriptblock]::Create($a.Extent.Text))
    }
    # The main flow is everything after the Discovery banner; it runs inside Invoke-IngressFlow with the stubs below.
    $script:flow = ($lines[$discoveryLine..($lines.Count - 1)]) -join "`n"
    $script:fixture = Get-Content (Join-Path $PSScriptRoot 'fixtures/ingress-tenant.json') -Raw | ConvertFrom-Json

    # ---- stubs for everything that would touch Azure ----
    # az is reached through Invoke-AzJson (`az <args> --output json`), which checks $LASTEXITCODE after the call
    $script:azCalls = [System.Collections.Generic.List[string]]::new()
    function az {
        $a = "$args"; $script:azCalls.Add($a); $global:LASTEXITCODE = 0
        if ($a -match 'account show') { return (@{ id = $script:fixture.accounts[0].id; tenantId = $script:fixture.tenantId } | ConvertTo-Json -Compress) }
        if ($a -match 'account list') { return ($script:fixture.accounts | ConvertTo-Json -AsArray -Depth 5) }
        throw "unexpected az call: $a"
    }
    function Invoke-Graph([string]$Query, [string[]]$Subs) {
        $f = $script:fixture
        $map = [ordered]@{
            "microsoft.apimanagement/service'" = $f.apim; "microsoft.network/virtualnetworks'" = $f.subnets; "microsoft.network/networksecuritygroups'" = $f.nsgs
            "microsoft.network/publicipaddresses'" = $f.publicIps; "microsoft.network/applicationgateways'" = $f.appGateways
            "microsoft.network/applicationgatewaywebapplicationfirewallpolicies'" = $f.agwWafPolicies
            "microsoft.network/frontdoorwebapplicationfirewallpolicies'" = $f.fdWafPolicies; "microsoft.network/frontdoors'" = $f.classicFrontDoors
            "microsoft.cdn/profiles'" = $f.afdProfiles; "microsoft.network/trafficmanagerprofiles'" = $f.trafficManagerProfiles
            "microsoft.network/azurefirewalls'" = $f.firewalls; "microsoft.network/firewallpolicies'" = $f.firewallPolicies
            "microsoft.network/ipgroups'" = $f.ipGroups; "microsoft.network/privateendpoints'" = $f.privateEndpoints
        }
        foreach ($k in $map.Keys) {
            if ($Query -match [regex]::Escape("type =~ '$k")) { return @($map[$k] | Where-Object { -not $_.subscriptionId -or $_.subscriptionId -in $Subs }) }
        }
        throw "unexpected Resource Graph query: $Query"
    }
    # Activity Log: the fixture's events for the queried resource group; $script:activityFailRg simulates an unreadable one
    $script:activityFailRg = ''
    $script:activityQueries = [System.Collections.Generic.List[string]]::new()
    function Get-Paged([string]$Url) {
        if ($Url -match '/providers/Microsoft\.Insights/eventtypes/management/values\?') {
            $script:activityQueries.Add($Url)
            if ([uri]::UnescapeDataString($Url) -notmatch "resourceGroupName eq '([^']+)'") { throw "Activity Log query without a resource group: $Url" }
            $rg = $Matches[1]
            if ($rg -ieq $script:activityFailRg) { $script:failures += [pscustomobject]@{ url = $Url; error = 'HTTP 403 AuthorizationFailed' }; return }
            return @($script:fixture.activityLog | Where-Object { "$($_.resourceId)" -match "/resourceGroups/$([regex]::Escape($rg))/" })
        }
        $c = $script:fixture.afdChildren
        if ($Url -match '/afdEndpoints\?') { return @($c.endpoints) }
        if ($Url -match '/originGroups\?') { return @($c.originGroups) }
        if ($Url -match '/originGroups/([^/]+)/origins\?') { $og = $Matches[1]; return @($c.origins | Where-Object { $_.'_originGroup' -eq $og }) }
        if ($Url -match '/afdEndpoints/([^/]+)/routes\?') { $ep = $Matches[1]; return @($c.routes | Where-Object { $_.'_endpoint' -eq $ep }) }
        if ($Url -match '/customDomains\?') { return @($c.customDomains) }
        if ($Url -match '/securityPolicies\?') { return @($c.securityPolicies) }
        if ($Url -match '/firewallPolicies/([^/]+)/ruleCollectionGroups\?') { $pol = $Matches[1]; return @($script:fixture.ruleCollectionGroups | Where-Object { $_.'_policy' -eq $pol }) }
        throw "unexpected ARM list: $Url"
    }
    function Get-One([string]$Url) {
        if ($Url -match '/service/([^/]+)/policies/policy\?') {
            $name = $Matches[1]
            $p = $script:fixture.policies | Where-Object { $_.apim -eq $name } | Select-Object -First 1
            $xml = if ($p) { $p.xml } else { $script:fixture.defaultPolicyXml }
            return [pscustomobject]@{ properties = [pscustomobject]@{ format = 'rawxml'; value = $xml } }
        }
        throw "unexpected ARM get: $Url"
    }
    # Runs the main flow with the script's parameters as local variables; console output goes to console.txt
    function Invoke-IngressFlow([string]$OutDir, [switch]$AllInstances, [switch]$IncludeConsumption, [string]$TenantId = '', [string]$ExposureDir = '',
                                [switch]$CheckGatewayPatch, [switch]$SkipChangeHistory, [datetime]$ChangesSince = '2026-11-01') {
        if (-not $ExposureDir) { $ExposureDir = Join-Path $OutDir 'no-exposure-dir' }   # no scope.csv there, so the tier rule applies
        $TightPrefixLength = 24; $TightPrefixLengthV6 = 48; $SkipPolicy = $false
        $script:failures = @()
        New-Item -ItemType Directory -Force $OutDir | Out-Null
        . ([scriptblock]::Create($script:flow)) *> (Join-Path $OutDir 'console.txt')
        [pscustomobject]@{ summary = @($summary); pathways = @($pathways); nsgRows = @($nsgRows); policyRows = @($policyRows); wafPolicyRows = @($wafPolicyRows)
                           patchRows = @($patchRows); changeRows = @($changeRows); outDir = $OutDir }
    }
}

Describe 'End-to-end run against the synthetic tenant' {
    BeforeAll {
        $script:run = Invoke-IngressFlow -OutDir (Join-Path $TestDrive 'default')
        $script:st = @{}; foreach ($s in $script:run.summary) { $script:st[$s.apim] = $s }
        $script:pw = @($script:run.pathways)
    }
    It 'analyses the Classic dedicated tiers and retains an unrecognized SKU (tier rule, no scope.csv)' {
        $script:run.summary.Count | Should -Be 8
        $script:st.ContainsKey('apim-v2-standard') | Should -BeFalse
        $script:st.ContainsKey('apim-consumption') | Should -BeFalse
        $script:st['apim-unknown-sku'].tierFamily | Should -Be 'Unknown'
        $script:st['apim-unknown-sku'].scope | Should -Match "unrecognized or missing SKU 'FutureTier': scope cannot be determined"
        $script:st['apim-unknown-sku'].ingressStatus | Should -Be 'OPEN'
        $script:st['apim-unknown-sku'].managementReach | Should -BeLike 'INTERNET*'
    }
    It 'never reads a subscription of another tenant' {
        $script:st.ContainsKey('apim-other-tenant') | Should -BeFalse
        Get-Content (Join-Path $script:run.outDir 'console.txt') -Raw | Should -Match 'Skipping 1 subscription\(s\) in 1 other tenant\(s\): 00000000-0000-0000-0000-00000000bbbb \(1\)'
    }
    It 'rates <Apim> <Status>' -TestCases @(
        @{ Apim = 'apim-none-open'; Status = 'OPEN' }, @{ Apim = 'apim-none-private'; Status = 'PRIVATE' }, @{ Apim = 'apim-external-ref'; Status = 'OPEN' }
        @{ Apim = 'apim-internal-locked'; Status = 'FILTERED' }, @{ Apim = 'apim-internal-3443-open'; Status = 'OPEN' }
        @{ Apim = 'apim-external-broad'; Status = 'BROAD' }, @{ Apim = 'apim-internal-dnat'; Status = 'OPEN' }
    ) { $script:st[$Apim].ingressStatus | Should -Be $Status }
    It 'puts the management endpoint where each mode leaves it' {
        $script:st['apim-none-open'].managementReach | Should -BeLike 'INTERNET*'
        $script:st['apim-none-private'].managementReach | Should -BeLike 'PRIVATE*'
        $script:st['apim-external-ref'].managementReach | Should -Be 'CONTROL-PLANE ONLY'
        $script:st['apim-internal-locked'].gatewayReach | Should -BeLike 'PRIVATE*'
        $script:st['apim-internal-3443-open'].managementReach | Should -BeLike 'INTERNET*'
        $script:st['apim-internal-3443-open'].nsg3443 | Should -Be 'OPEN'
        $script:st['apim-external-broad'].nsg443 | Should -Be 'BROAD'
        $script:st['apim-external-broad'].ipFilter | Should -BeLike 'allow (TIGHT)*'
        $script:st['apim-internal-locked'].fdidCheck | Should -BeTrue
        $script:st['apim-none-open'].nsg3443 | Should -Be ''
    }
    It 'finds the Application Gateway path and calls its WAF bypassable' {
        $row = @($script:pw | Where-Object { $_.apim -eq 'apim-external-ref' -and $_.pathway -eq 'Application Gateway' })
        $row.Count | Should -Be 1
        $row[0].wafVerdict | Should -Be 'PREVENTION'; $row[0].bypassable | Should -BeTrue; $row[0].sourceClass | Should -Be 'OPEN'
        $row[0].frontend | Should -BeLike '203.0.113.80:443*'
        $script:st['apim-external-ref'].wafBypassable | Should -BeTrue
    }
    It 'finds the Front Door Premium path over Private Link behind a prevention WAF' {
        $rows = @($script:pw | Where-Object { $_.apim -eq 'apim-internal-locked' -and $_.pathway -eq 'Front Door' })
        $rows.Count | Should -Be 2
        $rows.frontend | Should -Contain 'api.fabrikam.test'
        $rows[0].wafVerdict | Should -Be 'PREVENTION'; $rows[0].bypassable | Should -BeFalse; $rows[0].detail | Should -Match 'over Private Link'
        $script:st['apim-internal-locked'].wafBypassable | Should -BeFalse
    }
    It 'finds the classic Front Door path with a detection-only WAF' {
        $row = @($script:pw | Where-Object { $_.apim -eq 'apim-none-open' -and $_.pathway -eq 'Front Door (classic)' })
        $row.Count | Should -Be 1
        $row[0].wafVerdict | Should -Be 'DETECTION ONLY'; $row[0].frontend | Should -Be 'fd-classic-legacy.azurefd.net'
    }
    It 'finds the Traffic Manager, DNAT and private endpoint paths' {
        ($script:pw | Where-Object { $_.apim -eq 'apim-external-broad' -and $_.pathway -eq 'Traffic Manager' }).sourceClass | Should -Be 'BROAD'
        $dnat = @($script:pw | Where-Object { $_.apim -eq 'apim-internal-dnat' -and $_.pathway -eq 'Azure Firewall DNAT' })
        $dnat.Count | Should -Be 2
        ($dnat | Where-Object endpoint -eq 'management endpoint (3443)').sourceClass | Should -Be 'TIGHT'
        ($dnat | Where-Object endpoint -ne 'management endpoint (3443)').sourceClass | Should -Be 'OPEN'
        ($script:pw | Where-Object { $_.apim -eq 'apim-none-private' -and $_.pathway -eq 'private endpoint' }).sourceClass | Should -Be 'PRIVATE'
    }
    It 'reports the NSG rules against the reference' {
        # the Internet allow plus the synthesised VirtualNetwork and AzureLoadBalancer defaults all admit 3443
        $e = @($script:run.nsgRows | Where-Object { $_.apim -eq 'apim-internal-3443-open' -and $_.port -eq 3443 -and $_.effective })
        $e.Count | Should -Be 3
        $open = @($e | Where-Object sourceClass -eq 'OPEN')
        $open.Count | Should -Be 1; $open[0].source | Should -Be 'Internet'; $open[0].assessment | Should -BeLike 'OPEN*'
        $c = @($script:run.nsgRows | Where-Object { $_.apim -eq 'apim-external-ref' -and $_.port -eq 3443 -and $_.effective })
        $c[0].assessment | Should -BeLike 'expected*'
        $other = @($script:run.nsgRows | Where-Object { $_.apim -eq 'apim-internal-3443-open' -and $_.port -eq 'other' })
        $other.Count | Should -Be 1; $other[0].source | Should -Be '203.0.0.0/8'
        $b = @($script:run.nsgRows | Where-Object { $_.apim -eq 'apim-external-broad' -and $_.port -eq 443 -and $_.rule -eq 'AllowPartnerRange' })
        $b[0].effective | Should -BeTrue; $b[0].partiallyDeniedBy | Should -Match 'DenyOneBadHost'
    }
    It 'reads the global policies' {
        ($script:run.policyRows | Where-Object apim -eq 'apim-internal-locked').fdidCheck | Should -BeTrue
        ($script:run.policyRows | Where-Object apim -eq 'apim-external-broad').ipFilterClass | Should -Be 'TIGHT'
        ($script:run.policyRows | Where-Object apim -eq 'apim-none-open').ipFilterAction | Should -Be ''
    }
    It 'rates the WAF policies' {
        ($script:run.wafPolicyRows | Where-Object policy -eq 'waf-agw-prevention').verdict | Should -Be 'PREVENTION'
        ($script:run.wafPolicyRows | Where-Object policy -eq 'waffddetection').verdict | Should -Be 'DETECTION ONLY'
        ($script:run.wafPolicyRows | Where-Object policy -eq 'waffdprevention').usedBy | Should -Be 'apim-internal-locked'
    }
    It 'writes every output file and a report that names the open instances' {
        foreach ($f in 'ingress-summary.csv', 'ingress-pathways.csv', 'nsg-inbound-rules.csv', 'waf-policies.csv', 'waf-custom-rules.csv', 'apim-policy-controls.csv', 'failed-calls.csv', 'ingress-report.md') {
            Test-Path (Join-Path $script:run.outDir $f) | Should -BeTrue -Because "$f must exist"
        }
        $report = Get-Content (Join-Path $script:run.outDir 'ingress-report.md') -Raw
        $report | Should -Match 'apim-internal-3443-open'
        $report | Should -Match 'WAF BYPASSABLE'
        @(Import-Csv (Join-Path $script:run.outDir 'ingress-summary.csv')).Count | Should -Be 8
    }
}

Describe 'End-to-end run with -AllInstances' {
    It 'analyses v2 and Consumption instances without a 3443 endpoint' {
        $run = Invoke-IngressFlow -OutDir (Join-Path $TestDrive 'all') -AllInstances
        $run.summary.Count | Should -Be 10
        @($run.summary.apim) | Should -Not -Contain 'apim-other-tenant'
        $v2 = $run.summary | Where-Object apim -eq 'apim-v2-standard'
        $v2.managementReach | Should -BeLike 'n/a*'; $v2.ingressStatus | Should -Be 'OPEN'
        ($run.summary | Where-Object apim -eq 'apim-consumption').managementReach | Should -BeLike 'n/a*'
    }
}

Describe 'End-to-end run with -TenantId' {
    It 'reads the named tenant without asking az for the current account, also before any native command has run' {
        $previous = $global:LASTEXITCODE
        try {
            $global:LASTEXITCODE = $null   # a fresh pwsh process: the old inline check read this as a failure
            $script:azCalls.Clear()
            $run = Invoke-IngressFlow -OutDir (Join-Path $TestDrive 'tenant') -TenantId '00000000-0000-0000-0000-00000000aaaa'
            $run.summary.Count | Should -Be 8
            @($script:azCalls | Where-Object { $_ -match 'account show' }).Count | Should -Be 0
            @($script:azCalls | Where-Object { $_ -match 'account list' }).Count | Should -Be 1
        } finally { $global:LASTEXITCODE = $previous }
    }
    It 'fails clearly when the named tenant has no enabled subscriptions' {
        { Invoke-IngressFlow -OutDir (Join-Path $TestDrive 'tenant-empty') -TenantId '00000000-0000-0000-0000-00000000cccc' } |
            Should -Throw '*No enabled subscriptions in tenant 00000000-0000-0000-0000-00000000cccc*'
    }
}

Describe 'End-to-end run with a scope file from Check-ApimExposure.ps1' {
    BeforeAll {
        $script:exposureDir = Join-Path $TestDrive 'exposure'
        New-Item -ItemType Directory -Force $script:exposureDir | Out-Null
        $prefix = '/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-apim/providers/Microsoft.ApiManagement/service/'
        @(
            [pscustomobject]@{ id = "${prefix}apim-none-open"; inScope = 'False'; reason = 'not listed by Microsoft' }
            [pscustomobject]@{ id = "${prefix}apim-v2-standard"; inScope = 'True'; reason = 'listed by Microsoft, but now a v2 tier (migrated after the incident?)' }
            [pscustomobject]@{ id = "${prefix}apim-unknown-sku"; inScope = 'False'; reason = 'not listed by Microsoft' }
        ) | Export-Csv (Join-Path $script:exposureDir 'scope.csv')
    }
    It 'applies the file, keeps an unrecognized SKU for review and falls back to the tier rule for instances the file does not know' {
        $run = Invoke-IngressFlow -OutDir (Join-Path $TestDrive 'scoped') -ExposureDir $script:exposureDir
        $names = @($run.summary.apim)
        $names | Should -Not -Contain 'apim-none-open'
        $names | Should -Contain 'apim-v2-standard'
        $names | Should -Contain 'apim-unknown-sku'
        $run.summary.Count | Should -Be 8
        ($run.summary | Where-Object apim -eq 'apim-v2-standard').scope | Should -Be 'scope.csv: listed by Microsoft, but now a v2 tier (migrated after the incident?)'
        ($run.summary | Where-Object apim -eq 'apim-v2-standard').managementReach | Should -BeLike 'n/a*'
        ($run.summary | Where-Object apim -eq 'apim-external-ref').scope | Should -Match 'Classic dedicated tier'
        Get-Content (Join-Path $TestDrive 'scoped/console.txt') -Raw | Should -Match 'apim-external-ref is missing from .*scope\.csv; applying the tier fallback'
    }
    It 'stops on a malformed scope file instead of silently excluding instances' {
        $bad = Join-Path $TestDrive 'exposure-bad'
        New-Item -ItemType Directory -Force $bad | Out-Null
        [pscustomobject]@{ id = '/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-apim/providers/Microsoft.ApiManagement/service/apim-none-open'; inScope = 'maybe' } |
            Export-Csv (Join-Path $bad 'scope.csv')
        { Invoke-IngressFlow -OutDir (Join-Path $TestDrive 'scoped-bad') -ExposureDir $bad } | Should -Throw '*Expected True or False*'
    }
}

Describe 'End-to-end run: change history since the exposure window' {
    BeforeAll {
        $script:activityFailRg = ''
        $script:hist = Invoke-IngressFlow -OutDir (Join-Path $TestDrive 'history')
        $script:hs = @{}; foreach ($s in $script:hist.summary) { $script:hs[$s.apim] = $s }
    }
    It 'flags an NSG rule change on the APIM subnet, once, in its own case-insensitive resource group' {
        $script:hs['apim-internal-3443-open'].changesSince | Should -BeLike 'CHANGED: 1 change(s) since 2026-11-01, last 2026-11-20T09:15:30Z'
        $rows = @($script:hist.changeRows | Where-Object apim -eq 'apim-internal-3443-open')
        $rows.Count | Should -Be 1
        $rows[0].operation | Should -Be 'Microsoft.Network/networkSecurityGroups/securityRules/write'
        $rows[0].caller | Should -Be 'admin@contoso.test'
    }
    It 'flags a service update on an instance without a VNet' {
        $script:hs['apim-none-open'].changesSince | Should -BeLike 'CHANGED: 1 change(s)*2026-11-19T14:00:00Z'
    }
    It 'flags a change to a WAF policy in front of the instance' {
        $script:hs['apim-internal-locked'].changesSince | Should -BeLike 'CHANGED: 1 change(s)*'
        ($script:hist.changeRows | Where-Object apim -eq 'apim-internal-locked').resource | Should -Be 'waffdprevention'
    }
    It 'ignores API deployments and failed writes' {
        $script:hs['apim-external-ref'].changesSince | Should -Be 'no changes since 2026-11-01'
    }
    It 'reads each resource group once' {
        $script:activityQueries.Count | Should -Be (@($script:activityQueries | Sort-Object -Unique).Count)
    }
    It 'reports the changes in the report and network-changes.csv' {
        $report = Get-Content (Join-Path $script:hist.outDir 'ingress-report.md') -Raw
        $report | Should -Match '## Changes since 2026-11-01'
        $report | Should -Match 'securityRules/write'
        @(Import-Csv (Join-Path $script:hist.outDir 'network-changes.csv')).Count | Should -Be 3
        Get-Content (Join-Path $script:hist.outDir 'console.txt') -Raw | Should -Match "3 instance\(s\) had ingress-relevant changes"
    }
    It 'says unknown, not "no changes", when the Activity Log cannot be read' {
        $script:activityFailRg = 'rg-net'
        try { $run = Invoke-IngressFlow -OutDir (Join-Path $TestDrive 'history-fail') } finally { $script:activityFailRg = '' }
        ($run.summary | Where-Object apim -eq 'apim-external-ref').changesSince | Should -Be 'unknown (Activity Log not readable for rg-net)'
        ($run.summary | Where-Object apim -eq 'apim-none-open').changesSince | Should -BeLike 'CHANGED*'
        Get-Content (Join-Path $run.outDir 'ingress-report.md') -Raw | Should -Match 'Activity Log not readable'
    }
    It 'skips the Activity Log with -SkipChangeHistory' {
        $before = $script:activityQueries.Count
        $run = Invoke-IngressFlow -OutDir (Join-Path $TestDrive 'history-skip') -SkipChangeHistory
        $script:activityQueries.Count | Should -Be $before
        ($run.summary | Select-Object -First 1).changesSince | Should -Be 'not read (-SkipChangeHistory)'
        Test-Path (Join-Path $run.outDir 'network-changes.csv') | Should -BeFalse
    }
}

Describe 'End-to-end run with -CheckGatewayPatch' {
    BeforeAll {
        Mock Invoke-RestMethod {
            if ($Uri -match 'apim-internal-') { throw 'No such host is known.' }
            if ($Uri -match 'apim-external-ref') { return [pscustomobject]@{ RuntimeVersion = '0.52.31000.0' } }
            if ($Uri -match 'apim-unknown-sku') { return [pscustomobject]@{ RuntimeVersion = '0.53.4608.0' } }
            return [pscustomobject]@{ RuntimeVersion = '0.52.31936.0' }
        }
        $script:pr = Invoke-IngressFlow -OutDir (Join-Path $TestDrive 'patch') -CheckGatewayPatch -SkipChangeHistory -AllInstances
        $script:ps = @{}; foreach ($s in $script:pr.summary) { $script:ps[$s.apim] = $s }
    }
    It 'rates each Classic gateway against the threshold' {
        $script:ps['apim-none-open'].gatewayPatch | Should -Be 'patched (all 1 gateway(s))'
        $script:ps['apim-external-ref'].gatewayPatch | Should -BeLike 'NOT PATCHED in 1 of 1 gateway(s)*0.52.31936*'
    }
    It 'tells the reader to rerun from inside the VNet for an Internal instance' {
        $script:ps['apim-internal-locked'].gatewayPatch | Should -BeLike 'unknown in 1 of 1*'
        ($script:pr.patchRows | Where-Object apim -eq 'apim-internal-locked').note | Should -Match 'inside \(or peered with\) the VNet'
    }
    It 'does not call NSM''s v2 / Consumption pattern NOT PATCHED on an unknown SKU' {
        $script:ps['apim-unknown-sku'].gatewayPatch | Should -BeLike 'UNRECOGNISED*'
    }
    It 'does not probe v2 and Consumption instances' {
        $script:ps['apim-v2-standard'].gatewayPatch | Should -BeLike 'not applicable (v2 tier*'
        $script:ps['apim-consumption'].gatewayPatch | Should -BeLike 'not applicable (Classic (Consumption) tier*'
        Should -Invoke Invoke-RestMethod -Times 0 -ParameterFilter { $Uri -match 'apim-v2-standard|apim-consumption' }
    }
    It 'writes one row per gateway with its region' {
        $rows = @(Import-Csv (Join-Path $script:pr.outDir 'gateway-patch-status.csv'))
        $rows.Count | Should -Be $script:pr.summary.Count
        ($rows | Where-Object apim -eq 'apim-none-open').region | Should -BeLike '* (default hostname)'
    }
}
