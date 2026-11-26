#Requires -Version 7
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
Offline tests for the pure functions in Check-IngressExposure.ps1: CIDR width classification, NSG rule evaluation
(priority, deny shadowing, service tags, port ranges), WAF policy assessment, APIM hostname matching, the per-mode
reach decision, global policy parsing and the instance status. No Azure access needed.

Run:  Invoke-Pester ./tests
#>

# Used inside -TestCases, which Pester evaluates during discovery (before BeforeAll runs), so it lives at file level.
function New-TestPathway([string]$Class, [string]$Waf = '', [bool]$Bypass = $false) { [pscustomobject]@{ sourceClass = $Class; wafVerdict = $Waf; bypassable = $Bypass } }

BeforeAll {
    . (Join-Path $PSScriptRoot '../Apim-Helpers.ps1')   # Get-ResourceName and the tier rules the script shares with the scanners
    # Same helper again for the test bodies: Pester runs them in a scope that does not see file-level functions.
    function New-TestPathway([string]$Class, [string]$Waf = '', [bool]$Bypass = $false) { [pscustomobject]@{ sourceClass = $Class; wafVerdict = $Waf; bypassable = $Bypass } }
    $scriptPath = Join-Path $PSScriptRoot '../Check-IngressExposure.ps1'
    $ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $scriptPath), [ref]$null, [ref]$null)
    # Every top-level function, then the $script: lookup tables they use (in source order; the tables call functions).
    foreach ($d in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)) { . ([scriptblock]::Create($d.Extent.Text)) }
    # Only the lookup tables above the Discovery banner; the assignments below it call az.
    $discoveryLine = ($ast.Extent.Text -split "`n" | Select-String -SimpleMatch '# Discovery:' | Select-Object -First 1).LineNumber
    foreach ($a in ($ast.FindAll({ $args[0] -is [System.Management.Automation.Language.AssignmentStatementAst] -and $args[0].Left.Extent.Text -like '$script:*' }, $false) | Where-Object { -not $discoveryLine -or $_.Extent.StartLineNumber -lt $discoveryLine } | Sort-Object { $_.Extent.StartLineNumber })) {
        . ([scriptblock]::Create($a.Extent.Text))
    }

    function New-Rule([string]$Name, [int]$Priority, [string]$Access, $Source, $Ports, [string]$Protocol = 'Tcp', [string]$Direction = 'Inbound', $Destination = '*', [string]$SourcePorts = '*') {
        $p = [ordered]@{ priority = $Priority; direction = $Direction; access = $Access; protocol = $Protocol; sourcePortRange = $SourcePorts }
        if ($Source -is [array]) { $p.sourceAddressPrefixes = @($Source) } else { $p.sourceAddressPrefix = $Source }
        if ($Destination -is [array]) { $p.destinationAddressPrefixes = @($Destination) } else { $p.destinationAddressPrefix = $Destination }
        if ($Ports -is [array]) { $p.destinationPortRanges = @($Ports) } else { $p.destinationPortRange = $Ports }
        [pscustomobject]@{ name = $Name; properties = [pscustomobject]$p }
    }
    function New-Nsg([string]$Name, $Rules) {
        [pscustomobject]@{ id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/$Name"; name = $Name; rules = @($Rules); defaultRules = @() }
    }
    # Microsoft's reference NSG for an External-mode Classic instance
    function New-ReferenceNsg {
        New-Nsg 'nsg-apim' @(
            (New-Rule 'AllowClientInbound' 100 'Allow' 'Internet' @('80', '443'))
            (New-Rule 'AllowApimManagement' 110 'Allow' 'ApiManagement' '3443')
            (New-Rule 'AllowLoadBalancer' 120 'Allow' 'AzureLoadBalancer' '6390')
        )
    }
    function New-AgwPolicy([string]$Mode = 'Prevention', [string]$State = 'Enabled', $Rules = @(), $Overrides = @()) {
        [pscustomobject]@{
            id = '/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/waf-agw'; name = 'waf-agw'
            properties = [pscustomobject]@{
                policySettings = [pscustomobject]@{ state = $State; mode = $Mode; requestBodyCheck = $true }
                customRules = @($Rules)
                managedRules = [pscustomobject]@{ managedRuleSets = @([pscustomobject]@{ ruleSetType = 'OWASP'; ruleSetVersion = '3.2'; ruleGroupOverrides = @($Overrides) }); exclusions = @() }
            }
        }
    }
    function New-AgwRule([string]$Name, [int]$Priority, [string]$Action, [string]$Variable, [string]$Operator, $Values, [bool]$Negate = $false, [string]$State = 'Enabled', [string]$Type = 'MatchRule') {
        [pscustomobject]@{ name = $Name; priority = $Priority; ruleType = $Type; action = $Action; state = $State
            matchConditions = @([pscustomobject]@{ matchVariables = @([pscustomobject]@{ variableName = $Variable }); operator = $Operator; negationConditon = $Negate; matchValues = @($Values) }) }
    }
    function New-FdPolicy([string]$Mode = 'Prevention', [string]$State = 'Enabled', $Rules = @()) {
        [pscustomobject]@{
            id = '/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/FrontDoorWebApplicationFirewallPolicies/waffd'; name = 'waffd'; sku = [pscustomobject]@{ name = 'Premium_AzureFrontDoor' }
            properties = [pscustomobject]@{
                policySettings = [pscustomobject]@{ enabledState = $State; mode = $Mode; requestBodyCheck = 'Enabled' }
                customRules = [pscustomobject]@{ rules = @($Rules) }
                managedRules = [pscustomobject]@{ managedRuleSets = @([pscustomobject]@{ ruleSetType = 'Microsoft_DefaultRuleSet'; ruleSetVersion = '2.1'; ruleSetAction = 'Block'; ruleGroupOverrides = @(); exclusions = @() }) }
            }
        }
    }
    function New-FdRule([string]$Name, [int]$Priority, [string]$Action, [string]$Variable, [string]$Operator, $Values, [bool]$Negate = $false, [string]$State = 'Enabled', [string]$Type = 'MatchRule') {
        [pscustomobject]@{ name = $Name; priority = $Priority; ruleType = $Type; action = $Action; enabledState = $State
            matchConditions = @([pscustomobject]@{ matchVariable = $Variable; operator = $Operator; negateCondition = $Negate; matchValue = @($Values) }) }
    }
    function New-Apim([string]$Name = 'apim-x', $Hostnames = @(), $PublicIPs = @('203.0.113.10'), $PrivateIPs = @(), $Additional = @()) {
        [pscustomobject]@{ id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers/Microsoft.ApiManagement/service/$Name"; name = $Name
            hostnames = @($Hostnames); publicIPs = @($PublicIPs); privateIPs = @($PrivateIPs); additionalLocations = @($Additional) }
    }
}

Describe 'Function loading' {
    It 'finds the functions and lookup tables in Check-IngressExposure.ps1' {
        foreach ($n in 'ConvertTo-IpInfo', 'Get-SourceClass', 'Get-NsgRules', 'Get-NsgPortExposure', 'Get-WafAssessment', 'Get-ApimReach', 'Get-PolicyIngressControls', 'Get-IngressStatus') {
            Get-Command $n -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty -Because "$n must exist"
        }
        $script:classSeverity['OPEN'] | Should -Be 5
        @($script:privateRanges).Count | Should -BeGreaterThan 5
    }
}

Describe 'ConvertTo-IpInfo' {
    It 'parses an IPv4 CIDR' {
        $i = ConvertTo-IpInfo '203.0.113.0/24'
        $i.family | Should -Be 4; $i.prefixLength | Should -Be 24; "$($i.addresses)" | Should -Be '256'
        "$($i.network)" | Should -Be ([string]([System.Numerics.BigInteger]203 * 16777216 + 113 * 256))
    }
    It 'parses a single IPv4 address as a /32' { $i = ConvertTo-IpInfo '203.0.113.7'; $i.prefixLength | Should -Be 32; "$($i.addresses)" | Should -Be '1' }
    It 'parses an IPv6 CIDR' { $i = ConvertTo-IpInfo '2001:db8::/32'; $i.family | Should -Be 6; $i.prefixLength | Should -Be 32 }
    It 'returns null for <Value>' -TestCases @(@{ Value = 'Internet' }, @{ Value = '*' }, @{ Value = '443' }, @{ Value = '' }, @{ Value = '10.0.0.0/33' }, @{ Value = 'ApiManagement.WestEurope' }) {
        ConvertTo-IpInfo $Value | Should -BeNullOrEmpty
    }
}

Describe 'Test-PrefixContains and Test-PrivateRange' {
    It 'contains a smaller range of the same family' { Test-PrefixContains (ConvertTo-IpInfo '10.0.0.0/8') (ConvertTo-IpInfo '10.1.2.0/24') | Should -BeTrue }
    It 'does not contain a wider range' { Test-PrefixContains (ConvertTo-IpInfo '10.1.2.0/24') (ConvertTo-IpInfo '10.0.0.0/8') | Should -BeFalse }
    It 'does not contain an unrelated range' { Test-PrefixContains (ConvertTo-IpInfo '10.0.0.0/8') (ConvertTo-IpInfo '192.168.0.0/16') | Should -BeFalse }
    It 'never mixes families' { Test-PrefixContains (ConvertTo-IpInfo '::/0') (ConvertTo-IpInfo '10.0.0.0/8') | Should -BeFalse }
    It 'recognises <Value> as private = <Private>' -TestCases @(
        @{ Value = '10.1.2.3'; Private = $true }, @{ Value = '172.20.0.0/16'; Private = $true }, @{ Value = '192.168.1.0/24'; Private = $true }
        @{ Value = '100.64.0.0/10'; Private = $true }, @{ Value = 'fd00::/8'; Private = $true }, @{ Value = '203.0.113.0/24'; Private = $false }, @{ Value = '172.32.0.0/16'; Private = $false }
    ) { Test-PrivateRange (ConvertTo-IpInfo $Value) | Should -Be $Private }
}

Describe 'Get-SourceClass' {
    It 'classifies <Source> as <Class>' -TestCases @(
        @{ Source = '*'; Class = 'OPEN' }, @{ Source = 'Internet'; Class = 'OPEN' }, @{ Source = 'Any'; Class = 'OPEN' }, @{ Source = '0.0.0.0/0'; Class = 'OPEN' }, @{ Source = '::/0'; Class = 'OPEN' }
        @{ Source = '203.0.113.0/30'; Class = 'TIGHT' }, @{ Source = '203.0.113.0/25'; Class = 'TIGHT' }, @{ Source = '203.0.113.0/24'; Class = 'TIGHT' }, @{ Source = '203.0.113.7'; Class = 'TIGHT' }
        @{ Source = '203.0.112.0/23'; Class = 'BROAD' }, @{ Source = '203.0.0.0/16'; Class = 'BROAD' }, @{ Source = '8.0.0.0/8'; Class = 'BROAD' }
        @{ Source = '10.0.0.0/8'; Class = 'PRIVATE' }, @{ Source = '192.168.1.0/24'; Class = 'PRIVATE' }
        @{ Source = 'VirtualNetwork'; Class = 'VNET' }
        @{ Source = 'ApiManagement'; Class = 'CONTROL-PLANE' }, @{ Source = 'ApiManagement.WestEurope'; Class = 'CONTROL-PLANE' }, @{ Source = 'AzureLoadBalancer'; Class = 'CONTROL-PLANE' }
        @{ Source = 'GatewayManager'; Class = 'CONTROL-PLANE' }, @{ Source = 'AzureTrafficManager'; Class = 'CONTROL-PLANE' }
        @{ Source = 'AzureCloud'; Class = 'BROAD' }, @{ Source = 'AzureCloud.EastUS'; Class = 'BROAD' }
        @{ Source = 'AzureFrontDoor.Backend'; Class = 'AZURE-SHARED' }, @{ Source = 'AppService'; Class = 'AZURE-SHARED' }
        @{ Source = 'ASG:web-servers'; Class = 'ASG' }, @{ Source = ''; Class = 'UNKNOWN' }
        @{ Source = '2001:db8::/48'; Class = 'TIGHT' }, @{ Source = '2001:db8::/32'; Class = 'BROAD' }
    ) { (Get-SourceClass $Source).class | Should -Be $Class }
    It 'moves the boundary with the threshold: /24 is BROAD when /25 is required' { (Get-SourceClass '203.0.113.0/24' 25).class | Should -Be 'BROAD' }
    It 'reports the address count of a range' { "$((Get-SourceClass '203.0.0.0/16').addresses)" | Should -Be '65536' }
    It 'ranks OPEN above everything else' { Get-WorstClass @('TIGHT', 'CONTROL-PLANE', 'OPEN', 'BROAD') | Should -Be 'OPEN'; Get-WorstClass @() | Should -Be 'NONE' }
}

Describe 'Port parsing' {
    It 'parses <Ports> so that 3443 hit = <Hit3443> and 443 hit = <Hit443>' -TestCases @(
        @{ Ports = '*'; Hit3443 = $true; Hit443 = $true }, @{ Ports = '443'; Hit3443 = $false; Hit443 = $true }, @{ Ports = '80-443'; Hit3443 = $false; Hit443 = $true }
        @{ Ports = '3443'; Hit3443 = $true; Hit443 = $false }, @{ Ports = '80,443,3443'; Hit3443 = $true; Hit443 = $true }, @{ Ports = '3000-4000'; Hit3443 = $true; Hit443 = $false }
    ) { $r = @(Get-PortRanges $Ports); (Test-PortHit $r 3443) | Should -Be $Hit3443; (Test-PortHit $r 443) | Should -Be $Hit443 }
    It 'accepts a list of port values' { Test-PortHit @(Get-PortRanges @('22', '3443')) 3443 | Should -BeTrue }
    It 'treats * and Tcp as TCP but not Udp' { Test-TcpProtocol '*' | Should -BeTrue; Test-TcpProtocol 'TCP' | Should -BeTrue; Test-TcpProtocol 'Udp' | Should -BeFalse }
}

Describe 'Get-NsgRules' {
    It 'flattens sources, ports and synthesises the default inbound rules' {
        $nsg = New-Nsg 'n' @((New-Rule 'a' 100 'Allow' @('203.0.113.0/24', 'Internet') @('80', '443')), (New-Rule 'b' 200 'Deny' '*' '*'))
        $rules = @(Get-NsgRules $nsg)
        $rules.Count | Should -Be 5
        ($rules | Where-Object name -eq 'a').sources | Should -Be @('203.0.113.0/24', 'Internet')
        ($rules | Where-Object name -eq 'DenyAllInBound').priority | Should -Be 65500
        $rules[0].name | Should -Be 'a'
        ($rules | Where-Object name -eq 'AllowVNetInBound').isDefault | Should -BeTrue
    }
    It 'keeps real default rules when the resource carries them' {
        $nsg = New-Nsg 'n' @()
        $nsg.defaultRules = @((New-Rule 'DenyAllInBound' 65500 'Deny' '*' '*'))
        @(Get-NsgRules $nsg).Count | Should -Be 1
    }
}

Describe 'Get-NsgPortExposure' {
    It 'rates the Microsoft reference NSG: 443 open to the internet, 3443 control plane only' {
        $rules = Get-NsgRules (New-ReferenceNsg)
        Get-PortExposureClass (Get-NsgPortExposure $rules 443) | Should -Be 'OPEN'
        Get-PortExposureClass (Get-NsgPortExposure $rules 80) | Should -Be 'OPEN'
        Get-PortExposureClass (Get-NsgPortExposure $rules 3443) | Should -Be 'CONTROL-PLANE'
        Get-PortExposureClass (Get-NsgPortExposure $rules 6390) | Should -Be 'CONTROL-PLANE'
        Get-PortExposureClass (Get-NsgPortExposure $rules 22) | Should -Be 'VNET'
    }
    It 'shadows an allow from * by a higher-priority deny from Internet' {
        $rules = Get-NsgRules (New-Nsg 'n' @((New-Rule 'DenyMgmt' 100 'Deny' 'Internet' '3443'), (New-Rule 'AllowAll' 200 'Allow' '*' '3443')))
        $rows = @(Get-NsgPortExposure $rules 3443)
        ($rows | Where-Object rule -eq 'AllowAll').effective | Should -BeFalse
        ($rows | Where-Object rule -eq 'AllowAll').shadowedBy | Should -Match 'DenyMgmt'
        Get-PortExposureClass $rows | Should -Be 'VNET'
    }
    It 'flags a partial deny without shadowing the allow' {
        $rules = Get-NsgRules (New-Nsg 'n' @((New-Rule 'DenySome' 100 'Deny' '203.0.113.0/24' '3443'), (New-Rule 'AllowWide' 200 'Allow' '203.0.0.0/16' '3443')))
        $row = @(Get-NsgPortExposure $rules 3443) | Where-Object rule -eq 'AllowWide'
        $row.effective | Should -BeTrue
        $row.partiallyDeniedBy | Should -Match 'DenySome'
        $row.sourceClass | Should -Be 'BROAD'
    }
    It 'shadows a narrow allow by a wider deny' {
        $rules = Get-NsgRules (New-Nsg 'n' @((New-Rule 'DenyWide' 100 'Deny' '203.0.0.0/16' '3443'), (New-Rule 'AllowNarrow' 200 'Allow' '203.0.113.0/24' '3443')))
        (@(Get-NsgPortExposure $rules 3443) | Where-Object rule -eq 'AllowNarrow').effective | Should -BeFalse
    }
    It 'reports NONE when a deny-all sits above every allow' {
        $rules = Get-NsgRules (New-Nsg 'n' @((New-Rule 'DenyEverything' 100 'Deny' '*' '*'), (New-Rule 'AllowMgmt' 200 'Allow' 'ApiManagement' '3443')))
        Get-PortExposureClass (Get-NsgPortExposure $rules 3443) | Should -Be 'NONE'
    }
    It 'ignores UDP rules and outbound rules' {
        $rules = Get-NsgRules (New-Nsg 'n' @((New-Rule 'Udp' 100 'Allow' 'Internet' '3443' 'Udp'), (New-Rule 'Out' 110 'Allow' 'Internet' '3443' 'Tcp' 'Outbound'), (New-Rule 'DenyAll' 120 'Deny' '*' '*')))
        @(Get-NsgPortExposure $rules 3443 | Where-Object { $_.rule -in 'Udp', 'Out' }).Count | Should -Be 0
    }
    It 'applies the destination prefix when the subnet is known' {
        $rules = Get-NsgRules (New-Nsg 'n' @((New-Rule 'Other' 100 'Allow' 'Internet' '3443' 'Tcp' 'Inbound' '10.9.0.0/24'), (New-Rule 'DenyAll' 120 'Deny' '*' '*')))
        Get-PortExposureClass (Get-NsgPortExposure $rules 3443 24 48 @('10.1.0.0/24')) | Should -Be 'NONE'
        Get-PortExposureClass (Get-NsgPortExposure $rules 3443 24 48 @('10.9.0.0/26')) | Should -Be 'OPEN'
        Get-PortExposureClass (Get-NsgPortExposure $rules 3443) | Should -Be 'OPEN'
    }
    It 'does not let a deny aimed at another destination shadow the allow' {
        $rules = Get-NsgRules (New-Nsg 'n' @((New-Rule 'DenyElsewhere' 100 'Deny' '*' '3443' 'Tcp' 'Inbound' 'Internet'), (New-Rule 'AllowAll' 200 'Allow' 'Internet' '3443')))
        Get-PortExposureClass (Get-NsgPortExposure $rules 3443) | Should -Be 'OPEN'
    }
    It 'treats a wildcard protocol and a port range as hits' {
        $rules = Get-NsgRules (New-Nsg 'n' @((New-Rule 'Wide' 100 'Allow' '198.51.100.0/22' '3000-4000' '*')))
        $row = @(Get-NsgPortExposure $rules 3443) | Where-Object rule -eq 'Wide'
        $row.sourceClass | Should -Be 'BROAD'; $row.addresses | Should -Be '1024'
    }
}

Describe 'Get-ApimRuleAssessment' {
    It 'calls the ApiManagement tag on 3443 expected' { Get-ApimRuleAssessment 3443 'CONTROL-PLANE' 'ApiManagement' 'External' | Should -Match '^expected' }
    It 'calls an open 3443 OPEN' { Get-ApimRuleAssessment 3443 'OPEN' 'Internet' 'Internal' | Should -Match '^OPEN' }
    It 'calls a broad 3443 BROAD' { Get-ApimRuleAssessment 3443 'BROAD' '203.0.0.0/16' 'External' | Should -Match '^BROAD' }
    It 'calls open client traffic in External mode OPEN' { Get-ApimRuleAssessment 443 'OPEN' 'Internet' 'External' | Should -Match '^OPEN' }
    It 'notes that Internal mode has no public VIP on 443' { Get-ApimRuleAssessment 443 'OPEN' 'Internet' 'Internal' | Should -Match 'no public VIP' }
    It 'calls Traffic Manager probes expected' { Get-ApimRuleAssessment 443 'CONTROL-PLANE' 'AzureTrafficManager' 'External' | Should -Match '^expected' }
    It 'tells you to pair AzureFrontDoor.Backend with an X-Azure-FDID check' { Get-ApimRuleAssessment 443 'AZURE-SHARED' 'AzureFrontDoor.Backend' 'External' | Should -Match 'X-Azure-FDID' }
}

Describe 'Get-WafAssessment (Application Gateway policy)' {
    It 'rates prevention mode with a permissive allow and a tight allowlist' {
        $p = New-AgwPolicy 'Prevention' 'Enabled' @(
            (New-AgwRule 'allow-everyone' 10 'Allow' 'RemoteAddr' 'IPMatch' @('0.0.0.0/0'))
            (New-AgwRule 'only-office' 20 'Block' 'RemoteAddr' 'IPMatch' @('203.0.113.0/26') $true)
            (New-AgwRule 'old' 30 'Allow' 'RemoteAddr' 'IPMatch' @('0.0.0.0/0') $false 'Disabled')
        )
        $a = Get-WafAssessment $p 'AppGateway'
        $a.verdict | Should -Be 'PREVENTION (custom allow admits everyone)'
        $a.customRules | Should -Be 3
        $a.permissiveAllows | Should -Be 1
        $a.allowlist | Should -BeTrue
        $a.allowlistClass | Should -Be 'TIGHT'
        ($a.customRuleRows | Where-Object rule -eq 'allow-everyone').assessment | Should -Match '^PERMISSIVE ALLOW'
        ($a.customRuleRows | Where-Object rule -eq 'only-office').assessment | Should -Match '^ALLOWLIST:'
        ($a.customRuleRows | Where-Object rule -eq 'old').assessment | Should -Match '^disabled'
    }
    It 'rates detection mode DETECTION ONLY and a disabled policy WAF DISABLED' {
        (Get-WafAssessment (New-AgwPolicy 'Detection') 'AppGateway').verdict | Should -Be 'DETECTION ONLY'
        (Get-WafAssessment (New-AgwPolicy 'Prevention' 'Disabled') 'AppGateway').verdict | Should -Be 'WAF DISABLED'
    }
    It 'counts disabled and weakened managed rules' {
        $ov = @([pscustomobject]@{ ruleGroupName = 'REQUEST-920-PROTOCOL-ENFORCEMENT'; rules = @([pscustomobject]@{ ruleId = '920300' }, [pscustomobject]@{ ruleId = '920320'; state = 'Enabled'; action = 'Log' }) },
                [pscustomobject]@{ ruleGroupName = 'REQUEST-942-APPLICATION-ATTACK-SQLI'; rules = @() })
        $a = Get-WafAssessment (New-AgwPolicy 'Prevention' 'Enabled' @() $ov) 'AppGateway'
        $a.disabledRules | Should -Be 1; $a.weakenedRules | Should -Be 1; $a.disabledRuleGroups | Should -Be 1
        $a.notes | Should -Match 'disabled'
    }
    It 'flags an allow without a source restriction as a bypass' {
        $a = Get-WafAssessment (New-AgwPolicy 'Prevention' 'Enabled' @((New-AgwRule 'skip-health' 5 'Allow' 'RequestUri' 'Contains' @('/health')))) 'AppGateway'
        $a.customRuleRows[0].assessment | Should -Match '^ALLOW BYPASS'
        $a.permissiveAllows | Should -Be 1
    }
    It 'treats a broad allowlist as broad' {
        $a = Get-WafAssessment (New-AgwPolicy 'Prevention' 'Enabled' @((New-AgwRule 'country' 5 'Block' 'RemoteAddr' 'IPMatch' @('203.0.0.0/8') $true))) 'AppGateway'
        $a.allowlistClass | Should -Be 'BROAD'
        Get-WafPathwayClass $a | Should -Be 'BROAD'
    }
}

Describe 'Get-WafAssessment (Front Door policy) and legacy configuration' {
    It 'reads the Front Door shape (SocketAddr, enabledState, matchValue)' {
        $a = Get-WafAssessment (New-FdPolicy 'Prevention' 'Enabled' @((New-FdRule 'office-only' 1 'Block' 'SocketAddr' 'IPMatch' @('203.0.113.0/27', '198.51.100.4') $true))) 'FrontDoor'
        $a.verdict | Should -Be 'PREVENTION'; $a.allowlist | Should -BeTrue; $a.allowlistClass | Should -Be 'TIGHT'
        $a.managedRuleSets | Should -Match 'Microsoft_DefaultRuleSet'
        Get-WafPathwayClass $a | Should -Be 'TIGHT'
    }
    It 'rates a disabled Front Door policy WAF DISABLED and detection mode as OPEN pathway' {
        (Get-WafAssessment (New-FdPolicy 'Prevention' 'Disabled') 'FrontDoor').verdict | Should -Be 'WAF DISABLED'
        Get-WafPathwayClass (Get-WafAssessment (New-FdPolicy 'Detection') 'FrontDoor') | Should -Be 'OPEN'
        Get-WafPathwayClass $null | Should -Be 'OPEN'
    }
    It 'reads the inline Application Gateway configuration' {
        $gw = [pscustomobject]@{ id = '/s/rg/agw'; name = 'agw'; properties = [pscustomobject]@{ webApplicationFirewallConfiguration = [pscustomobject]@{ enabled = $true; firewallMode = 'Detection'; ruleSetType = 'OWASP'; ruleSetVersion = '3.1'; disabledRuleGroups = @([pscustomobject]@{ ruleGroupName = 'x'; rules = @(1, 2) }) } } }
        $a = Get-LegacyWafAssessment $gw
        $a.verdict | Should -Be 'DETECTION ONLY'; $a.disabledRules | Should -Be 2; $a.kind | Should -Be 'AppGatewayLegacy'
        $gw.properties.webApplicationFirewallConfiguration.enabled = $false
        (Get-LegacyWafAssessment $gw).verdict | Should -Be 'WAF DISABLED'
        Get-LegacyWafAssessment ([pscustomobject]@{ id = 'x'; name = 'x'; properties = [pscustomobject]@{} }) | Should -BeNullOrEmpty
    }
}

Describe 'APIM hostnames and targets' {
    It 'lists default and custom hostnames with their endpoint' {
        $hosts = @(Get-ApimHosts (New-Apim 'apim-x' @([pscustomobject]@{ type = 'Proxy'; hostName = 'api.contoso.com' }, [pscustomobject]@{ type = 'DeveloperPortal'; hostName = 'portal.contoso.com' })))
        ($hosts | Where-Object host -eq 'apim-x.azure-api.net').endpoint | Should -Be 'gateway'
        ($hosts | Where-Object host -eq 'api.contoso.com').endpoint | Should -Be 'gateway'
        ($hosts | Where-Object host -eq 'api.contoso.com').isDefault | Should -BeFalse
        ($hosts | Where-Object host -eq 'portal.contoso.com').endpoint | Should -Be 'developer portal'
        ($hosts | Where-Object host -eq 'apim-x.management.azure-api.net').endpoint | Should -Be 'management hostname'
        ($hosts | Where-Object host -eq 'apim-x.scm.azure-api.net').endpoint | Should -Be 'git'
    }
    It 'resolves addresses case-insensitively, with trailing dots, and by IP' {
        $apim = New-Apim 'apim-x' @([pscustomobject]@{ type = 'Proxy'; hostName = 'api.contoso.com' }) @('203.0.113.10') @('10.0.1.5')
        $hosts = Get-ApimHosts $apim; $ips = Get-ApimIps $apim
        Resolve-ApimTarget 'API.CONTOSO.COM.' $hosts $ips | Should -Be 'gateway'
        Resolve-ApimTarget 'apim-x.scm.azure-api.net' $hosts $ips | Should -Be 'git'
        Resolve-ApimTarget '10.0.1.5' $hosts $ips | Should -Be 'ip (any hostname)'
        Resolve-ApimTarget 'other.example.com' $hosts $ips | Should -BeNullOrEmpty
    }
    It 'collects IPs from additional locations too' {
        $apim = New-Apim 'apim-x' @() @('203.0.113.10') @('10.0.1.5') @([pscustomobject]@{ location = 'northeurope'; publicIPAddresses = @('198.51.100.9'); privateIPAddresses = @('10.0.2.5') })
        (Get-ApimIps $apim) | Should -Be @('10.0.1.5', '10.0.2.5', '198.51.100.9', '203.0.113.10')
    }
}

Describe 'Get-ApimReach' {
    It '<Case>' -TestCases @(
        @{ Case = 'no VNet, public access enabled: everything on the internet'; Vnet = 'None'; Public = 'Enabled'; Pe = 0; N443 = ''; N3443 = ''; HasNsg = $false; Gw = 'INTERNET*'; Mg = 'INTERNET*' }
        @{ Case = 'private endpoint with public access disabled: private'; Vnet = 'None'; Public = 'Disabled'; Pe = 1; N443 = ''; N3443 = ''; HasNsg = $false; Gw = 'PRIVATE*'; Mg = 'PRIVATE*' }
        @{ Case = 'External with the reference NSG: gateway on the internet, management control plane only'; Vnet = 'External'; Public = 'Enabled'; Pe = 0; N443 = 'OPEN'; N3443 = 'CONTROL-PLANE'; HasNsg = $true; Gw = 'INTERNET*'; Mg = 'CONTROL-PLANE ONLY' }
        @{ Case = 'External with 3443 open: management on the internet'; Vnet = 'External'; Public = 'Enabled'; Pe = 0; N443 = 'OPEN'; N3443 = 'OPEN'; HasNsg = $true; Gw = 'INTERNET*'; Mg = 'INTERNET*' }
        @{ Case = 'External with a tight 443 and no 3443 allow'; Vnet = 'External'; Public = 'Enabled'; Pe = 0; N443 = 'TIGHT'; N3443 = 'NONE'; HasNsg = $true; Gw = 'TIGHT*'; Mg = 'PRIVATE (no inbound allow)' }
        @{ Case = 'Internal with the reference NSG: gateway private, management control plane only'; Vnet = 'Internal'; Public = 'Enabled'; Pe = 0; N443 = 'OPEN'; N3443 = 'CONTROL-PLANE'; HasNsg = $true; Gw = 'PRIVATE*'; Mg = 'CONTROL-PLANE ONLY' }
        @{ Case = 'Internal with 3443 open to the internet'; Vnet = 'Internal'; Public = 'Enabled'; Pe = 0; N443 = 'VNET'; N3443 = 'OPEN'; HasNsg = $true; Gw = 'PRIVATE*'; Mg = 'INTERNET*' }
        @{ Case = 'Internal without an NSG'; Vnet = 'Internal'; Public = 'Enabled'; Pe = 0; N443 = ''; N3443 = ''; HasNsg = $false; Gw = 'PRIVATE*'; Mg = 'INTERNET*' }
        @{ Case = 'External with a broad 3443'; Vnet = 'External'; Public = 'Enabled'; Pe = 0; N443 = 'OPEN'; N3443 = 'BROAD'; HasNsg = $true; Gw = 'INTERNET*'; Mg = 'BROAD*' }
    ) {
        $r = Get-ApimReach $Vnet $Public $Pe $N443 $N3443 $HasNsg
        $r.gateway | Should -BeLike $Gw
        $r.management | Should -BeLike $Mg
    }
    It 'maps reach text back to a class' {
        Get-ReachClass 'INTERNET (no NSG)' | Should -Be 'OPEN'; Get-ReachClass 'CONTROL-PLANE ONLY' | Should -Be 'CONTROL-PLANE'
        Get-ReachClass 'PRIVATE (x)' | Should -Be 'PRIVATE'; Get-ReachClass 'TIGHT' | Should -Be 'TIGHT'; Get-ReachClass '' | Should -Be 'UNKNOWN'
    }
}

Describe 'Global policy parsing' {
    It 'classifies ip-filter ranges: <From>-<To> is <Class>' -TestCases @(
        @{ From = '203.0.113.0'; To = '203.0.113.127'; Class = 'TIGHT' }, @{ From = '203.0.0.0'; To = '203.0.255.255'; Class = 'BROAD' }
        @{ From = '0.0.0.0'; To = '255.255.255.255'; Class = 'OPEN' }, @{ From = '10.0.0.0'; To = '10.255.255.255'; Class = 'PRIVATE' }
        @{ From = '@(context.Variables["a"])'; To = '203.0.113.9'; Class = 'UNKNOWN' }, @{ From = '203.0.113.9'; To = '203.0.113.1'; Class = 'UNKNOWN' }
    ) { Get-RangeClass $From $To | Should -Be $Class }
    It 'reads an allow ip-filter and an X-Azure-FDID check' {
        $xml = '<policies><inbound><ip-filter action="allow"><address>203.0.113.7</address><address-range from="203.0.113.0" to="203.0.113.63" /></ip-filter><check-header name="X-Azure-FDID" failed-check-httpcode="403" failed-check-error-message="Invalid request." ignore-case="false"><value>{{FrontDoorId}}</value></check-header><base /></inbound><backend><base /></backend><outbound><base /></outbound><on-error><base /></on-error></policies>'
        $c = Get-PolicyIngressControls $xml
        $c.parsed | Should -BeTrue; $c.ipFilterAction | Should -Be 'allow'; $c.ipFilterEntries | Should -Be 2; $c.ipFilterClass | Should -Be 'TIGHT'
        $c.fdidCheck | Should -BeTrue; $c.fdidConditional | Should -BeFalse; $c.ipFilterConditional | Should -BeFalse
    }
    It 'treats a forbid filter as a blocklist and notices conditional filters' {
        $c = Get-PolicyIngressControls '<policies><inbound><ip-filter action="forbid"><address>198.51.100.1</address></ip-filter></inbound></policies>'
        $c.ipFilterAction | Should -Be 'forbid'; $c.ipFilterClass | Should -Be ''
        $c2 = Get-PolicyIngressControls '<policies><inbound><choose><when condition="@(true)"><ip-filter action="allow"><address>203.0.113.7</address></ip-filter><check-header name="X-Azure-FDID" failed-check-httpcode="403" failed-check-error-message="x" ignore-case="false"><value>a</value></check-header></when></choose></inbound></policies>'
        $c2.ipFilterConditional | Should -BeTrue; $c2.fdidConditional | Should -BeTrue
    }
    It 'handles an empty policy, a default policy and broken XML' {
        (Get-PolicyIngressControls '').note | Should -Be 'empty policy'
        $c = Get-PolicyIngressControls '<policies><inbound><base /></inbound></policies>'
        $c.parsed | Should -BeTrue; $c.ipFilterAction | Should -Be ''; $c.fdidCheck | Should -BeFalse
        $b = Get-PolicyIngressControls '<policies><inbound>'
        $b.parsed | Should -BeFalse; $b.note | Should -Match 'could not be parsed'
    }
}

Describe 'WAF bypass and instance status' {
    It 'bypass: <Direct> direct, fdid=<Fdid>, policy=<Policy> gives <Expected>' -TestCases @(
        @{ Direct = 'OPEN'; Fdid = $false; Policy = ''; Expected = $true }, @{ Direct = 'OPEN'; Fdid = $true; Policy = ''; Expected = $false }
        @{ Direct = 'OPEN'; Fdid = $false; Policy = 'TIGHT'; Expected = $false }, @{ Direct = 'OPEN'; Fdid = $false; Policy = 'BROAD'; Expected = $true }
        @{ Direct = 'TIGHT'; Fdid = $false; Policy = ''; Expected = $false }, @{ Direct = 'AZURE-SHARED'; Fdid = $false; Policy = ''; Expected = $true }
        @{ Direct = 'BROAD'; Fdid = $false; Policy = ''; Expected = $true }
    ) { Test-WafBypass $Direct $Fdid $Policy | Should -Be $Expected }
    It 'status: <Case>' -TestCases @(
        @{ Case = 'open pathway without WAF is OPEN'; Rows = @((New-TestPathway 'OPEN')); Expected = 'OPEN' }
        @{ Case = 'open pathway behind a prevention WAF is FILTERED'; Rows = @((New-TestPathway 'OPEN' 'PREVENTION')); Expected = 'FILTERED' }
        @{ Case = 'open pathway behind a bypassable WAF is OPEN'; Rows = @((New-TestPathway 'OPEN' 'PREVENTION' $true)); Expected = 'OPEN' }
        @{ Case = 'open pathway behind a detection-only WAF is OPEN'; Rows = @((New-TestPathway 'OPEN' 'DETECTION ONLY')); Expected = 'OPEN' }
        @{ Case = 'open pathway behind a disabled WAF is OPEN'; Rows = @((New-TestPathway 'OPEN' 'WAF DISABLED')); Expected = 'OPEN' }
        @{ Case = 'broad plus control plane is BROAD'; Rows = @((New-TestPathway 'BROAD'), (New-TestPathway 'CONTROL-PLANE')); Expected = 'BROAD' }
        @{ Case = 'a shared Azure tag is BROAD'; Rows = @((New-TestPathway 'AZURE-SHARED')); Expected = 'BROAD' }
        @{ Case = 'tight only is FILTERED'; Rows = @((New-TestPathway 'TIGHT')); Expected = 'FILTERED' }
        @{ Case = 'control plane and VNet only is PRIVATE'; Rows = @((New-TestPathway 'CONTROL-PLANE'), (New-TestPathway 'VNET')); Expected = 'PRIVATE' }
        @{ Case = 'no pathways is PRIVATE'; Rows = @(); Expected = 'PRIVATE' }
    ) { Get-IngressStatus $Rows $false | Should -Be $Expected }
    It 'reports UNCHECKED first' { Get-IngressStatus @((New-TestPathway 'OPEN')) $true | Should -Be 'UNCHECKED' }
}

Describe 'Get-GatewayPatchStatus (NSM thresholds)' {
    It 'rates <Version> on a <Tier> tier as <Expected>' -TestCases @(
        @{ Version = '0.52.31936.0'; Tier = 'Classic'; Expected = 'patched*' }, @{ Version = '0.52.31935.0'; Tier = 'Classic'; Expected = 'NOT PATCHED*' }
        @{ Version = '0.53.31938.0'; Tier = 'Classic'; Expected = 'patched*' }, @{ Version = '0.53.31000.0'; Tier = 'Classic'; Expected = 'NOT PATCHED*' }
        @{ Version = '0.52.40000'; Tier = 'Classic'; Expected = 'patched*' }
        # NSM's own examples of the v2 / Consumption pattern: never NOT PATCHED, on a Classic SKU a case for Microsoft
        @{ Version = '0.53.4608.0'; Tier = 'Classic'; Expected = 'UNRECOGNISED*v2 / Consumption*' }
        @{ Version = '0.52.4150.0'; Tier = 'Classic'; Expected = 'UNRECOGNISED*v2 / Consumption*' }
        @{ Version = '0.53.4608.0'; Tier = 'Classic (Consumption)'; Expected = 'not applicable*' }
        @{ Version = '0.52.4150.0'; Tier = 'v2'; Expected = 'not applicable*' }
        @{ Version = ''; Tier = 'v2'; Expected = 'not applicable*' }
        @{ Version = '0.54.1.0'; Tier = 'Classic'; Expected = 'UNRECOGNISED*outside*' }
        @{ Version = '0.5.31936.0'; Tier = 'Classic'; Expected = 'UNRECOGNISED*' }
        @{ Version = '0.521.31936.0'; Tier = 'Classic'; Expected = 'UNRECOGNISED*' }
        @{ Version = '0.53.31938.0'; Tier = 'Unknown'; Expected = 'patched*' }
        @{ Version = ''; Tier = 'Classic'; Expected = 'unknown*' }
    ) { Get-GatewayPatchStatus $Version $Tier | Should -BeLike $Expected }
    It 'names the threshold a NOT PATCHED build needs' { Get-GatewayPatchStatus '0.53.31937.0' 'Classic' | Should -Be 'NOT PATCHED (0.53.31937.0; needs 0.53.31938 or later)' }
    It 'defaults to the Classic rule' { Get-GatewayPatchStatus '0.52.31935.0' | Should -BeLike 'NOT PATCHED*' }
}

Describe 'Invoke-Arm sends the token to Azure Resource Manager only' {
    BeforeAll {
        Mock Get-ArmToken { throw 'Get-ArmToken must not be called for a refused URL' }
        Mock Invoke-RestMethod { throw 'Invoke-RestMethod must not be called for a refused URL' }
    }
    It 'refuses <Url>' -TestCases @(
        @{ Url = 'https://attacker.example/subscriptions/x?api-version=1' }
        @{ Url = 'https://management.azure.com.attacker.example/x' }
        @{ Url = 'http://management.azure.com/x' }
        @{ Url = '/subscriptions/x' }
        @{ Url = '' }
    ) {
        $r = Invoke-Arm GET $Url
        $r.ok | Should -BeFalse
        $r.error | Should -BeLike 'refused:*'
        Should -Invoke Get-ArmToken -Times 0 -Exactly
        Should -Invoke Invoke-RestMethod -Times 0 -Exactly
    }
}

Describe 'Retrying throttled and dropped calls' {
    It 'waits as long as Retry-After asks on a 429 (<Case>)' -TestCases @(
        @{ Case = 'header as text'; Headers = @{ 'Retry-After' = '17' }; Expected = 17 }
        @{ Case = 'typed header'; Headers = [pscustomobject]@{ RetryAfter = [System.Net.Http.Headers.RetryConditionHeaderValue]::new([timespan]::FromSeconds(12)) }; Expected = 12 }
    ) {
        $ex = [pscustomobject]@{ Response = [pscustomobject]@{ Headers = $Headers } }
        Get-RetryDelay $ex 429 1 | Should -Be $Expected
    }
    It 'backs off long enough on a 429 without Retry-After to outlast a 30-second window' {
        $ex = [pscustomobject]@{ Response = $null }
        $total = 0; foreach ($t in 1..5) { $total += Get-RetryDelay $ex 429 $t }
        $total | Should -BeGreaterThan 60
        Get-RetryDelay $ex 429 6 | Should -BeNullOrEmpty
    }
    It 'retries a server error' { Get-RetryDelay ([System.Exception]::new('x')) 503 1 | Should -Be 2 }
    It 'retries a reset connection (no HTTP status)' {
        $ex = [System.Net.Http.HttpRequestException]::new('Unable to read data from the transport connection', [System.IO.IOException]::new('reset'))
        Get-RetryDelay $ex 0 1 | Should -Be 2
    }
    It 'does not retry <Case>' -TestCases @(
        @{ Case = 'a 403'; Code = 403; Ex = [System.Exception]::new('forbidden') }
        @{ Case = 'a 404'; Code = 404; Ex = [System.Exception]::new('not found') }
        @{ Case = 'a non-network failure without status'; Code = 0; Ex = [System.ArgumentException]::new('bad') }
    ) { Get-RetryDelay $Ex $Code 1 | Should -BeNullOrEmpty }
    It 'Invoke-Arm recovers from a dropped connection' {
        $script:calls = 0
        Mock Get-ArmToken { 'token' }
        Mock Start-Sleep { }
        Mock Invoke-RestMethod {
            $script:calls++
            if ($script:calls -eq 1) { throw [System.Net.Http.HttpRequestException]::new('Unable to read data from the transport connection', [System.IO.IOException]::new('reset')) }
            [pscustomobject]@{ value = @() }
        }
        $r = Invoke-Arm GET 'https://management.azure.com/subscriptions/s1/resourcegroups?api-version=2021-04-01'
        $r.ok | Should -BeTrue
        Should -Invoke Invoke-RestMethod -Times 2 -Exactly
        Should -Invoke Start-Sleep -Times 1 -Exactly
    }
}

Describe 'Gateway probe targets and the per-instance patch summary' {
    It 'probes only the default hostname of a single-region instance' {
        $t = @(Get-GatewayProbeTargets ([pscustomobject]@{ name = 'apim-one'; location = 'westeurope'; additionalLocations = @(); gatewayRegionalUrl = 'https://apim-one-westeurope-01.regional.azure-api.net' }))
        $t.Count | Should -Be 1
        $t[0].host | Should -Be 'apim-one.azure-api.net'
    }
    It 'adds every regional gateway of a multi-region instance and keeps disabled regions unprobed' {
        $apim = [pscustomobject]@{ name = 'apim-multi'; location = 'westeurope'; gatewayRegionalUrl = 'https://apim-multi-westeurope-01.regional.azure-api.net'; disableGateway = 'false'
            additionalLocations = @(
                [pscustomobject]@{ location = 'northeurope'; gatewayRegionalUrl = 'https://apim-multi-northeurope-01.regional.azure-api.net'; disableGateway = $false }
                [pscustomobject]@{ location = 'swedencentral'; gatewayRegionalUrl = 'https://apim-multi-swedencentral-01.regional.azure-api.net'; disableGateway = $true }
            ) }
        $t = @(Get-GatewayProbeTargets $apim)
        $t.Count | Should -Be 4
        $t.host | Should -Contain 'apim-multi.azure-api.net'
        $t.host | Should -Contain 'apim-multi-westeurope-01.regional.azure-api.net'
        $t.host | Should -Contain 'apim-multi-northeurope-01.regional.azure-api.net'
        ($t | Where-Object region -eq 'swedencentral').disabled | Should -BeTrue
        ($t | Where-Object region -eq 'northeurope').disabled | Should -BeFalse
        ($t | Where-Object region -eq 'westeurope').disabled | Should -BeFalse
    }
    It 'reads additional locations from Resource Graph JSON text' {
        $apim = [pscustomobject]@{ name = 'apim-json'; location = 'westeurope'; gatewayRegionalUrl = 'https://apim-json-westeurope-01.regional.azure-api.net'
            additionalLocations = '[{"location":"northeurope","gatewayRegionalUrl":"https://apim-json-northeurope-01.regional.azure-api.net","disableGateway":false}]' }
        @(Get-GatewayProbeTargets $apim).Count | Should -Be 3
    }
    It 'summarises <Case>' -TestCases @(
        @{ Case = 'all patched'; In = @('patched (0.52.31936.0)', 'patched (0.52.31940.0)'); Expected = 'patched (all 2 gateway(s))' }
        @{ Case = 'one region behind'; In = @('patched (0.52.31936.0)', 'NOT PATCHED (0.52.31000.0; needs 0.52.31936 or later)'); Expected = 'NOT PATCHED in 1 of 2 gateway(s)*' }
        @{ Case = 'one region unreadable'; In = @('patched (0.52.31936.0)', 'unknown (status endpoint not reachable from here: x)'); Expected = 'unknown in 1 of 2 gateway(s)*' }
        @{ Case = 'an unrecognised build'; In = @('patched (0.52.31936.0)', 'UNRECOGNISED (0.54.1.0): x'); Expected = 'UNRECOGNISED in 1 of 2*' }
        @{ Case = 'a disabled region'; In = @('patched (0.52.31936.0)', 'not probed (gateway disabled in this region)'); Expected = 'patched (all 1 gateway(s))' }
        @{ Case = 'a v2 instance'; In = @('not applicable (v2 tier: not vulnerable per NSM)'); Expected = 'not applicable*' }
    ) { Get-PatchSummary $In | Should -BeLike $Expected }
    It 'never calls unprobed gateways patched' { Get-PatchSummary @('not probed (gateway disabled in this region)') | Should -BeLike 'not probed*' }
}

Describe 'Change history (Activity Log)' {
    BeforeAll {
        $script:apimId = '/subscriptions/s1/resourceGroups/rg-apim/providers/Microsoft.ApiManagement/service/apim-a'
        $script:nsgId = '/subscriptions/s1/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/nsg-apim'
        $script:watch = @($script:nsgId, '/subscriptions/s1/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet/subnets/snet-apim')
        function New-Event([string]$Op, [string]$ResourceId, [string]$Status = 'Succeeded') {
            [pscustomobject]@{ operationName = [pscustomobject]@{ value = $Op }; status = [pscustomobject]@{ value = $Status }; resourceId = $ResourceId; eventTimestamp = '2026-11-20T10:00:00Z' }
        }
    }
    It 'counts <Case>' -TestCases @(
        @{ Case = 'an NSG rule change (child of the NSG, different case)'; Op = 'Microsoft.Network/networkSecurityGroups/securityRules/write'; Rid = '/SUBSCRIPTIONS/s1/resourceGroups/RG-NET/providers/Microsoft.Network/networkSecurityGroups/nsg-apim/securityRules/AllowMgmt' }
        @{ Case = 'an NSG rule deletion'; Op = 'Microsoft.Network/networkSecurityGroups/securityRules/delete'; Rid = '/subscriptions/s1/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/nsg-apim/securityRules/AllowAll' }
        @{ Case = 'a subnet change (NSG association)'; Op = 'Microsoft.Network/virtualNetworks/subnets/write'; Rid = '/subscriptions/s1/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet/subnets/snet-apim' }
        @{ Case = 'a service update (VNet mode, public access)'; Op = 'Microsoft.ApiManagement/service/write'; Rid = '/subscriptions/s1/resourceGroups/rg-apim/providers/Microsoft.ApiManagement/service/apim-a' }
        @{ Case = 'the global policy'; Op = 'Microsoft.ApiManagement/service/policies/write'; Rid = '/subscriptions/s1/resourceGroups/rg-apim/providers/Microsoft.ApiManagement/service/apim-a/policies/policy' }
        @{ Case = 'tenant access (direct management API)'; Op = 'Microsoft.ApiManagement/service/tenant/write'; Rid = '/subscriptions/s1/resourceGroups/rg-apim/providers/Microsoft.ApiManagement/service/apim-a/tenant/access' }
        @{ Case = 'a private endpoint connection'; Op = 'Microsoft.ApiManagement/service/privateEndpointConnections/write'; Rid = '/subscriptions/s1/resourceGroups/rg-apim/providers/Microsoft.ApiManagement/service/apim-a/privateEndpointConnections/pe1' }
        @{ Case = 'applying a network configuration update'; Op = 'Microsoft.ApiManagement/service/applynetworkconfigurationupdates/action'; Rid = '/subscriptions/s1/resourceGroups/rg-apim/providers/Microsoft.ApiManagement/service/apim-a' }
        @{ Case = 'an APIM change record of a service update (capitals, service as resourceId)'; Op = 'MICROSOFT.APIMANAGEMENT/SERVICE/WRITE'; Rid = '/subscriptions/s1/resourceGroups/rg-apim/providers/Microsoft.ApiManagement/service/apim-a' }
        @{ Case = 'an APIM change record of the global policy'; Op = 'MICROSOFT.APIMANAGEMENT/SERVICE/POLICIES/WRITE'; Rid = '/subscriptions/s1/resourceGroups/rg-apim/providers/Microsoft.ApiManagement/service/apim-a' }
    ) { Test-IngressChange (New-Event $Op $Rid) $script:apimId $script:watch | Should -BeTrue }
    # APIM's own change records name the service as resourceId whatever was changed, so these must be told apart by operation
    It 'ignores the APIM change record of <Case>' -TestCases @(
        @{ Case = 'a subscription write'; Op = 'MICROSOFT.APIMANAGEMENT/SERVICE/SUBSCRIPTIONS/WRITE' }
        @{ Case = 'a named-value deletion'; Op = 'MICROSOFT.APIMANAGEMENT/SERVICE/NAMEDVALUES/DELETE' }
        @{ Case = 'an operation policy'; Op = 'MICROSOFT.APIMANAGEMENT/SERVICE/APIS/OPERATIONS/POLICIES/WRITE' }
        @{ Case = 'an API policy'; Op = 'MICROSOFT.APIMANAGEMENT/SERVICE/APIS/POLICIES/WRITE' }
        @{ Case = 'a product-API link'; Op = 'MICROSOFT.APIMANAGEMENT/SERVICE/PRODUCTS/APIS/WRITE' }
        @{ Case = 'a policy fragment'; Op = 'MICROSOFT.APIMANAGEMENT/SERVICE/POLICYFRAGMENTS/WRITE' }
        @{ Case = 'a user deletion'; Op = 'MICROSOFT.APIMANAGEMENT/SERVICE/USERS/DELETE' }
    ) { Test-IngressChange (New-Event $Op $script:apimId) $script:apimId $script:watch | Should -BeFalse }
    It 'counts a change recorded by both Resource Manager and APIM once, keeping the record with a caller' {
        $arm = New-Event 'Microsoft.ApiManagement/service/policies/write' "$($script:apimId)/policies/policy"
        $arm | Add-Member correlationId 'c1'; $arm | Add-Member caller 'admin@contoso.test'
        $own = New-Event 'MICROSOFT.APIMANAGEMENT/SERVICE/POLICIES/WRITE' $script:apimId.ToUpperInvariant()
        $own | Add-Member correlationId 'C1'; $own | Add-Member caller ''
        $other = New-Event 'MICROSOFT.APIMANAGEMENT/SERVICE/WRITE' $script:apimId
        $other | Add-Member correlationId 'c1'; $other | Add-Member caller ''
        $noId = New-Event 'MICROSOFT.APIMANAGEMENT/SERVICE/WRITE' $script:apimId
        $noId | Add-Member correlationId ''; $noId | Add-Member caller ''
        $u = @(Select-UniqueChange @($own, $arm, $other, $noId))
        $u.Count | Should -Be 3
        ($u | Where-Object { $_.operationName.value -like '*policies*' }).caller | Should -Be 'admin@contoso.test'
    }
    It 'ignores a role assignment on the instance' {
        Test-IngressChange (New-Event 'Microsoft.Authorization/roleAssignments/write' "$($script:apimId)/providers/Microsoft.Authorization/roleAssignments/r1") $script:apimId $script:watch | Should -BeFalse
    }
    It 'ignores <Case>' -TestCases @(
        @{ Case = 'an API deployment'; Op = 'Microsoft.ApiManagement/service/apis/write'; Rid = '/subscriptions/s1/resourceGroups/rg-apim/providers/Microsoft.ApiManagement/service/apim-a/apis/orders'; Status = 'Succeeded' }
        @{ Case = 'an API-level policy'; Op = 'Microsoft.ApiManagement/service/apis/policies/write'; Rid = '/subscriptions/s1/resourceGroups/rg-apim/providers/Microsoft.ApiManagement/service/apim-a/apis/orders/policies/policy'; Status = 'Succeeded' }
        @{ Case = 'the Started event of a write'; Op = 'Microsoft.Network/networkSecurityGroups/securityRules/write'; Rid = '/subscriptions/s1/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/nsg-apim/securityRules/x'; Status = 'Started' }
        @{ Case = 'a failed write'; Op = 'Microsoft.Network/networkSecurityGroups/write'; Rid = '/subscriptions/s1/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/nsg-apim'; Status = 'Failed' }
        @{ Case = 'a read-type action'; Op = 'Microsoft.ApiManagement/service/tenant/listSecrets/action'; Rid = '/subscriptions/s1/resourceGroups/rg-apim/providers/Microsoft.ApiManagement/service/apim-a/tenant/access'; Status = 'Succeeded' }
        @{ Case = 'another NSG whose name starts the same'; Op = 'Microsoft.Network/networkSecurityGroups/write'; Rid = '/subscriptions/s1/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/nsg-apim-test'; Status = 'Succeeded' }
        @{ Case = 'another instance whose name starts the same'; Op = 'Microsoft.ApiManagement/service/write'; Rid = '/subscriptions/s1/resourceGroups/rg-apim/providers/Microsoft.ApiManagement/service/apim-ab'; Status = 'Succeeded' }
    ) { Test-IngressChange (New-Event $Op $Rid $Status) $script:apimId $script:watch | Should -BeFalse }
    It 'builds one encoded Activity Log query per resource group' {
        $u = Get-ActivityLogUrl 's1' 'rg-net' ([datetime]::new(2026, 11, 1, 0, 0, 0, 'Utc')) ([datetime]::new(2026, 11, 26, 8, 30, 0, 'Utc'))
        $u | Should -BeLike 'https://management.azure.com/subscriptions/s1/providers/Microsoft.Insights/eventtypes/management/values?api-version=2015-04-01&$filter=*'
        $u | Should -Not -Match ' '
        [uri]::UnescapeDataString($u) | Should -Match "eventTimestamp ge '2026-11-01T00:00:00Z' and eventTimestamp le '2026-11-26T08:30:00Z' and resourceGroupName eq 'rg-net'"
    }
    It 'keys resource groups by subscription, case-insensitively' {
        Get-ResourceGroupKey '/subscriptions/S1/resourceGroups/RG-Net/providers/x/y/z' | Should -Be 's1|rg-net'
        Get-ResourceGroupKey 'not-an-id' | Should -Be ''
    }
    It 'formats timestamps as sortable UTC text' {
        Format-EventTime ([datetime]::new(2026, 11, 20, 10, 0, 0, 'Utc')) | Should -Be '2026-11-20T10:00:00Z'
        Format-EventTime '2026-11-20T10:00:00Z' | Should -Be '2026-11-20T10:00:00Z'
    }
}

Describe 'Deny shadowing needs full destination cover and all source ports' {
    It 'does not let a deny aimed at one host shadow the allow for the subnet' {
        $rules = Get-NsgRules (New-Nsg 'n' @((New-Rule 'DenyJumpbox' 100 'Deny' 'Internet' '3443' 'Tcp' 'Inbound' '10.0.1.9/32'), (New-Rule 'AllowAll' 200 'Allow' 'Internet' '3443')))
        $rows = @(Get-NsgPortExposure $rules 3443 24 48 @('10.0.1.0/24'))
        ($rows | Where-Object rule -eq 'AllowAll').effective | Should -BeTrue
        ($rows | Where-Object rule -eq 'AllowAll').partiallyDeniedBy | Should -Match 'DenyJumpbox'
        Get-PortExposureClass $rows | Should -Be 'OPEN'
    }
    It 'lets a deny that covers the whole subnet shadow the allow' {
        $rules = Get-NsgRules (New-Nsg 'n' @((New-Rule 'DenySubnet' 100 'Deny' 'Internet' '3443' 'Tcp' 'Inbound' '10.0.1.0/24'), (New-Rule 'AllowAll' 200 'Allow' 'Internet' '3443')))
        (@(Get-NsgPortExposure $rules 3443 24 48 @('10.0.1.0/24')) | Where-Object rule -eq 'AllowAll').effective | Should -BeFalse
    }
    It 'needs every prefix of a multi-prefix subnet covered' {
        $one = Get-NsgRules (New-Nsg 'n' @((New-Rule 'DenyOne' 100 'Deny' '*' '3443' 'Tcp' 'Inbound' '10.0.2.0/24'), (New-Rule 'AllowAll' 200 'Allow' 'Internet' '3443')))
        Get-PortExposureClass (Get-NsgPortExposure $one 3443 24 48 @('10.0.1.0/24', '10.0.2.0/24')) | Should -Be 'OPEN'
        $both = Get-NsgRules (New-Nsg 'n' @((New-Rule 'DenyBoth' 100 'Deny' '*' '3443' 'Tcp' 'Inbound' @('10.0.1.0/24', '10.0.2.0/24')), (New-Rule 'AllowAll' 200 'Allow' 'Internet' '3443')))
        Get-PortExposureClass (Get-NsgPortExposure $both 3443 24 48 @('10.0.1.0/24', '10.0.2.0/24')) | Should -Be 'NONE'
    }
    It 'does not let a deny limited to a source port shadow the allow' {
        $rules = Get-NsgRules (New-Nsg 'n' @((New-Rule 'DenyFromPort' 100 'Deny' '*' '3443' 'Tcp' 'Inbound' '*' '1024'), (New-Rule 'AllowAll' 200 'Allow' 'Internet' '3443')))
        $row = @(Get-NsgPortExposure $rules 3443) | Where-Object rule -eq 'AllowAll'
        $row.effective | Should -BeTrue
        $row.partiallyDeniedBy | Should -Match 'source ports'
    }
    It 'lets a base service tag deny shadow a regional allow, and treats sibling tags as partial' {
        Get-SourceRelation 'ApiManagement' 'ApiManagement.WestEurope' | Should -Be 'covers'
        Get-SourceRelation 'ApiManagement.WestEurope' 'ApiManagement' | Should -Be 'overlaps'
        Get-SourceRelation 'AzureFrontDoor.Backend' 'AzureFrontDoor.Frontend' | Should -Be 'overlaps'
        Get-SourceRelation 'Storage' 'Sql' | Should -Be 'none'
    }
    It 'lists another control-plane tag on 3443 for review' { Get-ApimRuleAssessment 3443 'CONTROL-PLANE' 'AzureLoadBalancer' 'External' | Should -Match 'confirm' }
}

Describe 'WAF verdicts that block nothing' {
    It 'marks a prevention policy without managed rule sets or blocking rules' {
        $p = New-FdPolicy 'Prevention'; $p.properties.managedRules.managedRuleSets = @()
        (Get-WafAssessment $p 'FrontDoor').verdict | Should -Be 'PREVENTION (no blocking rules)'
        $p2 = New-FdPolicy 'Prevention' 'Enabled' @((New-FdRule 'office-only' 1 'Block' 'SocketAddr' 'IPMatch' @('203.0.113.0/27') $true)); $p2.properties.managedRules.managedRuleSets = @()
        (Get-WafAssessment $p2 'FrontDoor').verdict | Should -Be 'PREVENTION'
    }
    It 'marks a prevention policy whose custom allow admits everyone' {
        (Get-WafAssessment (New-AgwPolicy 'Prevention' 'Enabled' @((New-AgwRule 'allow-everyone' 10 'Allow' 'RemoteAddr' 'IPMatch' @('0.0.0.0/0')))) 'AppGateway').verdict | Should -Be 'PREVENTION (custom allow admits everyone)'
        (Get-WafAssessment (New-AgwPolicy 'Prevention' 'Enabled' @((New-AgwRule 'allow-any' 10 'Allow' 'RequestUri' 'Any' @()))) 'AppGateway').verdict | Should -Be 'PREVENTION (custom allow admits everyone)'
        (Get-WafAssessment (New-AgwPolicy 'Prevention' 'Enabled' @((New-AgwRule 'allow-health' 10 'Allow' 'RequestUri' 'Contains' @('/health')))) 'AppGateway').verdict | Should -Be 'PREVENTION'
    }
    It 'does not treat those verdicts as mitigating, and keeps a tight pathway behind a real WAF FILTERED' {
        Get-IngressStatus @((New-TestPathway 'OPEN' 'PREVENTION (no blocking rules)')) $false | Should -Be 'OPEN'
        Get-IngressStatus @((New-TestPathway 'TIGHT' 'PREVENTION')) $false | Should -Be 'FILTERED'
    }
    It 'counts a legacy rule group without a rule list as a disabled group' {
        $gw = [pscustomobject]@{ id = '/s/rg/agw'; name = 'agw'; properties = [pscustomobject]@{ webApplicationFirewallConfiguration = [pscustomobject]@{ enabled = $true; firewallMode = 'Prevention'; ruleSetType = 'OWASP'; ruleSetVersion = '3.2'; disabledRuleGroups = @([pscustomobject]@{ ruleGroupName = 'x' }) } } }
        $a = Get-LegacyWafAssessment $gw
        $a.disabledRules | Should -Be 0; $a.disabledRuleGroups | Should -Be 1
    }
}

Describe 'Ranges, bypass and tables' {
    It 'does not call a range PRIVATE when it spans public space' { Get-RangeClass '10.255.255.0' '11.0.0.255' | Should -Be 'BROAD'; Get-RangeClass '10.0.0.0' '192.168.0.0' | Should -Not -Be 'PRIVATE'; Get-RangeClass '10.0.0.1' '10.0.0.200' | Should -Be 'PRIVATE' }
    It 'treats an NSG that admits any Front Door as bypassable' { Test-WafBypass 'AZURE-SHARED' $false '' | Should -BeTrue }
    It 'prints _None._ for an empty or null table' { ConvertTo-MdTable $null @('a') | Should -Be '_None._'; ConvertTo-MdTable @() @('a') | Should -Be '_None._' }
}
