#Requires -Version 7
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
Offline tests for the scope and status decisions in Check-ApimExposure.ps1. No Azure access needed.
The functions are loaded from the script itself, so the script stays a single standalone file.

Run:  Invoke-Pester ./tests
#>

BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot '../Check-ApimExposure.ps1'
    $ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $scriptPath), [ref]$null, [ref]$null)
    $wanted = 'Get-ResourceName', 'Get-TierFamily', 'New-ImpactedList', 'Add-Impacted', 'Get-ScopeDecision', 'Get-InstanceStatus'
    $defs = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $args[0].Name -in $wanted }, $true)
    foreach ($d in $defs) { . ([scriptblock]::Create($d.Extent.Text)) }

    function New-Instance([string]$Name, [string]$Sku, [string]$Platform = 'stv2.1', [string]$Sub = '00000000-0000-0000-0000-000000000001') {
        [pscustomobject]@{
            id = "/subscriptions/$Sub/resourceGroups/rg-test/providers/Microsoft.ApiManagement/service/$Name"
            name = $Name; sku = $Sku; platformVersion = $Platform
        }
    }
}

Describe 'Function loading' {
    It 'finds every function under test in Check-ApimExposure.ps1' {
        foreach ($n in 'Get-ResourceName', 'Get-TierFamily', 'New-ImpactedList', 'Add-Impacted', 'Get-ScopeDecision', 'Get-InstanceStatus') {
            Get-Command $n -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty -Because "$n must exist"
        }
    }
}

Describe 'Get-TierFamily' {
    It 'maps <Sku> to <Family>' -TestCases @(
        @{ Sku = 'Developer'; Family = 'Classic' }
        @{ Sku = 'Basic'; Family = 'Classic' }
        @{ Sku = 'Standard'; Family = 'Classic' }
        @{ Sku = 'Premium'; Family = 'Classic' }
        @{ Sku = 'Isolated'; Family = 'Classic' }
        @{ Sku = 'Consumption'; Family = 'Classic (Consumption)' }
        @{ Sku = 'BasicV2'; Family = 'v2' }
        @{ Sku = 'StandardV2'; Family = 'v2' }
        @{ Sku = 'PremiumV2'; Family = 'v2' }
    ) {
        Get-TierFamily $Sku | Should -Be $Family
    }
}

Describe 'Get-ScopeDecision without a Microsoft list (tier rule)' {
    It 'puts a Classic dedicated tier on platform stv2.1 in scope (stv2.1 is not the v2 tier)' {
        $d = Get-ScopeDecision (New-Instance 'apim-std' 'Standard' 'stv2.1') $null
        $d.inScope | Should -BeTrue
        $d.tierFamily | Should -Be 'Classic'
        $d.reason | Should -Match 'Classic dedicated tier \(platform stv2\.1\)'
    }
    It 'puts a Classic dedicated tier on platform stv1 in scope' {
        (Get-ScopeDecision (New-Instance 'apim-old' 'Premium' 'stv1') $null).inScope | Should -BeTrue
    }
    It 'keeps the v2 tier <Sku> out of scope' -TestCases @(
        @{ Sku = 'BasicV2' }, @{ Sku = 'StandardV2' }, @{ Sku = 'PremiumV2' }
    ) {
        $d = Get-ScopeDecision (New-Instance 'apim-v2' $Sku 'stv2.1') $null
        $d.inScope | Should -BeFalse
        $d.tierFamily | Should -Be 'v2'
        $d.reason | Should -Match 'v2 tier'
    }
    It 'keeps Consumption out of scope by default' {
        (Get-ScopeDecision (New-Instance 'apim-cons' 'Consumption' 'mtv1') $null).inScope | Should -BeFalse
    }
    It 'includes Consumption with -IncludeConsumption' {
        (Get-ScopeDecision (New-Instance 'apim-cons' 'Consumption' 'mtv1') $null -IncludeConsumption).inScope | Should -BeTrue
    }
}

Describe 'Get-ScopeDecision with a Microsoft list' {
    BeforeEach {
        $classic = New-Instance 'apim-classic' 'Standard'
        $migrated = New-Instance 'apim-migrated' 'StandardV2'
        $other = New-Instance 'apim-other' 'Basic'
        $list = New-ImpactedList
    }
    It 'matches on full resource ID, case-insensitive and ignoring a trailing slash' {
        Add-Impacted $list ($classic.id.ToUpper() + '/') ''
        (Get-ScopeDecision $classic $list).reason | Should -Be 'listed by Microsoft'
    }
    It 'falls back to the name when the list has no resource ID' {
        Add-Impacted $list '' 'apim-classic'
        (Get-ScopeDecision $classic $list).inScope | Should -BeTrue
    }
    It 'does not match a listed resource ID in another subscription' {
        Add-Impacted $list ($classic.id -replace '0001/', '0002/') ''
        (Get-ScopeDecision $classic $list).inScope | Should -BeFalse
    }
    It 'keeps a Classic instance that Microsoft did not list out of scope' {
        Add-Impacted $list $classic.id ''
        $d = Get-ScopeDecision $other $list
        $d.inScope | Should -BeFalse
        $d.reason | Should -Be 'not listed by Microsoft'
    }
    It 'keeps a listed v2 instance in scope but flags it as migrated' {
        Add-Impacted $list $migrated.id ''
        $d = Get-ScopeDecision $migrated $list
        $d.inScope | Should -BeTrue
        $d.tierFamily | Should -Be 'v2'
        $d.reason | Should -Match 'now a v2 tier'
    }
    It 'keeps an unlisted v2 instance out of scope' {
        Add-Impacted $list $classic.id ''
        (Get-ScopeDecision $migrated $list).inScope | Should -BeFalse
    }
}

Describe 'Add-Impacted' {
    It 'stores a non-ARM value as a name, not as an ID' {
        $l = New-ImpactedList
        Add-Impacted $l 'not-an-arm-id' 'apim-x'
        $l.ids.Count | Should -Be 0
        $l.names.Contains('apim-x') | Should -BeTrue
    }
}

Describe 'Get-InstanceStatus' {
    It 'never rates a v2-tier instance LIKELY EXPOSED' {
        Get-InstanceStatus -TierFamily 'v2' -NoNetwork -SecretsHeld | Should -Be 'REVIEW (v2 tier)'
    }
    It 'rates a Classic instance without network integration LIKELY EXPOSED' {
        Get-InstanceStatus -TierFamily 'Classic' -NoNetwork | Should -Be 'LIKELY EXPOSED'
    }
    It 'rates a Classic instance with secrets held by APIM LIKELY EXPOSED' {
        Get-InstanceStatus -TierFamily 'Classic' -SecretsHeld | Should -Be 'LIKELY EXPOSED'
    }
    It 'rates a network-integrated Classic instance without APIM-held secrets REVIEW' {
        Get-InstanceStatus -TierFamily 'Classic' | Should -Be 'REVIEW'
    }
    It 'reports UNCHECKED first when objects could not be read' {
        Get-InstanceStatus -Unchecked -TierFamily 'v2' -NoNetwork | Should -Be 'UNCHECKED'
    }
}
