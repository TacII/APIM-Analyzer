#Requires -Version 7
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    . (Join-Path $PSScriptRoot '..\Apim-Helpers.ps1')
    function az { throw 'Unmocked Azure CLI call in offline tests' }
}

Describe 'Explicit SKU handling' {
    It 'classifies and scopes <Sku> consistently' -TestCases @(
        @{ Sku = 'Developer'; Family = 'Classic'; InScope = $true }
        @{ Sku = 'Basic'; Family = 'Classic'; InScope = $true }
        @{ Sku = 'Standard'; Family = 'Classic'; InScope = $true }
        @{ Sku = 'Premium'; Family = 'Classic'; InScope = $true }
        @{ Sku = 'Isolated'; Family = 'Classic'; InScope = $true }
        @{ Sku = 'Consumption'; Family = 'Classic (Consumption)'; InScope = $false }
        @{ Sku = 'BasicV2'; Family = 'v2'; InScope = $false }
        @{ Sku = 'StandardV2'; Family = 'v2'; InScope = $false }
        @{ Sku = 'PremiumV2'; Family = 'v2'; InScope = $false }
        @{ Sku = ' standardv2 '; Family = 'v2'; InScope = $false }
        @{ Sku = ' cOnSuMpTiOn '; Family = 'Classic (Consumption)'; InScope = $false }
    ) {
        $instance = [pscustomobject]@{ id = '/subscriptions/test/service/apim'; name = 'apim'; sku = $Sku }
        Get-TierFamily $Sku | Should -Be $Family
        $decision = Get-ScopeDecision $instance $null
        $decision.inScope | Should -Be $InScope
        @(Select-ApimInstance @($instance) '').Count | Should -Be ([int]$InScope)
        @(Select-ApimInstance @($instance) '' -IncludeConsumption).Count | Should -Be ([int]($InScope -or $Family -eq 'Classic (Consumption)'))
    }

    It 'retains unknown SKU <Sku> for review and warns instead of guessing its family' -TestCases @(
        @{ Sku = 'FutureV2' }, @{ Sku = 'PremiumV3' }, @{ Sku = '' }, @{ Sku = $null }, @{ Sku = ' ' }
    ) {
        Mock Write-Warning {}
        $instance = [pscustomobject]@{ id = '/subscriptions/test/service/apim'; name = 'apim'; sku = $Sku }
        Get-TierFamily $Sku | Should -Be 'Unknown'
        $decision = Get-ScopeDecision $instance (New-ImpactedList)
        $decision.inScope | Should -BeTrue
        $decision.tierFamily | Should -Be 'Unknown'
        $decision.reason | Should -Match 'scope cannot be determined'
        Should -Invoke Write-Warning -Times 1 -Exactly
    }
}

Describe 'Scope CSV validation' {
    BeforeEach {
        $instance = [pscustomobject]@{ id = '/subscriptions/test/service/apim'; name = 'apim'; sku = 'Standard' }
        $scopePath = Join-Path $TestDrive 'scope.csv'
    }

    It 'uses case-insensitive IDs and explicit False values' {
        [pscustomobject]@{ id = ($instance.id.ToUpper() + '/'); inScope = 'False' } | Export-Csv $scopePath
        @(Select-ApimInstance @($instance) $scopePath).Count | Should -Be 0
    }

    It 'preserves a Microsoft-listed v2 instance' {
        $instance.sku = 'PremiumV2'
        [pscustomobject]@{ id = $instance.id; inScope = 'True' } | Export-Csv $scopePath
        @(Select-ApimInstance @($instance) $scopePath).Count | Should -Be 1
    }

    It 'does not let an old scope decision conceal an unknown SKU' {
        Mock Write-Warning {}
        $instance.sku = 'NewSku'
        [pscustomobject]@{ id = $instance.id; inScope = 'False' } | Export-Csv $scopePath
        @(Select-ApimInstance @($instance) $scopePath).Count | Should -Be 1
        Should -Invoke Write-Warning -Times 1 -Exactly
    }

    It 'rejects malformed or missing scope columns' {
        [pscustomobject]@{ name = 'apim'; scope = 'yes' } | Export-Csv $scopePath
        { Select-ApimInstance @($instance) $scopePath } | Should -Throw '*id and inScope*'
    }

    It 'rejects unrecognized boolean values' {
        [pscustomobject]@{ id = $instance.id; inScope = 'maybe' } | Export-Csv $scopePath
        { Select-ApimInstance @($instance) $scopePath } | Should -Throw '*Expected True or False*'
    }

    It 'rejects duplicate IDs even if their case differs' {
        @(
            [pscustomobject]@{ id = $instance.id; inScope = 'True' }
            [pscustomobject]@{ id = $instance.id.ToUpper(); inScope = 'False' }
        ) | Export-Csv $scopePath
        { Select-ApimInstance @($instance) $scopePath } | Should -Throw '*Duplicate resource ID*'
    }

    It 'warns about new resources missing from a scope file and applies the fallback' {
        Mock Write-Warning {}
        [pscustomobject]@{ id = '/subscriptions/test/service/old'; inScope = 'False' } | Export-Csv $scopePath
        @(Select-ApimInstance @($instance) $scopePath).Count | Should -Be 1
        Should -Invoke Write-Warning -Times 1 -Exactly -ParameterFilter { $Message -like '*missing from*' }
    }

    It 'rejects an empty scope file when inventory contains resources' {
        Set-Content $scopePath ''
        { Select-ApimInstance @($instance) $scopePath } | Should -Throw '*Scope file is empty*'
    }
}

Describe 'Strict boolean conversion' {
    It 'accepts <Value> as <Expected>' -TestCases @(
        @{ Value = $true; Expected = $true }, @{ Value = $false; Expected = $false }
        @{ Value = ' True '; Expected = $true }, @{ Value = 'false'; Expected = $false }
    ) {
        ConvertTo-ReportBoolean $Value 'test flag' | Should -Be $Expected
    }

    It 'rejects <Value> instead of coercing it to a boolean' -TestCases @(
        @{ Value = 'enabled' }, @{ Value = 1 }, @{ Value = '' }, @{ Value = $null }
    ) {
        { ConvertTo-ReportBoolean $Value 'test flag' } | Should -Throw '*Expected True or False for test flag*'
    }
}

Describe 'Managed identity validation' {
    It 'handles no identity and type None' {
        @(Get-PrincipalIds $null).Count | Should -Be 0
        @(Get-PrincipalIds '{"type":"None"}').Count | Should -Be 0
    }

    It 'combines and deduplicates system and user-assigned principal IDs' {
        $identity = '{"type":"SystemAssigned, UserAssigned","principalId":"AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA","userAssignedIdentities":{"/identity/a":{"principalId":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"},"/identity/b":{"principalId":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"}}}'
        $ids = @(Get-PrincipalIds $identity)
        $ids.Count | Should -Be 2
        $ids | Should -Contain 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        $ids | Should -Contain 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
    }

    It 'supports user-assigned-only identities' {
        @(Get-PrincipalIds '{"type":"UserAssigned","userAssignedIdentities":{"/identity/a":{"principalId":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}}}').Count | Should -Be 1
    }

    It 'rejects identity shape <Identity>' -TestCases @(
        @{ Identity = '{"type":"Other"}' }
        @{ Identity = '{"type":"SystemAssigned"}' }
        @{ Identity = '{"type":"UserAssigned","userAssignedIdentities":{}}' }
        @{ Identity = '{"type":"UserAssigned","userAssignedIdentities":{"/identity/a":{}}}' }
        @{ Identity = '{"type":"SystemAssigned","principalId":"not-a-guid"}' }
        @{ Identity = 'not-json' }
    ) {
        { Get-PrincipalIds $Identity } | Should -Throw
    }
}

Describe 'CLI failure handling' {
    BeforeEach { $previousExitCode = $global:LASTEXITCODE }
    AfterEach { $global:LASTEXITCODE = $previousExitCode }

    It 'checks exit status before accepting valid-looking JSON' {
        Mock az { $global:LASTEXITCODE = 7; '[]' }
        { Invoke-AzJson @('account', 'list') } | Should -Throw '*exit 7*'
    }

    It 'rejects invalid JSON' {
        Mock az { $global:LASTEXITCODE = 0; 'bad-json' }
        { Invoke-AzJson @('account', 'list') } | Should -Throw '*invalid JSON*'
    }

    It 'rejects an empty subscription list' {
        Mock az { $global:LASTEXITCODE = 0; '[]' }
        { Get-EnabledSubscription } | Should -Throw '*No enabled subscriptions*'
    }

    It 'preserves single-element JSON arrays and returns a subscription ID' {
        Mock az { $global:LASTEXITCODE = 0; '[{"id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","state":"Enabled"}]' }
        @(Get-EnabledSubscription) | Should -Be @('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa')
    }

    It 'warns when a subscription has an unrecognized state' {
        Mock Write-Warning {}
        Mock az { $global:LASTEXITCODE = 0; '[{"id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","state":"Enabled"},{"id":"other","state":"Unexpected"}]' }
        @(Get-EnabledSubscription).Count | Should -Be 1
        Should -Invoke Write-Warning -Times 1 -Exactly
    }
}

Describe 'Log Analytics response validation' {
    It 'supports both name and ColumnName metadata' -TestCases @(
        @{ Column = @{ name = 'Events' } }, @{ Column = @{ ColumnName = 'Events' } }
    ) {
        $response = @{ tables = @(@{ columns = @($Column); rows = @(@(42), @(43)) }) }
        $rows = @(ConvertFrom-LogAnalyticsResponse $response)
        $rows.Count | Should -Be 2
        $rows[0].Events | Should -Be 42
        $rows[1].Events | Should -Be 43
    }

    It 'allows a valid empty result table' {
        $response = @{ tables = @(@{ columns = @(@{ name = 'Events' }); rows = @() }) }
        @(ConvertFrom-LogAnalyticsResponse $response).Count | Should -Be 0
    }

    It 'rejects a partial-success response' {
        $response = @{
            tables = @(@{ columns = @(@{ name = 'Events' }); rows = @(@(42), @(43)) })
            error = @{ code = 'PartialError'; message = 'Query results are incomplete' }
        }
        { ConvertFrom-LogAnalyticsResponse $response } | Should -Throw '*PartialError*'
    }

    It 'rejects a malformed table <Case>' -TestCases @(
        @{ Case = 'missing tables'; Response = @{} }
        @{ Case = 'no tables'; Response = @{ tables = @() } }
        @{ Case = 'missing rows'; Response = @{ tables = @(@{ columns = @(@{ name = 'Events' }) }) } }
        @{ Case = 'no columns'; Response = @{ tables = @(@{ columns = @(); rows = @() }) } }
        @{ Case = 'unnamed column'; Response = @{ tables = @(@{ columns = @(@{}); rows = @() }) } }
        @{ Case = 'duplicate columns'; Response = @{ tables = @(@{ columns = @(@{ name = 'Events' }, @{ name = 'events' }); rows = @() }) } }
        @{ Case = 'ragged row'; Response = @{ tables = @(@{ columns = @(@{ name = 'Events' }); rows = @(@(1, 2)) }) } }
    ) {
        { ConvertFrom-LogAnalyticsResponse $Response } | Should -Throw
    }
}

Describe 'Audit window validation' {
    It 'treats unspecified timestamps as UTC without changing the clock value' {
        $value = ConvertTo-UtcDate ([datetime]'2026-11-16T12:30:45')
        $value.Kind | Should -Be ([DateTimeKind]::Utc)
        $value.Hour | Should -Be 12
        $value.Minute | Should -Be 30
    }

    It 'rejects empty or reversed windows' {
        { Assert-AuditWindow ([datetime]'2026-11-21') ([datetime]'2026-11-21') 90 } | Should -Throw '*earlier than*'
        { Assert-AuditWindow ([datetime]'2026-11-22') ([datetime]'2026-11-21') 90 } | Should -Throw '*earlier than*'
    }

    It 'rejects nonpositive lookback values' {
        { Assert-AuditWindow ([datetime]'2026-11-16') ([datetime]'2026-11-21') 0 } | Should -Throw '*positive*'
    }

    It 'warns when the window is older than the lookback' {
        Mock Write-Warning {}
        Assert-AuditWindow ([datetime]::UtcNow.AddDays(-10)) ([datetime]::UtcNow.AddDays(-9)) 5
        Should -Invoke Write-Warning -Times 1 -Exactly
    }
}
