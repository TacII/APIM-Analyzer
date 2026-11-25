#Requires -Version 7
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $repo = Split-Path $PSScriptRoot -Parent
    function az {
        param([Parameter(ValueFromRemainingArguments)][string[]]$Arguments)
        throw "Unmocked Azure CLI call: $Arguments"
    }
    function Invoke-RestMethod {
        param($Method, $Uri, $Headers, $Body, $ContentType)
        throw "Unmocked HTTP request: $Method $Uri"
    }
    function New-TestLogTable([string[]]$Columns, [object[]]$Rows = @()) {
        @{ tables = @(@{ columns = @($Columns | ForEach-Object { @{ name = $_ } }); rows = $Rows }) }
    }
    function Write-TestCallerInput {
        New-Item -ItemType Directory '.\kv-audit' -Force | Out-Null
        [pscustomobject]@{
            Oid = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
            ResourceId = $global:ApimWorkflowFixture.vaultId; CallerIP = '203.0.113.20'
        } | Export-Csv '.\kv-audit\new-callers-in-window.csv'
        [pscustomobject]@{
            vaultId = $global:ApimWorkflowFixture.vaultId
            workspaceId = $global:ApimWorkflowFixture.workspaceId
        } | Export-Csv '.\kv-audit\vault-logging.csv'
    }
}

Describe 'Offline three-script workflow' {
    BeforeEach {
        $previousExitCode = $global:LASTEXITCODE
        $script:subId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        $script:principal = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
        $script:vaultId = "/subscriptions/$script:subId/resourceGroups/test/providers/Microsoft.KeyVault/vaults/test-vault"
        $script:workspaceId = "/subscriptions/$script:subId/resourceGroups/test/providers/Microsoft.OperationalInsights/workspaces/test-workspace"
        $script:inventory = @(
            foreach ($sku in 'Developer', 'Basic', 'Standard', 'Premium', 'Isolated', 'Consumption', 'BasicV2', 'StandardV2', 'PremiumV2') {
                [pscustomobject]@{
                    id = "/subscriptions/$script:subId/resourceGroups/test/providers/Microsoft.ApiManagement/service/apim-$($sku.ToLowerInvariant())"
                    name = "apim-$($sku.ToLowerInvariant())"; subscriptionId = $script:subId
                    sku = $sku; platformVersion = 'stv2.1'; vnetType = 'None'; publicAccess = 'Enabled'
                    privateEndpoints = 0; privateEndpointConnections = '[]'
                    publicIPs = @('203.0.113.10'); privateIPs = @()
                    additionalLocations = @(@{ publicIPAddresses = @('203.0.113.11'); privateIPAddresses = @() })
                    identity = (@{ type = 'SystemAssigned'; principalId = $script:principal } | ConvertTo-Json -Compress)
                }
            }
        )
        $global:ApimWorkflowFixture = @{
            subId = $script:subId; principal = $script:principal
            vaultId = $script:vaultId; workspaceId = $script:workspaceId
            inventory = $script:inventory; partialLogs = $false; repeatGraphToken = $false
            directoryFailed = $false; sharedQueryFailed = $false
            diagnosticFailed = $false; noDiagnostics = $false; unknownVaultMode = $false; rbacOnlyCandidate = $false
        }
        Mock Write-Host {}
        Mock Write-Warning {}
        Mock az {
            param($Arguments)
            $global:LASTEXITCODE = 0
            if ($Arguments -contains 'get-access-token') {
                return (@{ accessToken = 'offline-test-token'; expires_on = [DateTimeOffset]::UtcNow.AddHours(1).ToUnixTimeSeconds() } | ConvertTo-Json -Compress)
            }
            if ($Arguments -contains 'list') { return (@(@{ id = $global:ApimWorkflowFixture.subId; state = 'Enabled' }) | ConvertTo-Json -AsArray -Compress) }
            if ($Arguments -contains 'show') { return (@{ id = $global:ApimWorkflowFixture.subId } | ConvertTo-Json -Compress) }
            throw "Unexpected mock CLI arguments: $Arguments"
        }
        Mock Invoke-RestMethod {
            param($Method, $Uri, $Headers, $Body)
            if ($Uri -like '*directoryObjects/getByIds') {
                if ($global:ApimWorkflowFixture.directoryFailed) { throw 'Directory access denied (simulated)' }
                return @{ value = @(@{
                    id = 'cccccccc-cccc-cccc-cccc-cccccccccccc'; '@odata.type' = '#microsoft.graph.servicePrincipal'
                    displayName = 'test-pipeline'; servicePrincipalType = 'Application'
                }) }
            }
            if ($Uri -like '*Microsoft.Network/locations/*/serviceTags?*') {
                return @{ values = @(@{ name = 'AzureCloud'; properties = @{ addressPrefixes = @('203.0.113.0/24') } }) }
            }
            if ($Uri -like '*roleDefinitions/test-role?*') {
                return @{ properties = @{ roleName = 'Test Secrets Reader'; permissions = @(@{
                    dataActions = @('Microsoft.KeyVault/vaults/secrets/getSecret/action')
                    notDataActions = @(); actions = @(); notActions = @()
                }) } }
            }
            if ($Uri -like '*Microsoft.ResourceGraph/resources*') {
                $query = ($Body | ConvertFrom-Json).query
                $data = @()
                if ($query -match "type =~ 'microsoft.apimanagement/service'") { $data = $global:ApimWorkflowFixture.inventory }
                elseif ($query -match 'authorizationresources' -and $global:ApimWorkflowFixture.rbacOnlyCandidate) {
                    $data = @(@{
                        id = '/role-assignment/test'; principalId = $global:ApimWorkflowFixture.principal
                        scope = $global:ApimWorkflowFixture.vaultId
                        roleDefinitionId = '/providers/Microsoft.Authorization/roleDefinitions/test-role'
                    })
                }
                elseif ($query -match 'mv-expand ap') {
                    if (-not $global:ApimWorkflowFixture.rbacOnlyCandidate) {
                        $data = @(@{ id = $global:ApimWorkflowFixture.vaultId; principalId = $global:ApimWorkflowFixture.principal; objectId = $global:ApimWorkflowFixture.principal; vault = 'test-vault' })
                    }
                }
                elseif ($query -match "type =~ 'microsoft.keyvault/vaults'") { $data = @([pscustomobject]@{
                    id = $global:ApimWorkflowFixture.vaultId; name = 'test-vault'; subscriptionId = $global:ApimWorkflowFixture.subId
                    rbacMode = if ($global:ApimWorkflowFixture.unknownVaultMode) { $null } else { $false }
                }) }
                elseif ($query -match 'resourcecontainers') { $data = @(@{ subscriptionId = $global:ApimWorkflowFixture.subId; mgChain = @() }) }
                $response = @{ data = @($data); totalRecords = @($data).Count }
                if ($global:ApimWorkflowFixture.repeatGraphToken) { $response['$skipToken'] = 'repeated-token' }
                return $response
            }
            if ($Uri -like '*diagnosticSettings?*') {
                if ($global:ApimWorkflowFixture.diagnosticFailed) { throw 'Diagnostic settings access denied (simulated)' }
                if ($global:ApimWorkflowFixture.noDiagnostics) { return @{ value = @() } }
                return @{ value = @(@{ properties = @{ workspaceId = $global:ApimWorkflowFixture.workspaceId; logs = @(@{ enabled = $true; category = 'AuditEvent' }) } }) }
            }
            if ($Uri -like '*/api/query?*') {
                $query = ($Body | ConvertFrom-Json).query
                if ($query -match 'DataPlaneEvents=countif') {
                    $response = New-TestLogTable @('ResourceId', 'Events', 'First', 'Last', 'Sources', 'DataPlaneEvents', 'MissingIp', 'MissingOid') `
                        -Rows @(, @($global:ApimWorkflowFixture.vaultId.ToLowerInvariant(), 10, '2026-11-01T00:00:00Z', '2026-11-22T00:00:00Z', 'AZKVAuditLogs', 10, 0, 0))
                } elseif ($query -match 'by ResourceId, Oid, CallerIP, OperationName') {
                    $query | Should -Match 'TimeGenerated >= datetime\(2026-11-16T00:00:00\.0000000\) and TimeGenerated < datetime\(2026-11-21T00:00:00\.0000000\)'
                    $response = New-TestLogTable @('ResourceId', 'Oid', 'CallerIP', 'OperationName', 'Events', 'First', 'Last') `
                        -Rows @(, @($global:ApimWorkflowFixture.vaultId.ToLowerInvariant(), $global:ApimWorkflowFixture.principal, '203.0.113.11', 'SecretGet', 2, '2026-11-18T00:00:00Z', '2026-11-19T00:00:00Z'))
                } elseif ($query -match 'BaselineEvents=countif') {
                    $response = New-TestLogTable @('Oid', 'ResourceId', 'BaselineEvents', 'BaselineDays', 'WindowEvents', 'WindowDays', 'WindowFailedOps', 'FirstSeen', 'BaselineItems', 'WindowItems') `
                        -Rows @(, @('cccccccc-cccc-cccc-cccc-cccccccccccc', $global:ApimWorkflowFixture.vaultId.ToLowerInvariant(), 10, 5, 2, 1, '[]', '2026-11-01T00:00:00Z', 1, 1))
                } elseif ($query -match 'BeforeWindow=countif') {
                    $response = New-TestLogTable @('Oid', 'ResourceId', 'Client', 'Events', 'BeforeWindow', 'InWindow') `
                        -Rows @(, @('cccccccc-cccc-cccc-cccc-cccccccccccc', $global:ApimWorkflowFixture.vaultId.ToLowerInvariant(), 'Terraform', 12, 10, 2))
                } elseif ($query -match 'Failed=countif') {
                    $response = New-TestLogTable @('Oid', 'ResourceId', 'CallerIP', 'Events') `
                        -Rows @(, @('cccccccc-cccc-cccc-cccc-cccccccccccc', $global:ApimWorkflowFixture.vaultId.ToLowerInvariant(), '203.0.113.20', 12))
                } else {
                    if ($global:ApimWorkflowFixture.sharedQueryFailed) { throw 'Shared IP query failed (simulated)' }
                    $response = New-TestLogTable @('ResourceId', 'Oid', 'CallerIP', 'Events')
                }
                if ($global:ApimWorkflowFixture.partialLogs) { $response.error = @{ code = 'PartialError'; message = 'Incomplete results' } }
                return $response
            }
            if ($Uri -match '/providers/Microsoft.ApiManagement/service\?') { return @{ value = $global:ApimWorkflowFixture.inventory } }
            if ($Uri -match '/tenant/(access|gitAccess)\?') { return @{ properties = @{ enabled = $false } } }
            if ($Uri -match '/(namedValues|identityProviders|openidConnectProviders|authorizationServers|backends|loggers|authorizationProviders|certificates|subscriptions)\?') {
                return @{ value = @() }
            }
            throw "Unexpected mock HTTP request: $Method $Uri"
        }
        Push-Location $TestDrive
    }

    AfterEach {
        Pop-Location
        $global:LASTEXITCODE = $previousExitCode
        Remove-Variable ApimWorkflowFixture -Scope Global
    }

    It 'runs exposure, audit and offline analysis with all nine supported SKUs' {
        & (Join-Path $repo 'Check-ApimExposure.ps1')
        $summary = @(Import-Csv '.\apim-exposure\summary.csv')
        $summary.Count | Should -Be 9
        @($summary | Where-Object status -eq 'LIKELY EXPOSED').Count | Should -Be 5
        @($summary | Where-Object status -eq 'OUT OF SCOPE').Count | Should -Be 4
        @($summary | Where-Object { $_.directMgmtApi -eq 'False' }).Count | Should -Be 5

        & (Join-Path $repo 'Check-KeyVaultAudit.ps1') -WindowStart '2026-11-16' -WindowEnd '2026-11-21'
        $vaults = @(Import-Csv '.\kv-audit\vault-verdicts.csv')
        $vaults.Count | Should -Be 1
        $vaults[0].status | Should -Be 'no anomaly found in available logs'
        $vaults[0].logsTo | Should -Not -BeNullOrEmpty
        @(Import-Csv '.\kv-audit\apim-identity-activity.csv')[0].Flag | Should -Be 'expected'

        & (Join-Path $repo 'Analyze-Findings.ps1') -SkipLive
        $report = Get-Content '.\incident-analysis\analysis-report.md' -Raw
        $report | Should -Match '\| Instances in scope \| 5 '
        $report | Should -Match '\| Active subscriptions \| 0 '
        (Get-Content '.\incident-analysis\snapshot.json' -Raw | ConvertFrom-Json).heldSecrets | Should -Be 0
    }

    It 'uses the same IncludeConsumption fallback in audit and analysis without a scope file' {
        New-Item -ItemType Directory '.\fallback-exposure' | Out-Null
        $script:inventory | Export-Csv '.\fallback-exposure\apim-instances.csv'
        $script:inventory | ForEach-Object { [pscustomobject]@{ apim = $_.name; status = 'REVIEW' } } |
            Export-Csv '.\fallback-exposure\summary.csv'
        & (Join-Path $repo 'Check-KeyVaultAudit.ps1') -ScopeFile '.\missing-scope.csv' -IncludeConsumption
        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter { $Object -eq 'APIM instances in scope: 6 of 9' }
        & (Join-Path $repo 'Analyze-Findings.ps1') -ExposureDir '.\fallback-exposure' -IncludeConsumption -SkipLive
        (Get-Content '.\incident-analysis\analysis-report.md' -Raw) | Should -Match '\| Instances in scope \| 6 '
    }

    It 'reports an unknown SKU as UNCHECKED instead of assuming Classic or v2' {
        $script:inventory[0].sku = 'FutureV2'
        & (Join-Path $repo 'Check-ApimExposure.ps1')
        $unknown = Import-Csv '.\apim-exposure\summary.csv' | Where-Object apim -eq 'apim-developer'
        $unknown.status | Should -Be 'UNCHECKED'
        $unknown.tierFamily | Should -Be 'Unknown'
        $unknown.scope | Should -Match 'scope cannot be determined'
        Should -Invoke Write-Warning -ParameterFilter { $Message -like '*unrecognized or missing APIM SKU*' }
    }

    It 'does not accept partial Log Analytics results as clean evidence' {
        $global:ApimWorkflowFixture.partialLogs = $true
        & (Join-Path $repo 'Check-KeyVaultAudit.ps1') -ScopeFile '.\missing-scope.csv'
        @(Import-Csv '.\kv-audit\vault-verdicts.csv')[0].status | Should -Be 'QUERY FAILED - cannot assess'
    }

    It 'distinguishes inaccessible diagnostic settings from logging being disabled' {
        $global:ApimWorkflowFixture.diagnosticFailed = $true
        & (Join-Path $repo 'Check-KeyVaultAudit.ps1') -ScopeFile '.\missing-scope.csv'
        $vault = @(Import-Csv '.\kv-audit\vault-verdicts.csv')[0]
        $vault.status | Should -Be 'DIAGNOSTIC SETTINGS FAILED - cannot assess'
        $vault.note | Should -Match 'Diagnostic settings access denied'
    }

    It 'reports missing audit logging without looking up a null workspace key' {
        $global:ApimWorkflowFixture.noDiagnostics = $true
        & (Join-Path $repo 'Check-KeyVaultAudit.ps1') -ScopeFile '.\missing-scope.csv'
        @(Import-Csv '.\kv-audit\vault-verdicts.csv')[0].status | Should -Be 'NO AUDIT LOGGING - cannot assess'
    }

    It 'warns about an unknown vault authorization mode and still reviews reachable vaults' {
        $global:ApimWorkflowFixture.unknownVaultMode = $true
        $global:ApimWorkflowFixture.rbacOnlyCandidate = $true
        & (Join-Path $repo 'Check-KeyVaultAudit.ps1') -ScopeFile '.\missing-scope.csv'
        @(Import-Csv '.\kv-audit\vault-verdicts.csv').Count | Should -Be 1
        @(Import-Csv '.\kv-audit\vault-logging.csv')[0].via | Should -Match 'Test Secrets Reader.*data access'
        Should -Invoke Write-Warning -Times 1 -Exactly -ParameterFilter { $Message -like '*vault authorization mode is unknown*' }
    }

    It 'aborts repeated Resource Graph paging instead of looping forever' {
        $global:ApimWorkflowFixture.repeatGraphToken = $true
        { & (Join-Path $repo 'Check-ApimExposure.ps1') } | Should -Throw '*repeated a continuation token*'
    }

    It 'stops on CLI authentication failure without issuing HTTP calls' {
        Mock az { $global:LASTEXITCODE = 1; '[]' }
        { & (Join-Path $repo 'Check-ApimExposure.ps1') } | Should -Throw '*exit 1*'
        Should -Invoke Invoke-RestMethod -Times 0 -Exactly
    }

    It 'rejects invalid windows before creating output or calling Azure' {
        { & (Join-Path $repo 'Check-KeyVaultAudit.ps1') -WindowStart '2026-11-21' -WindowEnd '2026-11-16' } | Should -Throw '*earlier than*'
        Should -Invoke az -Times 0 -Exactly
        Should -Invoke Invoke-RestMethod -Times 0 -Exactly
    }

    It 'preserves sub-day UTC windows without making live calls in SkipLive mode' {
        & (Join-Path $repo 'Check-ApimExposure.ps1')
        Mock az { throw 'SkipLive must not call Azure CLI' }
        Mock Invoke-RestMethod { throw 'SkipLive must not issue HTTP requests' }
        & (Join-Path $repo 'Analyze-Findings.ps1') -SkipLive -WindowStart '2026-11-16T12:30:00' -WindowEnd '2026-11-20T18:45:00'
        $snapshot = Get-Content '.\incident-analysis\snapshot.json' -Raw | ConvertFrom-Json
        $snapshot.window | Should -Be '2026-11-16T12:30:00.0000000Z/2026-11-20T18:45:00.0000000Z'
    }

    It 'distinguishes a failed directory lookup from an identity absent from the directory' {
        & (Join-Path $repo 'Check-ApimExposure.ps1')
        Write-TestCallerInput
        $global:ApimWorkflowFixture.directoryFailed = $true
        & (Join-Path $repo 'Analyze-Findings.ps1')
        $caller = @(Import-Csv '.\incident-analysis\caller-drilldown.csv')[0]
        $caller.identityType | Should -Be 'LOOKUP FAILED'
        $caller.verdict | Should -Be 'NOT ANALYSED - directory lookup failed'
    }

    It 'does not produce a benign verdict when a later drill-down query fails' {
        & (Join-Path $repo 'Check-ApimExposure.ps1')
        Write-TestCallerInput
        $global:ApimWorkflowFixture.sharedQueryFailed = $true
        & (Join-Path $repo 'Analyze-Findings.ps1')
        @(Import-Csv '.\incident-analysis\caller-drilldown.csv')[0].verdict |
            Should -Be 'NOT ANALYSED - log queries failed or returned incomplete results'
    }
}
