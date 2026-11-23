#Requires -Version 7
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    . (Join-Path $PSScriptRoot '..\Apim-Helpers.ps1')
    foreach ($file in 'Check-KeyVaultAudit.ps1', 'Analyze-Findings.ps1') {
        $path = Join-Path $PSScriptRoot "..\$file"
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$null)
        $wanted = 'Get-VaultStatus', 'Build-ApimActivityQuery', 'Get-AllPages'
        $defs = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $args[0].Name -in $wanted }, $true)
        foreach ($d in $defs) { . ([scriptblock]::Create($d.Extent.Text)) }
    }
    function Invoke-Api { throw 'Unexpected live API call in offline tests' }
}

Describe 'Backend and logger enumeration' {
    It 'throws instead of treating a denied request as an empty list' {
        Mock Invoke-Api { [pscustomobject]@{ ok = $false; error = 'HTTP 403 Forbidden' } }
        { Get-AllPages 'https://management.azure.com/test/backends' } |
            Should -Throw '*Could not enumerate https://management.azure.com/test/backends: HTTP 403 Forbidden*'
    }

    It 'throws when a later page fails instead of silently accepting a partial list' {
        Mock Invoke-Api {
            param($Method, $Url)
            if ($Url -eq 'https://management.azure.com/page1') {
                return [pscustomobject]@{ ok = $true; data = @{ value = @('backend1'); nextLink = 'https://management.azure.com/page2' } }
            }
            [pscustomobject]@{ ok = $false; error = 'HTTP 500 Server error' }
        }
        { Get-AllPages 'https://management.azure.com/page1' } | Should -Throw '*page2: HTTP 500 Server error*'
    }

    It 'returns every successful page' {
        Mock Invoke-Api {
            param($Method, $Url)
            if ($Url -eq 'https://management.azure.com/page1') {
                return [pscustomobject]@{ ok = $true; data = @{ value = @('backend1'); nextLink = 'https://management.azure.com/page2' } }
            }
            [pscustomobject]@{ ok = $true; data = @{ value = @('backend2'); nextLink = $null } }
        }
        $rows = @(Get-AllPages 'https://management.azure.com/page1')
        $rows.Count | Should -Be 2
        $rows[0] | Should -Be 'backend1'
        $rows[1] | Should -Be 'backend2'
    }

    It 'allows a successful empty list' {
        Mock Invoke-Api { [pscustomobject]@{ ok = $true; data = @{ value = @(); nextLink = $null } } }
        @(Get-AllPages 'https://management.azure.com/test/loggers').Count | Should -Be 0
    }

    It 'rejects a malformed success response instead of reporting an empty list' {
        Mock Invoke-Api { [pscustomobject]@{ ok = $true; data = @{} } }
        { Get-AllPages 'https://management.azure.com/test/loggers' } | Should -Throw "*expected a 'value' array*"
    }

    It 'aborts a repeated nextLink' {
        Mock Invoke-Api {
            [pscustomobject]@{ ok = $true; data = @{ value = @(); nextLink = 'https://management.azure.com/test/loggers' } }
        }
        { Get-AllPages 'https://management.azure.com/test/loggers' } | Should -Throw '*Repeated nextLink*'
        Should -Invoke Invoke-Api -Times 1 -Exactly
    }
}

Describe 'Vault evidence and verdicts' {
    BeforeEach {
        $argsForStatus = @{
            WorkspaceId = '/subscriptions/test/workspaces/test'
            QueryFailed = $false
            Coverage = [pscustomobject]@{
                First = '2026-11-01T00:00:00Z'; Last = '2026-11-22T00:00:00Z'
                MissingIp = 0; MissingOid = 0
            }
            UnexpectedIps = 0; NewCallers = 0; UnverifiableIps = 0
            Start = [datetime]'2026-11-16'; End = [datetime]'2026-11-21'
        }
    }

    It 'allows no anomaly only with bracketing timestamps and complete caller fields' {
        Get-VaultStatus @argsForStatus | Should -Be 'no anomaly found in available logs'
    }

    It 'does not clear a vault whose logs stop before the incident' {
        $argsForStatus.Coverage.Last = '2026-11-15T00:00:00Z'
        Get-VaultStatus @argsForStatus | Should -Be 'PARTIAL COVERAGE - logs do not extend to window end'
    }

    It 'does not clear a vault whose logs stop inside the incident window' {
        $argsForStatus.Coverage.Last = '2026-11-20T23:59:59Z'
        Get-VaultStatus @argsForStatus | Should -Be 'PARTIAL COVERAGE - logs do not extend to window end'
    }

    It 'accepts timestamps exactly at both window boundaries' {
        $argsForStatus.Coverage.First = '2026-11-16T00:00:00Z'
        $argsForStatus.Coverage.Last = '2026-11-21T00:00:00Z'
        Get-VaultStatus @argsForStatus | Should -Be 'no anomaly found in available logs'
    }

    It 'keeps a late log start inconclusive' {
        $argsForStatus.Coverage.First = '2026-11-17T00:00:00Z'
        Get-VaultStatus @argsForStatus | Should -Be 'PARTIAL COVERAGE - logs start after window start'
    }

    It 'requires both timestamps' {
        $argsForStatus.Coverage.Last = $null
        Get-VaultStatus @argsForStatus | Should -Be 'PARTIAL COVERAGE - log timestamps missing'
    }

    It 'does not clear logs with missing <Field>' -TestCases @(
        @{ Field = 'MissingIp' }
        @{ Field = 'MissingOid' }
    ) {
        $argsForStatus.Coverage.$Field = 1
        Get-VaultStatus @argsForStatus | Should -Be 'PARTIAL COVERAGE - authenticated data-plane rows lack caller IP or object ID'
    }

    It 'preserves a suspicious finding despite incomplete coverage' {
        $argsForStatus.NewCallers = 1
        $argsForStatus.Coverage.MissingOid = 1
        Get-VaultStatus @argsForStatus | Should -Be 'SUSPICIOUS - review'
    }

    It 'preserves an unexpected APIM IP finding' {
        $argsForStatus.UnexpectedIps = 1
        Get-VaultStatus @argsForStatus | Should -Be 'SUSPICIOUS - review'
    }

    It 'preserves an unverifiable APIM IP finding' {
        $argsForStatus.UnverifiableIps = 1
        Get-VaultStatus @argsForStatus | Should -Be 'REVIEW - APIM identity activity, source IPs unverifiable'
    }

    It 'preserves failed-query status even with partial results' {
        $argsForStatus.QueryFailed = $true
        Get-VaultStatus @argsForStatus | Should -Be 'QUERY FAILED - cannot assess'
    }

    It 'preserves missing-logging status' {
        $argsForStatus.WorkspaceId = ''
        Get-VaultStatus @argsForStatus | Should -Be 'NO AUDIT LOGGING - cannot assess'
    }

    It 'does not claim logging is disabled when reading its settings failed' {
        $argsForStatus.WorkspaceId = ''
        Get-VaultStatus @argsForStatus -LoggingFailed | Should -Be 'DIAGNOSTIC SETTINGS FAILED - cannot assess'
    }

    It 'preserves missing-data status' {
        $argsForStatus.Coverage = $null
        Get-VaultStatus @argsForStatus | Should -Be 'NO LOG DATA IN LOOKBACK - cannot assess'
    }
}

Describe 'APIM identity activity query' {
    It 'filters to the inclusive start and exclusive end before aggregating' {
        $query = Build-ApimActivityQuery "let src = test;`n" "'principal-id'" ([datetime]'2026-11-16') ([datetime]'2026-11-21')
        $query | Should -Be ("let src = test;`n" +
            "src | where TimeGenerated >= datetime(2026-11-16T00:00:00.0000000) and TimeGenerated < datetime(2026-11-21T00:00:00.0000000) | where Oid in (dynamic(['principal-id'])) | summarize Events=count(), First=min(TimeGenerated), Last=max(TimeGenerated) by ResourceId, Oid, CallerIP, OperationName")
    }

    It 'preserves sub-day window boundaries' {
        $query = Build-ApimActivityQuery '' "'principal-id'" ([datetime]'2026-11-16T12:30:00') ([datetime]'2026-11-20T18:45:00')
        $query | Should -Match 'TimeGenerated >= datetime\(2026-11-16T12:30:00\.0000000\) and TimeGenerated < datetime\(2026-11-20T18:45:00\.0000000\)'
    }
}
