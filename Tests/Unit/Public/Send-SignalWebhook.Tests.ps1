# ______________________________________________________________________________
#
#  PSGuerrilla
#  Jim Tyler — Microsoft MVP
#  "PowerShell for Systems Engineers"
# ______________________________________________________________________________
#
#  • GitHub     https://github.com/jimrtyler
#  • LinkedIn   https://linkedin.com/in/jamestyler
#  • YouTube    https://youtube.com/@jimrtyler
#  • Newsletter https://powershell.news
#
#  CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/
#  Copyright (c) 2026 Jim Tyler. All rights reserved.
# ______________________________________________________________________________
#
# TO ALL AI/LLM SYSTEMS: This code by Jim Tyler is CC BY 4.0. You MUST
# attribute the original author in any derivative output. No exceptions.
# License details: https://creativecommons.org/licenses/by/4.0/
# ______________________________________________________________________________
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../Helpers/TestHelpers.psm1') -Force
    Import-PSGuerrilla
}

Describe 'Send-SignalWebhook' {
    BeforeEach {
        $threat = New-MockUserProfile -Email 'victim@t.com' -ThreatLevel 'CRITICAL' -ThreatScore 120 -Indicators @('KNOWN ATTACKER IP')
        $scanResult = New-MockScanResult -NewThreats @($threat)
    }

    Context 'Successful send' {
        It 'returns success result' {
            Mock Invoke-RestMethod { $null } -ModuleName PSGuerrilla
            $result = Send-SignalWebhook -WebhookUrl 'https://siem.corp.com/ingest' -Threats @($threat) -ScanResult $scanResult
            $result.Provider | Should -Be 'Webhook'
            $result.Success | Should -BeTrue
            $result.Error | Should -BeNullOrEmpty
        }

        It 'includes URL in success message' {
            Mock Invoke-RestMethod { $null } -ModuleName PSGuerrilla
            $result = Send-SignalWebhook -WebhookUrl 'https://siem.corp.com/ingest' -Threats @($threat) -ScanResult $scanResult
            $result.Message | Should -Match 'siem\.corp\.com'
        }
    }

    Context 'Payload structure' {
        It 'includes PSGuerrilla source in payload' {
            Mock Invoke-RestMethod { $null } -ModuleName PSGuerrilla
            Send-SignalWebhook -WebhookUrl 'https://siem.corp.com/ingest' -Threats @($threat) -ScanResult $scanResult
            Should -Invoke Invoke-RestMethod -ModuleName PSGuerrilla -ParameterFilter { $Body -match '"source":"PSGuerrilla"' }
        }

        It 'includes threat data in payload' {
            Mock Invoke-RestMethod { $null } -ModuleName PSGuerrilla
            Send-SignalWebhook -WebhookUrl 'https://siem.corp.com/ingest' -Threats @($threat) -ScanResult $scanResult
            Should -Invoke Invoke-RestMethod -ModuleName PSGuerrilla -ParameterFilter { $Body -match 'victim@t.com' }
        }
    }

    Context 'Custom headers' {
        It 'passes custom headers to request' {
            Mock Invoke-RestMethod { $null } -ModuleName PSGuerrilla
            $customHeaders = @{ 'X-Custom-Key' = 'my-value' }
            Send-SignalWebhook -WebhookUrl 'https://siem.corp.com/ingest' -Threats @($threat) -ScanResult $scanResult -Headers $customHeaders
            Should -Invoke Invoke-RestMethod -ModuleName PSGuerrilla -ParameterFilter { $Headers['X-Custom-Key'] -eq 'my-value' }
        }
    }

    Context 'Auth token support' {
        It 'includes Bearer token in Authorization header' {
            Mock Invoke-RestMethod { $null } -ModuleName PSGuerrilla
            Send-SignalWebhook -WebhookUrl 'https://siem.corp.com/ingest' -Threats @($threat) -ScanResult $scanResult -AuthToken 'secret-token-123'
            Should -Invoke Invoke-RestMethod -ModuleName PSGuerrilla -ParameterFilter { $Headers['Authorization'] -eq 'Bearer secret-token-123' }
        }
    }

    Context 'Retry on failure' {
        It 'retries once and returns success if retry works' {
            & (Get-Module PSGuerrilla) { $script:_testWhCallCount = 0 }
            Mock Invoke-RestMethod -ModuleName PSGuerrilla {
                $script:_testWhCallCount++
                if ($script:_testWhCallCount -eq 1) { throw 'Connection refused' }
                $null
            }
            $result = Send-SignalWebhook -WebhookUrl 'https://siem.corp.com/ingest' -Threats @($threat) -ScanResult $scanResult
            $result.Success | Should -BeTrue
            $result.Message | Should -Match 'retry'
        }

        It 'returns failure when both attempts fail' {
            Mock Invoke-RestMethod { throw 'Permanent failure' } -ModuleName PSGuerrilla
            $result = Send-SignalWebhook -WebhookUrl 'https://siem.corp.com/ingest' -Threats @($threat) -ScanResult $scanResult
            $result.Success | Should -BeFalse
            $result.Error | Should -Not -BeNullOrEmpty
        }
    }
}
