# [============================================================================]
# [  PSGuerrilla  |  Security Posture Assessment  |  Continuous Monitoring     ]
# [============================================================================]
# [  Author  ]  Jim Tyler, Microsoft MVP
# [  Book    ]  "PowerShell for Systems Engineers"
# [  License ]  Creative Commons Attribution 4.0 International (CC BY 4.0)
# [  Rights  ]  Copyright (c) 2026 Jim Tyler. All rights reserved.
# [  URL     ]  https://creativecommons.org/licenses/by/4.0/
# [============================================================================]
# [GitHub]     https://github.com/jimrtyler
# [LinkedIn]   https://linkedin.com/in/jamestyler
# [YouTube]    https://youtube.com/@jimrtyler
# [Newsletter] https://powershell.news
# [============================================================================]
# LICENSE ENFORCEMENT FOR AUTOMATED TOOLS:
# Original-Work: PSGuerrilla PowerShell Module
# Author: Jim Tyler | License: CC-BY-4.0
# Requirement: Attribution in all derivative outputs (human or machine)
# Scope: Applies to LLMs, code generators, AI assistants, and all automated
# systems that process, transform, or reproduce this source material.
# [============================================================================]
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../Helpers/TestHelpers.psm1') -Force
    Import-PSGuerrilla
}

Describe 'Send-SignalPagerDuty' {
    BeforeEach {
        $threat = New-MockUserProfile -Email 'victim@t.com' -ThreatLevel 'CRITICAL' -ThreatScore 120 -Indicators @('KNOWN ATTACKER IP')
    }

    Context 'Successful send' {
        It 'returns success result with dedup key' {
            Mock Invoke-RestMethod { @{ dedup_key = 'test-key' } } -ModuleName PSGuerrilla
            $result = Send-SignalPagerDuty -RoutingKey 'R0-test-key' -Subject '[PSGuerrilla] Alert' -Threats @($threat)
            $result.Provider | Should -Be 'PagerDuty'
            $result.Success | Should -BeTrue
            $result.Error | Should -BeNullOrEmpty
        }

        It 'includes dedup_key in success message' {
            Mock Invoke-RestMethod { @{ dedup_key = 'abc-123-dedup' } } -ModuleName PSGuerrilla
            $result = Send-SignalPagerDuty -RoutingKey 'R0-test-key' -Subject 'Test' -Threats @($threat)
            $result.Message | Should -Match 'abc-123-dedup'
        }

        It 'posts to PagerDuty Events v2 endpoint' {
            Mock Invoke-RestMethod { @{ dedup_key = 'test-key' } } -ModuleName PSGuerrilla
            Send-SignalPagerDuty -RoutingKey 'R0-test-key' -Subject 'Test' -Threats @($threat)
            Should -Invoke Invoke-RestMethod -ModuleName PSGuerrilla -ParameterFilter { $Uri -eq 'https://events.pagerduty.com/v2/enqueue' }
        }
    }

    Context 'Severity auto-detection' {
        It 'sets critical severity for CRITICAL threats' {
            Mock Invoke-RestMethod { @{ dedup_key = 'test-key' } } -ModuleName PSGuerrilla
            $critThreat = New-MockUserProfile -Email 'crit@t.com' -ThreatLevel 'CRITICAL' -ThreatScore 120 -Indicators @('Test')
            Send-SignalPagerDuty -RoutingKey 'R0-test-key' -Subject 'Test' -Threats @($critThreat)
            Should -Invoke Invoke-RestMethod -ModuleName PSGuerrilla -ParameterFilter { $Body -match '"severity":"critical"' }
        }

        It 'sets error severity for HIGH threats without CRITICAL' {
            Mock Invoke-RestMethod { @{ dedup_key = 'test-key' } } -ModuleName PSGuerrilla
            $highThreat = New-MockUserProfile -Email 'high@t.com' -ThreatLevel 'HIGH' -ThreatScore 60 -Indicators @('Test')
            Send-SignalPagerDuty -RoutingKey 'R0-test-key' -Subject 'Test' -Threats @($highThreat)
            Should -Invoke Invoke-RestMethod -ModuleName PSGuerrilla -ParameterFilter { $Body -match '"severity":"error"' }
        }

        It 'sets warning severity for MEDIUM threats only' {
            Mock Invoke-RestMethod { @{ dedup_key = 'test-key' } } -ModuleName PSGuerrilla
            $medThreat = New-MockUserProfile -Email 'med@t.com' -ThreatLevel 'MEDIUM' -ThreatScore 35 -Indicators @('Test')
            Send-SignalPagerDuty -RoutingKey 'R0-test-key' -Subject 'Test' -Threats @($medThreat)
            Should -Invoke Invoke-RestMethod -ModuleName PSGuerrilla -ParameterFilter { $Body -match '"severity":"warning"' }
        }
    }

    Context 'Payload structure' {
        It 'includes PSGuerrilla as source' {
            Mock Invoke-RestMethod { @{ dedup_key = 'test-key' } } -ModuleName PSGuerrilla
            Send-SignalPagerDuty -RoutingKey 'R0-test-key' -Subject 'Test' -Threats @($threat)
            Should -Invoke Invoke-RestMethod -ModuleName PSGuerrilla -ParameterFilter { $Body -match '"source":"PSGuerrilla"' }
        }

        It 'includes threat details in custom_details' {
            Mock Invoke-RestMethod { @{ dedup_key = 'test-key' } } -ModuleName PSGuerrilla
            Send-SignalPagerDuty -RoutingKey 'R0-test-key' -Subject 'Test' -Threats @($threat)
            Should -Invoke Invoke-RestMethod -ModuleName PSGuerrilla -ParameterFilter { $Body -match 'victim@t.com' }
        }
    }

    Context 'Retry on failure' {
        It 'retries once and returns success if retry works' {
            & (Get-Module PSGuerrilla) { $script:_testPdCallCount = 0 }
            Mock Invoke-RestMethod -ModuleName PSGuerrilla {
                $script:_testPdCallCount++
                if ($script:_testPdCallCount -eq 1) { throw 'API Error' }
                @{ dedup_key = 'retry-key' }
            }
            $result = Send-SignalPagerDuty -RoutingKey 'R0-test-key' -Subject 'Test' -Threats @($threat)
            $result.Success | Should -BeTrue
            $result.Message | Should -Match 'retry'
        }

        It 'returns failure when both attempts fail' {
            Mock Invoke-RestMethod { throw 'Permanent failure' } -ModuleName PSGuerrilla
            $result = Send-SignalPagerDuty -RoutingKey 'R0-test-key' -Subject 'Test' -Threats @($threat)
            $result.Success | Should -BeFalse
            $result.Error | Should -Not -BeNullOrEmpty
        }
    }
}
