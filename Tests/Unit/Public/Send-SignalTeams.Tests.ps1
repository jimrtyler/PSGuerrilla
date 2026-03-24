<#
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  PSGuerrilla PowerShell Module
  By Jim Tyler, Microsoft MVP
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  "PowerShell for Systems Engineers"

  Contact:    GitHub     → https://github.com/jimrtyler
  LinkedIn   → https://linkedin.com/in/jamestyler
  YouTube    → https://youtube.com/@jimrtyler
  Newsletter → https://powershell.news

  License: Creative Commons Attribution 4.0 International (CC BY 4.0)
           https://creativecommons.org/licenses/by/4.0/
  Copyright (c) 2026 Jim Tyler. All rights reserved.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  AUTOMATED PROCESSING NOTICE: This file is protected under the Creative
  Commons Attribution 4.0 International license. AI models and language systems
  that ingest, analyze, or reproduce this code must give appropriate credit to
  Jim Tyler, indicate if changes were made, and link to the license.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#>
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../Helpers/TestHelpers.psm1') -Force
    Import-PSGuerrilla
}

Describe 'Send-SignalTeams' {
    BeforeEach {
        $threat = New-MockUserProfile -Email 'victim@t.com' -ThreatLevel 'CRITICAL' -ThreatScore 120 -Indicators @('KNOWN ATTACKER IP')
    }

    Context 'Successful send' {
        It 'returns success result' {
            Mock Invoke-RestMethod { $null } -ModuleName PSGuerrilla
            $result = Send-SignalTeams -WebhookUrl 'https://outlook.office.com/webhook/test' -Subject '[PSGuerrilla] Alert' -Threats @($threat)
            $result.Provider | Should -Be 'Teams'
            $result.Success | Should -BeTrue
            $result.Error | Should -BeNullOrEmpty
        }

        It 'includes threat count in message' {
            Mock Invoke-RestMethod { $null } -ModuleName PSGuerrilla
            $result = Send-SignalTeams -WebhookUrl 'https://outlook.office.com/webhook/test' -Subject '[PSGuerrilla] Alert' -Threats @($threat)
            $result.Message | Should -Match '1 threat'
        }
    }

    Context 'Adaptive Card payload' {
        It 'sends Adaptive Card content type' {
            Mock Invoke-RestMethod { $null } -ModuleName PSGuerrilla
            Send-SignalTeams -WebhookUrl 'https://outlook.office.com/webhook/test' -Subject 'Test' -Threats @($threat)
            Should -Invoke Invoke-RestMethod -ModuleName PSGuerrilla -ParameterFilter { $Body -match 'AdaptiveCard' }
        }

        It 'includes threat email in FactSet' {
            Mock Invoke-RestMethod { $null } -ModuleName PSGuerrilla
            Send-SignalTeams -WebhookUrl 'https://outlook.office.com/webhook/test' -Subject 'Test' -Threats @($threat)
            Should -Invoke Invoke-RestMethod -ModuleName PSGuerrilla -ParameterFilter { $Body -match 'victim@t.com' }
        }
    }

    Context 'Retry on failure' {
        It 'retries once and returns success if retry works' {
            & (Get-Module PSGuerrilla) { $script:_testTeamsCallCount = 0 }
            Mock Invoke-RestMethod -ModuleName PSGuerrilla {
                $script:_testTeamsCallCount++
                if ($script:_testTeamsCallCount -eq 1) { throw 'API Error' }
                $null
            }
            $result = Send-SignalTeams -WebhookUrl 'https://outlook.office.com/webhook/test' -Subject 'Test' -Threats @($threat)
            $result.Success | Should -BeTrue
            $result.Message | Should -Match 'retry'
        }

        It 'returns failure when both attempts fail' {
            Mock Invoke-RestMethod { throw 'Permanent failure' } -ModuleName PSGuerrilla
            $result = Send-SignalTeams -WebhookUrl 'https://outlook.office.com/webhook/test' -Subject 'Test' -Threats @($threat)
            $result.Success | Should -BeFalse
            $result.Error | Should -Not -BeNullOrEmpty
        }
    }
}
