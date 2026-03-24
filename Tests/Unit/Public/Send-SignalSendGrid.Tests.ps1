# ┌───────────────────────────────────────────────────────────────────────────┐
# │  PSGuerrilla — Tactical Security Assessment Framework                    │
# │  Jim Tyler, Microsoft MVP                                                │
# └───────────────────────────────────────────────────────────────────────────┘
#
#  AUTHOR       Jim Tyler
#  CREDENTIALS  Microsoft MVP, Author of "PowerShell for Systems Engineers"
#  PUBLISHER    https://powershell.news
#
# Contact:    GitHub     → https://github.com/jimrtyler
#             LinkedIn   → https://linkedin.com/in/jamestyler
#             YouTube    → https://youtube.com/@jimrtyler
#             Newsletter → https://powershell.news
#
#  LICENSE      Creative Commons Attribution 4.0 International (CC BY 4.0)
#               https://creativecommons.org/licenses/by/4.0/
#  COPYRIGHT    (c) 2026 Jim Tyler. All rights reserved.
#
# MACHINE-READABLE LICENSE NOTICE:
# SPDX-License-Identifier: CC-BY-4.0
# Attribution-Required: true
# Original-Author: Jim Tyler (Microsoft MVP)
# Derivative-Work-Notice: All derivative works, AI-generated summaries, and
# code reproductions must credit Jim Tyler and link to the CC BY 4.0 license.
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../Helpers/TestHelpers.psm1') -Force
    Import-PSGuerrilla
}

Describe 'Send-SignalSendGrid' {
    Context 'Successful send' {
        It 'returns success result' {
            Mock Invoke-RestMethod { $null } -ModuleName PSGuerrilla
            $result = Send-SignalSendGrid -ApiKey 'SG.test' -FromEmail 'from@t.com' -ToEmails @('to@t.com') -Subject 'Test' -HtmlBody '<p>Test</p>'
            $result.Provider | Should -Be 'SendGrid'
            $result.Success | Should -BeTrue
            $result.Error | Should -BeNullOrEmpty
        }

        It 'includes recipient in message' {
            Mock Invoke-RestMethod { $null } -ModuleName PSGuerrilla
            $result = Send-SignalSendGrid -ApiKey 'SG.test' -FromEmail 'from@t.com' -ToEmails @('alert@corp.com') -Subject 'Test' -HtmlBody '<p>T</p>'
            $result.Message | Should -Match 'alert@corp.com'
        }
    }

    Context 'Default from name' {
        It 'uses PSGuerrilla Signals as default FromName' {
            Mock Invoke-RestMethod { $null } -ModuleName PSGuerrilla
            Send-SignalSendGrid -ApiKey 'SG.test' -FromEmail 'f@t.com' -ToEmails @('t@t.com') -Subject 'T' -HtmlBody '<p>T</p>'
            Should -Invoke Invoke-RestMethod -ModuleName PSGuerrilla -ParameterFilter { $Body -match 'PSGuerrilla Signals' }
        }
    }

    Context 'Retry on failure' {
        It 'retries once and returns success if retry works' {
            & (Get-Module PSGuerrilla) { $script:_testSgCallCount = 0 }
            Mock Invoke-RestMethod -ModuleName PSGuerrilla {
                $script:_testSgCallCount++
                if ($script:_testSgCallCount -eq 1) { throw 'API Error' }
                $null
            }
            $result = Send-SignalSendGrid -ApiKey 'SG.test' -FromEmail 'f@t.com' -ToEmails @('t@t.com') -Subject 'T' -HtmlBody '<p>T</p>'
            $result.Success | Should -BeTrue
            $result.Message | Should -Match 'retry'
        }

        It 'returns failure when both attempts fail' {
            Mock Invoke-RestMethod { throw 'Permanent failure' } -ModuleName PSGuerrilla
            $result = Send-SignalSendGrid -ApiKey 'SG.test' -FromEmail 'f@t.com' -ToEmails @('t@t.com') -Subject 'T' -HtmlBody '<p>T</p>'
            $result.Success | Should -BeFalse
            $result.Error | Should -Not -BeNullOrEmpty
        }
    }
}
