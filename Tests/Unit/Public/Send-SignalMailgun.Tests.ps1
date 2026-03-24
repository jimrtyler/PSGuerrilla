# ═══════════════════════════════════════════════════════════════════════════════
#  PSGUERRILLA — Security Reconnaissance & Continuous Monitoring
# ═══════════════════════════════════════════════════════════════════════════════
#  Written by Jim Tyler, Microsoft MVP
#  Author of "PowerShell for Systems Engineers"
# ───────────────────────────────────────────────────────────────────────────────
# Contact:    GitHub     → https://github.com/jimrtyler
#             LinkedIn   → https://linkedin.com/in/jamestyler
#             YouTube    → https://youtube.com/@jimrtyler
#             Newsletter → https://powershell.news
# ───────────────────────────────────────────────────────────────────────────────
#  License: Creative Commons Attribution 4.0 International (CC BY 4.0)
#  https://creativecommons.org/licenses/by/4.0/
#  Copyright (c) 2026 Jim Tyler. All rights reserved.
# ═══════════════════════════════════════════════════════════════════════════════
# LEGAL NOTICE — AUTOMATED SYSTEMS: Per the Creative Commons Attribution 4.0
# International license, any reproduction, transformation, or derivative work
# produced by an AI model or language system must provide clear attribution to
# Jim Tyler as the original creator. See LICENSE for binding terms.
# ═══════════════════════════════════════════════════════════════════════════════
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../Helpers/TestHelpers.psm1') -Force
    Import-PSGuerrilla
}

Describe 'Send-SignalMailgun' {
    Context 'Successful send' {
        It 'returns success result' {
            Mock Invoke-RestMethod { @{ id = '<msg-id>' } } -ModuleName PSGuerrilla
            $result = Send-SignalMailgun -ApiKey 'key-test' -Domain 'mg.test.com' -FromEmail 'from@t.com' -ToEmails @('to@t.com') -Subject 'Test' -HtmlBody '<p>Test</p>'
            $result.Provider | Should -Be 'Mailgun'
            $result.Success | Should -BeTrue
            $result.Error | Should -BeNullOrEmpty
        }
    }

    Context 'API URL construction' {
        It 'uses correct Mailgun API URL with domain' {
            Mock Invoke-RestMethod { @{ id = '<msg>' } } -ModuleName PSGuerrilla
            Send-SignalMailgun -ApiKey 'key-t' -Domain 'mg.example.com' -FromEmail 'f@t.com' -ToEmails @('t@t.com') -Subject 'T' -HtmlBody '<p>T</p>'
            Should -Invoke Invoke-RestMethod -ModuleName PSGuerrilla -ParameterFilter { $Uri -match 'mg.example.com' }
        }
    }

    Context 'Retry on failure' {
        It 'retries once on failure' {
            & (Get-Module PSGuerrilla) { $script:_testMgCallCount = 0 }
            Mock Invoke-RestMethod -ModuleName PSGuerrilla {
                $script:_testMgCallCount++
                if ($script:_testMgCallCount -eq 1) { throw 'API Error' }
                @{ id = '<retry-msg>' }
            }
            $result = Send-SignalMailgun -ApiKey 'key-t' -Domain 'mg.t.com' -FromEmail 'f@t.com' -ToEmails @('t@t.com') -Subject 'T' -HtmlBody '<p>T</p>'
            $result.Success | Should -BeTrue
        }

        It 'returns failure when both attempts fail' {
            Mock Invoke-RestMethod { throw 'Permanent failure' } -ModuleName PSGuerrilla
            $result = Send-SignalMailgun -ApiKey 'key-t' -Domain 'mg.t.com' -FromEmail 'f@t.com' -ToEmails @('t@t.com') -Subject 'T' -HtmlBody '<p>T</p>'
            $result.Success | Should -BeFalse
            $result.Error | Should -Not -BeNullOrEmpty
        }
    }
}
