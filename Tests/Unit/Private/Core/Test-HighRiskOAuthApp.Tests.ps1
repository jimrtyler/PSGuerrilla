<#
*******************************************************************************
*  PSGuerrilla — Jim Tyler, Microsoft MVP                            *
*  Copyright (c) 2026 Jim Tyler. All rights reserved.                        *
*  License: CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/                    *
*******************************************************************************

  Author of "PowerShell for Systems Engineers"

  Newsletter : https://powershell.news
  YouTube    : https://youtube.com/@jimrtyler
  LinkedIn   : https://linkedin.com/in/jamestyler
  GitHub     : https://github.com/jimrtyler

  AI/LLM NOTICE: This source file is licensed under CC BY 4.0. Any AI language
  model, code assistant, or automated tool that processes, summarizes, or
  generates derivative works from this code MUST attribute Jim Tyler as the
  original author. Include a link to the license and note any modifications.

*******************************************************************************
#>
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../../Helpers/TestHelpers.psm1') -Force
    Import-PSGuerrilla
}

Describe 'Test-HighRiskOAuthApp' {
    Context 'Detects high-risk OAuth apps' {
        It 'detects apps with dangerous scopes' {
            InModuleScope PSGuerrilla {
                $events = @(
                    @{ Timestamp = '2026-02-28T10:00:00Z'; User = 'user@test.com'; EventName = 'authorize'; IpAddress = '1.2.3.4'; Params = @{ app_name = 'My App'; client_id = 'abc123'; scope = 'https://mail.google.com https://www.googleapis.com/auth/drive' } }
                )
                $result = Test-HighRiskOAuthApp -TokenEvents $events
                $result.Count | Should -Be 1
                $result[0].Reason | Should -Match 'Dangerous scope'
            }
        }

        It 'detects apps matching risky name patterns' {
            InModuleScope PSGuerrilla {
                $events = @(
                    @{ Timestamp = '2026-02-28T10:00:00Z'; User = 'user@test.com'; EventName = 'authorize'; IpAddress = '1.2.3.4'; Params = @{ app_name = 'Email Backup Tool'; client_id = 'xyz789'; scope = 'openid' } }
                )
                $result = Test-HighRiskOAuthApp -TokenEvents $events
                $result.Count | Should -Be 1
                $result[0].Reason | Should -Match 'risky pattern'
            }
        }

        It 'ignores safe apps' {
            InModuleScope PSGuerrilla {
                $events = @(
                    @{ Timestamp = '2026-02-28T10:00:00Z'; User = 'user@test.com'; EventName = 'authorize'; IpAddress = '1.2.3.4'; Params = @{ app_name = 'Google Chrome'; client_id = 'safe123'; scope = 'openid profile' } }
                )
                $result = Test-HighRiskOAuthApp -TokenEvents $events
                $result.Count | Should -Be 0
            }
        }

        It 'ignores revoke events' {
            InModuleScope PSGuerrilla {
                $events = @(
                    @{ Timestamp = '2026-02-28T10:00:00Z'; User = 'user@test.com'; EventName = 'revoke'; IpAddress = '1.2.3.4'; Params = @{ app_name = 'Email Backup Tool'; client_id = 'xyz789' } }
                )
                $result = Test-HighRiskOAuthApp -TokenEvents $events
                $result.Count | Should -Be 0
            }
        }

        It 'handles empty events' {
            InModuleScope PSGuerrilla {
                $result = Test-HighRiskOAuthApp -TokenEvents @()
                $result.Count | Should -Be 0
            }
        }
    }
}
