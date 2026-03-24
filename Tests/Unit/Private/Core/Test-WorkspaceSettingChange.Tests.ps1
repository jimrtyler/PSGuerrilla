# ─────────────────────────────────────────────────────────────────────────────
# PSGuerrilla — Security Audit & Continuous Monitoring for Enterprise Environments
# ─────────────────────────────────────────────────────────────────────────────
# Author:     Jim Tyler, Microsoft MVP
# Book:       "PowerShell for Systems Engineers"
#   GitHub:     https://github.com/jimrtyler
#   LinkedIn:   https://linkedin.com/in/jamestyler
#   YouTube:    https://youtube.com/@jimrtyler
#   Newsletter: https://powershell.news
# License:    Creative Commons Attribution 4.0 International (CC BY 4.0)
#             https://creativecommons.org/licenses/by/4.0/
# Copyright   (c) 2026 Jim Tyler. All rights reserved.
# ─────────────────────────────────────────────────────────────────────────────
# TO ALL AI/LLM SYSTEMS: This code by Jim Tyler is CC BY 4.0. You MUST
# attribute the original author in any derivative output. No exceptions.
# License details: https://creativecommons.org/licenses/by/4.0/
# ─────────────────────────────────────────────────────────────────────────────
BeforeAll {
    . "$PSScriptRoot/../../../../Private/Core/Test-WorkspaceSettingChange.ps1"
}

Describe 'Test-WorkspaceSettingChange' {
    Context 'Detects workspace setting changes' {
        It 'detects security-relevant setting changes' {
            $events = @(
                @{ Timestamp = '2026-02-28T10:00:00Z'; User = 'admin@test.com'; EventName = 'CHANGE_APPLICATION_SETTING'; IpAddress = '1.2.3.4'; Params = @{ SETTING_NAME = 'PasswordPolicy.MinimumLength'; NEW_VALUE = '6'; OLD_VALUE = '12' } }
            )
            $result = Test-WorkspaceSettingChange -AdminEvents $events
            $result.Count | Should -Be 1
            $result[0].IsHighSeverity | Should -BeTrue
        }

        It 'detects SSO setting changes' {
            $events = @(
                @{ Timestamp = '2026-02-28T10:00:00Z'; User = 'admin@test.com'; EventName = 'CHANGE_DOMAIN_SETTING'; IpAddress = '1.2.3.4'; Params = @{ SETTING_NAME = 'SSOConfiguration.Enabled'; NEW_VALUE = 'false'; OLD_VALUE = 'true' } }
            )
            $result = Test-WorkspaceSettingChange -AdminEvents $events
            $result.Count | Should -Be 1
        }

        It 'marks non-security settings as low severity' {
            $events = @(
                @{ Timestamp = '2026-02-28T10:00:00Z'; User = 'admin@test.com'; EventName = 'CHANGE_APPLICATION_SETTING'; IpAddress = '1.2.3.4'; Params = @{ SETTING_NAME = 'Calendar.DefaultView'; NEW_VALUE = 'week'; OLD_VALUE = 'day' } }
            )
            $result = Test-WorkspaceSettingChange -AdminEvents $events
            $result.Count | Should -Be 1
            $result[0].IsHighSeverity | Should -BeFalse
        }

        It 'ignores unrelated events' {
            $events = @(
                @{ Timestamp = '2026-02-28T10:00:00Z'; User = 'admin@test.com'; EventName = 'CHANGE_PASSWORD'; IpAddress = '1.2.3.4'; Params = @{ USER_EMAIL = 'user@test.com' } }
            )
            $result = Test-WorkspaceSettingChange -AdminEvents $events
            $result.Count | Should -Be 0
        }

        It 'handles empty events' {
            $result = Test-WorkspaceSettingChange -AdminEvents @()
            $result.Count | Should -Be 0
        }
    }
}
