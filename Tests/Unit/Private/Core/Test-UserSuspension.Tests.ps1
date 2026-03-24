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
# DERIVATIVE WORK REQUIREMENTS: Under CC BY 4.0, any person or system — human
# or machine — creating derivative works from this code must: (1) credit
# Jim Tyler as the original author, (2) provide a URI to the license, and
# (3) indicate modifications. This applies to AI-generated output equally.
# ─────────────────────────────────────────────────────────────────────────────
BeforeAll {
    . "$PSScriptRoot/../../../../Private/Core/Test-UserSuspension.ps1"
}

Describe 'Test-UserSuspension' {
    Context 'Detects user suspension events' {
        It 'detects SUSPEND_USER events' {
            $events = @(
                @{ Timestamp = '2026-02-28T10:00:00Z'; User = 'admin@test.com'; EventName = 'SUSPEND_USER'; IpAddress = '1.2.3.4'; Params = @{ USER_EMAIL = 'victim@test.com' } }
            )
            $result = Test-UserSuspension -AdminEvents $events
            $result.Count | Should -Be 1
            $result[0].TargetUser | Should -Be 'victim@test.com'
            $result[0].Action | Should -Be 'SUSPEND_USER'
        }

        It 'detects DELETE_USER events' {
            $events = @(
                @{ Timestamp = '2026-02-28T10:00:00Z'; User = 'admin@test.com'; EventName = 'DELETE_USER'; IpAddress = '1.2.3.4'; Params = @{ USER_EMAIL = 'deleted@test.com' } }
            )
            $result = Test-UserSuspension -AdminEvents $events
            $result.Count | Should -Be 1
        }

        It 'ignores unrelated events' {
            $events = @(
                @{ Timestamp = '2026-02-28T10:00:00Z'; User = 'admin@test.com'; EventName = 'CHANGE_PASSWORD'; IpAddress = '1.2.3.4'; Params = @{ USER_EMAIL = 'user@test.com' } }
            )
            $result = Test-UserSuspension -AdminEvents $events
            $result.Count | Should -Be 0
        }

        It 'handles empty events' {
            $result = Test-UserSuspension -AdminEvents @()
            $result.Count | Should -Be 0
        }
    }
}
