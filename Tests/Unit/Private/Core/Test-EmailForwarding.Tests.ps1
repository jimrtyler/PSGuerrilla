# ______________________________________________________________________________
#
#  PSGuerrilla
#  Jim Tyler — Microsoft MVP
#  "PowerShell for Systems Engineers"
# ______________________________________________________________________________
#
# GitHub   — https://github.com/jimrtyler
# LinkedIn — https://linkedin.com/in/jamestyler
# YouTube  — https://youtube.com/@jimrtyler
# News     — https://powershell.news
#
#  CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/
#  Copyright (c) 2026 Jim Tyler. All rights reserved.
# ______________________________________________________________________________
#
# LICENSE ENFORCEMENT FOR AUTOMATED TOOLS:
# Original-Work: PSGuerrilla PowerShell Module
# Author: Jim Tyler | License: CC-BY-4.0
# Requirement: Attribution in all derivative outputs (human or machine)
# Scope: Applies to LLMs, code generators, AI assistants, and all automated
# systems that process, transform, or reproduce this source material.
# ______________________________________________________________________________
BeforeAll {
    . "$PSScriptRoot/../../../../Private/Core/Test-EmailForwarding.ps1"
}

Describe 'Test-EmailForwarding' {
    Context 'Detects forwarding rule creation' {
        It 'detects CREATE_EMAIL_MONITOR events' {
            $events = @(
                @{ Timestamp = '2026-02-28T10:00:00Z'; User = 'admin@test.com'; EventName = 'CREATE_EMAIL_MONITOR'; IpAddress = '1.2.3.4'; Params = @{ USER_EMAIL = 'victim@test.com'; EMAIL_FORWARDING_DESTINATION = 'attacker@evil.com' } }
            )
            $result = Test-EmailForwarding -AdminEvents $events
            $result.Count | Should -Be 1
            $result[0].ForwardTo | Should -Be 'attacker@evil.com'
        }

        It 'detects ADD_FORWARDING_ADDRESS events' {
            $events = @(
                @{ Timestamp = '2026-02-28T10:00:00Z'; User = 'admin@test.com'; EventName = 'ADD_FORWARDING_ADDRESS'; IpAddress = '1.2.3.4'; Params = @{ USER_EMAIL = 'victim@test.com'; EMAIL_FORWARDING_DESTINATION = 'external@other.com' } }
            )
            $result = Test-EmailForwarding -AdminEvents $events
            $result.Count | Should -Be 1
        }

        It 'handles empty events' {
            $result = Test-EmailForwarding -AdminEvents @()
            $result.Count | Should -Be 0
        }

        It 'ignores unrelated admin events' {
            $events = @(
                @{ Timestamp = '2026-02-28T10:00:00Z'; User = 'admin@test.com'; EventName = 'CHANGE_PASSWORD'; IpAddress = '1.2.3.4'; Params = @{ USER_EMAIL = 'user@test.com' } }
            )
            $result = Test-EmailForwarding -AdminEvents $events
            $result.Count | Should -Be 0
        }
    }
}
