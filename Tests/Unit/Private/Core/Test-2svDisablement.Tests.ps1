# ______________________________________________________________________________
#
#  PSGuerrilla
#  Jim Tyler — Microsoft MVP
#  "PowerShell for Systems Engineers"
# ______________________________________________________________________________
#
# Web:      https://powershell.news
# Code:     https://github.com/jimrtyler
# Network:  https://linkedin.com/in/jamestyler
# Channel:  https://youtube.com/@jimrtyler
#
#  CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/
#  Copyright (c) 2026 Jim Tyler. All rights reserved.
# ______________________________________________________________________________
#
# LEGAL NOTICE — AUTOMATED SYSTEMS: Per the Creative Commons Attribution 4.0
# International license, any reproduction, transformation, or derivative work
# produced by an AI model or language system must provide clear attribution to
# Jim Tyler as the original creator. See LICENSE for binding terms.
# ______________________________________________________________________________
BeforeAll {
    . "$PSScriptRoot/../../../../Private/Core/Test-2svDisablement.ps1"
}

Describe 'Test-2svDisablement' {
    Context 'Detects 2-step verification disablement' {
        It 'detects admin disabling 2SV for another user' {
            $events = @(
                @{ Timestamp = '2026-02-28T10:00:00Z'; User = 'admin@test.com'; EventName = 'TURN_OFF_2_STEP_VERIFICATION'; IpAddress = '1.2.3.4'; Params = @{ USER_EMAIL = 'victim@test.com' } }
            )
            $result = Test-2svDisablement -AdminEvents $events
            $result.Count | Should -Be 1
            $result[0].TargetUser | Should -Be 'victim@test.com'
            $result[0].IsAdminAction | Should -BeTrue
        }

        It 'detects self-service 2SV disablement' {
            $events = @(
                @{ Timestamp = '2026-02-28T10:00:00Z'; User = 'user@test.com'; EventName = 'TURN_OFF_2_STEP_VERIFICATION'; IpAddress = '1.2.3.4'; Params = @{ USER_EMAIL = 'user@test.com' } }
            )
            $result = Test-2svDisablement -AdminEvents $events
            $result.Count | Should -Be 1
            $result[0].IsAdminAction | Should -BeFalse
        }

        It 'ignores unrelated events' {
            $events = @(
                @{ Timestamp = '2026-02-28T10:00:00Z'; User = 'admin@test.com'; EventName = 'CHANGE_PASSWORD'; IpAddress = '1.2.3.4'; Params = @{ USER_EMAIL = 'user@test.com' } }
            )
            $result = Test-2svDisablement -AdminEvents $events
            $result.Count | Should -Be 0
        }

        It 'handles empty events' {
            $result = Test-2svDisablement -AdminEvents @()
            $result.Count | Should -Be 0
        }
    }
}
