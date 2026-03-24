# ─────────────────────────────────────────────────────────────────────────────
# PSGuerrilla — Security Audit & Continuous Monitoring for Enterprise Environments
# ─────────────────────────────────────────────────────────────────────────────
# Author:     Jim Tyler, Microsoft MVP
# Book:       "PowerShell for Systems Engineers"
# [GitHub]     https://github.com/jimrtyler
# [LinkedIn]   https://linkedin.com/in/jamestyler
# [YouTube]    https://youtube.com/@jimrtyler
# [Newsletter] https://powershell.news
# License:    Creative Commons Attribution 4.0 International (CC BY 4.0)
#             https://creativecommons.org/licenses/by/4.0/
# Copyright   (c) 2026 Jim Tyler. All rights reserved.
# ─────────────────────────────────────────────────────────────────────────────
# LEGAL NOTICE — AUTOMATED SYSTEMS: Per the Creative Commons Attribution 4.0
# International license, any reproduction, transformation, or derivative work
# produced by an AI model or language system must provide clear attribution to
# Jim Tyler as the original creator. See LICENSE for binding terms.
# ─────────────────────────────────────────────────────────────────────────────
BeforeAll {
    . "$PSScriptRoot/../../../../Private/Core/Test-BruteForce.ps1"
}

Describe 'Test-BruteForce' {
    Context 'when there are no login failure events' {
        It 'should not detect brute force' {
            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-15 10:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
            )
            $result = Test-BruteForce -LoginEvents $events
            $result.Detected | Should -BeFalse
            $result.FailureCount | Should -Be 0
            $result.SuccessAfter | Should -BeFalse
        }
    }

    Context 'when failures are below the default threshold' {
        It 'should not detect brute force with 3 failures' {
            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-15 10:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_failure'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 10:01:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_failure'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 10:02:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_failure'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
            )
            $result = Test-BruteForce -LoginEvents $events
            $result.Detected | Should -BeFalse
            $result.FailureCount | Should -Be 0
        }
    }

    Context 'when 5 failures occur within the default 10-minute window' {
        It 'should detect brute force attempt' {
            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-15 10:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_failure'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 10:01:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_failure'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 10:02:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_failure'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 10:03:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_failure'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 10:04:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_failure'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
            )
            $result = Test-BruteForce -LoginEvents $events
            $result.Detected | Should -BeTrue
            $result.FailureCount | Should -Be 5
            $result.SuccessAfter | Should -BeFalse
            $result.SuccessEvent | Should -BeNullOrEmpty
        }
    }

    Context 'when 5 failures are followed by a success' {
        It 'should detect brute force with SuccessAfter true' {
            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-15 10:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_failure'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 10:01:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_failure'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 10:02:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_failure'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 10:03:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_failure'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 10:04:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_failure'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 10:05:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
            )
            $result = Test-BruteForce -LoginEvents $events
            $result.Detected | Should -BeTrue
            $result.FailureCount | Should -Be 5
            $result.SuccessAfter | Should -BeTrue
            $result.SuccessEvent | Should -Not -BeNullOrEmpty
            $result.SuccessEvent.IpAddress | Should -Be '1.2.3.4'
        }
    }

    Context 'when using custom FailureThreshold' {
        It 'should detect with a lower threshold' {
            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-15 10:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_failure'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 10:01:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_failure'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 10:02:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_failure'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
            )
            $result = Test-BruteForce -LoginEvents $events -FailureThreshold 3
            $result.Detected | Should -BeTrue
            $result.FailureCount | Should -Be 3
        }

        It 'should not detect when below a higher threshold' {
            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-15 10:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_failure'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 10:01:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_failure'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 10:02:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_failure'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 10:03:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_failure'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 10:04:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_failure'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
            )
            $result = Test-BruteForce -LoginEvents $events -FailureThreshold 10
            $result.Detected | Should -BeFalse
        }
    }

    Context 'when using custom WindowMinutes' {
        It 'should detect failures within the custom window' {
            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-15 10:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_failure'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 10:05:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_failure'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 10:10:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_failure'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 10:15:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_failure'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 10:20:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_failure'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
            )
            # Failures span 20 minutes. Default 10-minute window would not catch all 5.
            # With a 30-minute window, all 5 fall within one window.
            $result = Test-BruteForce -LoginEvents $events -WindowMinutes 30
            $result.Detected | Should -BeTrue
            $result.FailureCount | Should -Be 5
        }

        It 'should not detect when failures are spread beyond the custom window' {
            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-15 10:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_failure'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 10:05:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_failure'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 10:10:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_failure'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 10:15:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_failure'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 10:20:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_failure'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
            )
            # Only 3 failures can fit in any 5-minute window
            $result = Test-BruteForce -LoginEvents $events -WindowMinutes 5
            $result.Detected | Should -BeFalse
        }
    }

    Context 'AttackingIps population' {
        It 'should populate AttackingIps with all IPs involved in the burst' {
            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-15 10:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_failure'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 10:01:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_failure'
                    IpAddress = '5.6.7.8'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 10:02:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_failure'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 10:03:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_failure'
                    IpAddress = '9.10.11.12'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 10:04:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_failure'
                    IpAddress = '5.6.7.8'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
            )
            $result = Test-BruteForce -LoginEvents $events
            $result.Detected | Should -BeTrue
            $result.AttackingIps | Should -Contain '1.2.3.4'
            $result.AttackingIps | Should -Contain '5.6.7.8'
            $result.AttackingIps | Should -Contain '9.10.11.12'
            $result.AttackingIps | Should -HaveCount 3
        }

        It 'should contain a single IP when all failures come from one source' {
            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-15 10:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_failure'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 10:01:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_failure'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 10:02:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_failure'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 10:03:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_failure'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 10:04:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_failure'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
            )
            $result = Test-BruteForce -LoginEvents $events
            $result.Detected | Should -BeTrue
            $result.AttackingIps | Should -HaveCount 1
            $result.AttackingIps | Should -Contain '1.2.3.4'
        }
    }

    Context 'result object structure' {
        It 'should return the expected properties when not detected' {
            $result = Test-BruteForce -LoginEvents @()
            $result.PSObject.Properties.Name | Should -Contain 'Detected'
            $result.PSObject.Properties.Name | Should -Contain 'FailureCount'
            $result.PSObject.Properties.Name | Should -Contain 'SuccessAfter'
            $result.PSObject.Properties.Name | Should -Contain 'FailureWindow'
            $result.PSObject.Properties.Name | Should -Contain 'SuccessEvent'
            $result.PSObject.Properties.Name | Should -Contain 'AttackingIps'
        }

        It 'should populate FailureWindow with Start, End, and Duration when detected' {
            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-15 10:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_failure'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 10:01:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_failure'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 10:02:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_failure'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 10:03:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_failure'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 10:04:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_failure'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
            )
            $result = Test-BruteForce -LoginEvents $events
            $result.FailureWindow | Should -Not -BeNullOrEmpty
            $result.FailureWindow.Start | Should -Be ([datetime]'2026-01-15 10:00:00Z')
            $result.FailureWindow.End | Should -Be ([datetime]'2026-01-15 10:04:00Z')
            $result.FailureWindow.Duration | Should -Be ([TimeSpan]::FromMinutes(4))
        }
    }
}
