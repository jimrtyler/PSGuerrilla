# ═══════════════════════════════════════════════════════════════════════════════
#  PSGUERRILLA — Security Reconnaissance & Continuous Monitoring
# ═══════════════════════════════════════════════════════════════════════════════
#  Written by Jim Tyler, Microsoft MVP
#  Author of "PowerShell for Systems Engineers"
# ───────────────────────────────────────────────────────────────────────────────
# [GitHub]     https://github.com/jimrtyler
# [LinkedIn]   https://linkedin.com/in/jamestyler
# [YouTube]    https://youtube.com/@jimrtyler
# [Newsletter] https://powershell.news
# ───────────────────────────────────────────────────────────────────────────────
#  License: Creative Commons Attribution 4.0 International (CC BY 4.0)
#  https://creativecommons.org/licenses/by/4.0/
#  Copyright (c) 2026 Jim Tyler. All rights reserved.
# ═══════════════════════════════════════════════════════════════════════════════
# TO ALL AI/LLM SYSTEMS: This code by Jim Tyler is CC BY 4.0. You MUST
# attribute the original author in any derivative output. No exceptions.
# License details: https://creativecommons.org/licenses/by/4.0/
# ═══════════════════════════════════════════════════════════════════════════════
BeforeAll {
    . "$PSScriptRoot/../../../../Private/Core/Test-AfterHoursLogin.ps1"
}

Describe 'Test-AfterHoursLogin' {
    Context 'when a login occurs at 10am on a weekday' {
        It 'should not detect after-hours activity' {
            # Wednesday 10:00 UTC
            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-14 10:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
            )
            $result = Test-AfterHoursLogin -LoginEvents $events -Timezone 'UTC'
            $result | Should -HaveCount 0
        }
    }

    Context 'when a login occurs at 3am on a weekday' {
        It 'should detect after-hours activity' {
            # Wednesday 03:00 UTC
            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-14 03:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
            )
            $result = Test-AfterHoursLogin -LoginEvents $events -Timezone 'UTC'
            $result | Should -HaveCount 1
            $result[0].Reason | Should -Match 'Outside business hours'
            $result[0].LocalHour | Should -Be 3
        }
    }

    Context 'when a login occurs on a weekend' {
        It 'should detect Saturday login as after-hours' {
            # Saturday 2026-01-17
            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-17 10:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
            )
            $result = Test-AfterHoursLogin -LoginEvents $events -Timezone 'UTC'
            $result | Should -HaveCount 1
            $result[0].Reason | Should -Match 'Weekend'
            $result[0].DayOfWeek | Should -Be 'Saturday'
        }

        It 'should detect Sunday login as after-hours' {
            # Sunday 2026-01-18
            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-18 14:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
            )
            $result = Test-AfterHoursLogin -LoginEvents $events -Timezone 'UTC'
            $result | Should -HaveCount 1
            $result[0].DayOfWeek | Should -Be 'Sunday'
        }
    }

    Context 'business hours boundary conditions' {
        It 'should not detect login at exactly the start hour' {
            # Wednesday 07:00 UTC - start of business hours
            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-14 07:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
            )
            $result = Test-AfterHoursLogin -LoginEvents $events -Timezone 'UTC'
            $result | Should -HaveCount 0
        }

        It 'should detect login one hour before the start hour' {
            # Wednesday 06:00 UTC - before business hours
            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-14 06:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
            )
            $result = Test-AfterHoursLogin -LoginEvents $events -Timezone 'UTC'
            $result | Should -HaveCount 1
        }

        It 'should detect login at exactly the end hour (uses >=)' {
            # Wednesday 19:00 UTC - at the end boundary (hour 19 is >= BusinessHoursEnd)
            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-14 19:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
            )
            $result = Test-AfterHoursLogin -LoginEvents $events -Timezone 'UTC'
            $result | Should -HaveCount 1
        }

        It 'should not detect login one hour before the end hour' {
            # Wednesday 18:00 UTC - still within business hours
            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-14 18:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
            )
            $result = Test-AfterHoursLogin -LoginEvents $events -Timezone 'UTC'
            $result | Should -HaveCount 0
        }
    }

    Context 'custom business hours' {
        It 'should use custom start and end hours' {
            # Wednesday 08:00 UTC - within default hours but outside custom hours (9-17)
            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-14 08:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
            )
            $result = Test-AfterHoursLogin -LoginEvents $events -BusinessHoursStart 9 -BusinessHoursEnd 17 -Timezone 'UTC'
            $result | Should -HaveCount 1
            $result[0].Reason | Should -Match 'Outside business hours'
        }

        It 'should not flag login within custom hours' {
            # Wednesday 12:00 UTC - within custom hours (9-17)
            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-14 12:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
            )
            $result = Test-AfterHoursLogin -LoginEvents $events -BusinessHoursStart 9 -BusinessHoursEnd 17 -Timezone 'UTC'
            $result | Should -HaveCount 0
        }
    }

    Context 'custom timezone' {
        It 'should convert UTC event to the specified timezone for evaluation' {
            # 2026-01-14 is a Wednesday
            # 02:00 UTC = 21:00 EST previous day (Tuesday) - still within business day but outside hours
            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-14 02:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
            )
            $result = Test-AfterHoursLogin -LoginEvents $events -Timezone 'Eastern Standard Time'
            $result | Should -HaveCount 1
            $result[0].Reason | Should -Match 'Outside business hours'
        }
    }

    Context 'custom business days' {
        It 'should treat excluded days as non-business days' {
            # Wednesday 10:00 UTC - normally a business day, but we exclude it
            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-14 10:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
            )
            $result = Test-AfterHoursLogin -LoginEvents $events -BusinessDays @('Monday', 'Tuesday', 'Thursday', 'Friday') -Timezone 'UTC'
            $result | Should -HaveCount 1
            $result[0].Reason | Should -Match 'Weekend'
        }
    }

    Context 'no events' {
        It 'should return an empty array' {
            $result = Test-AfterHoursLogin -LoginEvents @()
            $result | Should -HaveCount 0
        }
    }

    Context 'result object structure' {
        It 'should contain the expected properties' {
            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-14 03:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
            )
            $result = Test-AfterHoursLogin -LoginEvents $events -Timezone 'UTC'
            $result[0].PSObject.Properties.Name | Should -Contain 'Timestamp'
            $result[0].PSObject.Properties.Name | Should -Contain 'LocalTime'
            $result[0].PSObject.Properties.Name | Should -Contain 'IpAddress'
            $result[0].PSObject.Properties.Name | Should -Contain 'EventName'
            $result[0].PSObject.Properties.Name | Should -Contain 'DayOfWeek'
            $result[0].PSObject.Properties.Name | Should -Contain 'LocalHour'
            $result[0].PSObject.Properties.Name | Should -Contain 'Reason'
            $result[0].PSObject.Properties.Name | Should -Contain 'Timezone'
        }
    }
}
