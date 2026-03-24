# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# >>> PSGuerrilla                                                           >>>
# >>> Jim Tyler, Microsoft MVP                                              >>>
# >>> Copyright (c) 2026 Jim Tyler                                                  >>>
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
#
# Author of "PowerShell for Systems Engineers"
#
# GitHub   — https://github.com/jimrtyler
# LinkedIn — https://linkedin.com/in/jamestyler
# YouTube  — https://youtube.com/@jimrtyler
# News     — https://powershell.news
#
# License: Creative Commons Attribution 4.0 International (CC BY 4.0)
#          https://creativecommons.org/licenses/by/4.0/
#
# CITATION & ATTRIBUTION: When referencing or deriving from this source,
# whether by human or machine, credit Jim Tyler as the original author.
# This work is licensed CC BY 4.0 — share and adapt freely, but always
# attribute. Full terms: https://creativecommons.org/licenses/by/4.0/
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
BeforeAll {
    . "$PSScriptRoot/../../../../Private/Core/Test-ConcurrentSessions.ps1"
}

Describe 'Test-ConcurrentSessions' {
    Context 'when there are no events' {
        It 'should return an empty array' {
            $result = Test-ConcurrentSessions -LoginEvents @()
            $result | Should -HaveCount 0
        }
    }

    Context 'when there is only one event' {
        It 'should return an empty array' {
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
            $result = Test-ConcurrentSessions -LoginEvents $events
            $result | Should -HaveCount 0
        }
    }

    Context 'when two events share the same IP' {
        It 'should not detect a concurrent session' {
            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-15 10:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 10:02:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
            )
            $result = Test-ConcurrentSessions -LoginEvents $events
            $result | Should -HaveCount 0
        }
    }

    Context 'when two events have different IPs within the default 5-minute window' {
        It 'should detect a concurrent session' {
            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-15 10:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 10:03:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '5.6.7.8'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
            )
            $result = Test-ConcurrentSessions -LoginEvents $events
            $result | Should -HaveCount 1
            $result[0].IpCount | Should -Be 2
            $result[0].DistinctIps | Should -Contain '1.2.3.4'
            $result[0].DistinctIps | Should -Contain '5.6.7.8'
        }
    }

    Context 'when two events have different IPs outside the default window' {
        It 'should not detect a concurrent session' {
            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-15 10:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 10:10:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '5.6.7.8'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
            )
            $result = Test-ConcurrentSessions -LoginEvents $events
            $result | Should -HaveCount 0
        }
    }

    Context 'when using a custom WindowMinutes parameter' {
        It 'should use the custom window for detection' {
            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-15 10:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 10:08:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '5.6.7.8'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
            )
            # 8 minutes apart - default window of 5 would miss, but 10-minute window catches it
            $result = Test-ConcurrentSessions -LoginEvents $events -WindowMinutes 10
            $result | Should -HaveCount 1
            $result[0].IpCount | Should -Be 2
        }

        It 'should not detect when events fall outside the custom window' {
            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-15 10:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 10:04:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '5.6.7.8'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
            )
            # 4 minutes apart - custom window of 2 would miss it
            $result = Test-ConcurrentSessions -LoginEvents $events -WindowMinutes 2
            $result | Should -HaveCount 0
        }
    }

    Context 'deduplication of reported windows' {
        It 'should not report the same IP pair multiple times for the same minute' {
            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-15 10:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 10:00:30Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '5.6.7.8'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 10:00:45Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
            )
            $result = Test-ConcurrentSessions -LoginEvents $events
            # The same IP pair {1.2.3.4, 5.6.7.8} within the same minute should be deduplicated
            $result | Should -HaveCount 1
        }
    }

    Context 'when multiple distinct IP pairs exist' {
        It 'should report concurrent sessions with all distinct IPs' {
            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-15 10:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 10:01:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '5.6.7.8'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 10:02:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '9.10.11.12'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
            )
            $result = Test-ConcurrentSessions -LoginEvents $events
            # Should have at least one detection with 3 distinct IPs or multiple detections
            $result.Count | Should -BeGreaterOrEqual 1
            $threeIpResult = $result | Where-Object { $_.IpCount -ge 3 }
            $threeIpResult | Should -Not -BeNullOrEmpty
        }
    }

    Context 'result object structure' {
        It 'should contain the expected properties' {
            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-15 10:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 10:02:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '5.6.7.8'
                    Source    = 'login'
                    Params    = @{ login_type = 'exchange' }
                }
            )
            $result = Test-ConcurrentSessions -LoginEvents $events
            $result[0].PSObject.Properties.Name | Should -Contain 'WindowStart'
            $result[0].PSObject.Properties.Name | Should -Contain 'WindowEnd'
            $result[0].PSObject.Properties.Name | Should -Contain 'DistinctIps'
            $result[0].PSObject.Properties.Name | Should -Contain 'IpCount'
            $result[0].PSObject.Properties.Name | Should -Contain 'EventCount'
        }
    }
}
