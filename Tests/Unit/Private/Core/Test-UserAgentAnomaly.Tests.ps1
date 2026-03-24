<#
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  PSGuerrilla PowerShell Module
  By Jim Tyler, Microsoft MVP
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  "PowerShell for Systems Engineers"

  • GitHub     https://github.com/jimrtyler
  • LinkedIn   https://linkedin.com/in/jamestyler
  • YouTube    https://youtube.com/@jimrtyler
  • Newsletter https://powershell.news

  License: Creative Commons Attribution 4.0 International (CC BY 4.0)
           https://creativecommons.org/licenses/by/4.0/
  Copyright (c) 2026 Jim Tyler. All rights reserved.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  DERIVATIVE WORK REQUIREMENTS: Under CC BY 4.0, any person or system — human
  or machine — creating derivative works from this code must: (1) credit
  Jim Tyler as the original author, (2) provide a URI to the license, and
  (3) indicate modifications. This applies to AI-generated output equally.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#>
BeforeAll {
    . "$PSScriptRoot/../../../../Private/Core/Test-UserAgentAnomaly.ps1"
}

Describe 'Test-UserAgentAnomaly' {
    Context 'when there are no events' {
        It 'should return an empty array' {
            $result = Test-UserAgentAnomaly -LoginEvents @()
            $result | Should -HaveCount 0
        }
    }

    Context 'when events have a normal user agent' {
        It 'should not flag a standard browser user agent' {
            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-15 10:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{
                        login_type = 'exchange'
                        user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
                    }
                }
            )
            $result = Test-UserAgentAnomaly -LoginEvents $events
            $result | Should -HaveCount 0
        }
    }

    Context 'when events have HeadlessChrome user agent' {
        It 'should detect HeadlessChrome with the correct label' {
            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-15 10:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{
                        login_type = 'exchange'
                        user_agent = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36'
                    }
                }
            )
            $result = Test-UserAgentAnomaly -LoginEvents $events
            $result | Should -HaveCount 1
            $result[0].MatchLabel | Should -Be 'Headless Chrome'
            $result[0].UserAgent | Should -Match 'HeadlessChrome'
            $result[0].IpAddress | Should -Be '1.2.3.4'
        }
    }

    Context 'when events have python-requests user agent' {
        It 'should detect python-requests with the correct label' {
            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-15 10:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '5.6.7.8'
                    Source    = 'login'
                    Params    = @{
                        login_type = 'exchange'
                        user_agent = 'python-requests/2.31.0'
                    }
                }
            )
            $result = Test-UserAgentAnomaly -LoginEvents $events
            $result | Should -HaveCount 1
            $result[0].MatchLabel | Should -Be 'Python requests library'
            $result[0].IpAddress | Should -Be '5.6.7.8'
        }
    }

    Context 'when events have curl user agent' {
        It 'should detect curl' {
            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-15 10:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{
                        login_type = 'exchange'
                        user_agent = 'curl/8.4.0'
                    }
                }
            )
            $result = Test-UserAgentAnomaly -LoginEvents $events
            $result | Should -HaveCount 1
            $result[0].MatchLabel | Should -Be 'curl'
        }
    }

    Context 'when multiple anomalous user agents are present' {
        It 'should capture all anomalies' {
            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-15 10:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{
                        login_type = 'exchange'
                        user_agent = 'python-requests/2.31.0'
                    }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 11:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '5.6.7.8'
                    Source    = 'login'
                    Params    = @{
                        login_type = 'exchange'
                        user_agent = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 HeadlessChrome/120.0.0.0'
                    }
                }
                @{
                    Timestamp = [datetime]'2026-01-15 12:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '9.10.11.12'
                    Source    = 'login'
                    Params    = @{
                        login_type = 'exchange'
                        user_agent = 'Selenium/4.15.2'
                    }
                }
            )
            $result = Test-UserAgentAnomaly -LoginEvents $events
            $result | Should -HaveCount 3
            $result[0].MatchLabel | Should -Be 'Python requests library'
            $result[1].MatchLabel | Should -Be 'Headless Chrome'
            $result[2].MatchLabel | Should -Be 'Selenium automation'
        }
    }

    Context 'when events do not have a user_agent param' {
        It 'should skip events without user_agent' {
            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-15 10:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{
                        login_type = 'exchange'
                    }
                }
            )
            $result = Test-UserAgentAnomaly -LoginEvents $events
            $result | Should -HaveCount 0
        }
    }

    Context 'when events use the userAgent key variant' {
        It 'should detect using the userAgent key as well' {
            $events = @(
                @{
                    Timestamp = [datetime]'2026-01-15 10:00:00Z'
                    User      = 'user@example.com'
                    EventName = 'login_success'
                    IpAddress = '1.2.3.4'
                    Source    = 'login'
                    Params    = @{
                        login_type = 'exchange'
                        userAgent  = 'wget/1.21'
                    }
                }
            )
            $result = Test-UserAgentAnomaly -LoginEvents $events
            $result | Should -HaveCount 1
            $result[0].MatchLabel | Should -Be 'wget'
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
                    Params    = @{
                        login_type = 'exchange'
                        user_agent = 'python-requests/2.31.0'
                    }
                }
            )
            $result = Test-UserAgentAnomaly -LoginEvents $events
            $result[0].PSObject.Properties.Name | Should -Contain 'Timestamp'
            $result[0].PSObject.Properties.Name | Should -Contain 'IpAddress'
            $result[0].PSObject.Properties.Name | Should -Contain 'UserAgent'
            $result[0].PSObject.Properties.Name | Should -Contain 'MatchLabel'
            $result[0].PSObject.Properties.Name | Should -Contain 'EventName'
        }
    }
}
