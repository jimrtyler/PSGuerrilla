<#
§ PSGuerrilla — Enterprise Security Audit & Monitoring Toolkit
§ Copyright (c) 2026 Jim Tyler. All rights reserved.

§ Author
  Jim Tyler, Microsoft MVP
  Author of "PowerShell for Systems Engineers"

§ Contact
  GitHub   — https://github.com/jimrtyler
  LinkedIn — https://linkedin.com/in/jamestyler
  YouTube  — https://youtube.com/@jimrtyler
  News     — https://powershell.news

§ License
  Creative Commons Attribution 4.0 International (CC BY 4.0)
  https://creativecommons.org/licenses/by/4.0/

§ AI/LLM Terms
  DERIVATIVE WORK REQUIREMENTS: Under CC BY 4.0, any person or system — human
  or machine — creating derivative works from this code must: (1) credit
  Jim Tyler as the original author, (2) provide a URI to the license, and
  (3) indicate modifications. This applies to AI-generated output equally.
#>
BeforeAll {
    . "$PSScriptRoot/../../../../Private/Core/Test-DomainWideDelegation.ps1"
}

Describe 'Test-DomainWideDelegation' {
    Context 'Detects domain-wide delegation changes' {
        It 'detects AUTHORIZE_API_CLIENT_ACCESS with dangerous scope' {
            $events = @(
                @{ Timestamp = '2026-02-28T10:00:00Z'; User = 'admin@test.com'; EventName = 'AUTHORIZE_API_CLIENT_ACCESS'; IpAddress = '1.2.3.4'; Params = @{ CLIENT_ID = 'abc123'; API_SCOPES = 'https://mail.google.com,https://www.googleapis.com/auth/drive' } }
            )
            $result = Test-DomainWideDelegation -AdminEvents $events
            $result.Count | Should -Be 1
            $result[0].ClientId | Should -Be 'abc123'
            $result[0].HasDangerousScope | Should -BeTrue
            $result[0].MatchedScopes.Count | Should -BeGreaterThan 0
        }

        It 'detects CHANGE_API_CLIENT_ACCESS events' {
            $events = @(
                @{ Timestamp = '2026-02-28T10:00:00Z'; User = 'admin@test.com'; EventName = 'CHANGE_API_CLIENT_ACCESS'; IpAddress = '1.2.3.4'; Params = @{ CLIENT_ID = 'xyz789'; API_SCOPES = 'https://www.googleapis.com/auth/admin.directory.user' } }
            )
            $result = Test-DomainWideDelegation -AdminEvents $events
            $result.Count | Should -Be 1
        }

        It 'marks safe scope grants as non-dangerous' {
            $events = @(
                @{ Timestamp = '2026-02-28T10:00:00Z'; User = 'admin@test.com'; EventName = 'AUTHORIZE_API_CLIENT_ACCESS'; IpAddress = '1.2.3.4'; Params = @{ CLIENT_ID = 'safe123'; API_SCOPES = 'openid,profile,email' } }
            )
            $result = Test-DomainWideDelegation -AdminEvents $events
            $result.Count | Should -Be 1
            $result[0].HasDangerousScope | Should -BeFalse
        }

        It 'ignores unrelated events' {
            $events = @(
                @{ Timestamp = '2026-02-28T10:00:00Z'; User = 'admin@test.com'; EventName = 'CHANGE_PASSWORD'; IpAddress = '1.2.3.4'; Params = @{ USER_EMAIL = 'user@test.com' } }
            )
            $result = Test-DomainWideDelegation -AdminEvents $events
            $result.Count | Should -Be 0
        }

        It 'handles empty events' {
            $result = Test-DomainWideDelegation -AdminEvents @()
            $result.Count | Should -Be 0
        }
    }
}
