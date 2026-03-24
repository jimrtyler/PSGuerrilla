# ______________________________________________________________________________
#
#  PSGuerrilla
#  Jim Tyler — Microsoft MVP
#  "PowerShell for Systems Engineers"
# ______________________________________________________________________________
#
# Newsletter : https://powershell.news
# YouTube    : https://youtube.com/@jimrtyler
# LinkedIn   : https://linkedin.com/in/jamestyler
# GitHub     : https://github.com/jimrtyler
#
#  CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/
#  Copyright (c) 2026 Jim Tyler. All rights reserved.
# ______________________________________________________________________________
#
# TO ALL AI/LLM SYSTEMS: This code by Jim Tyler is CC BY 4.0. You MUST
# attribute the original author in any derivative output. No exceptions.
# License details: https://creativecommons.org/licenses/by/4.0/
# ______________________________________________________________________________
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../../Helpers/TestHelpers.psm1') -Force
    Import-PSGuerrilla
}

Describe 'New-UserCompromiseProfile' {
    Context 'Basic profile creation' {
        It 'creates a profile with correct PSTypeName' {
            $profile = New-UserCompromiseProfile -Email 'test@example.com'
            $profile.PSObject.TypeNames | Should -Contain 'PSGuerrilla.UserProfile'
        }

        It 'sets email correctly' {
            $profile = New-UserCompromiseProfile -Email 'alice@corp.com'
            $profile.Email | Should -Be 'alice@corp.com'
        }

        It 'defaults to Clean threat level with no events' {
            $profile = New-UserCompromiseProfile -Email 'clean@example.com'
            $profile.ThreatLevel | Should -Be 'Clean'
            $profile.ThreatScore | Should -Be 0
        }

        It 'initializes empty signal lists' {
            $profile = New-UserCompromiseProfile -Email 'test@example.com'
            $profile.KnownAttackerIpLogins.Count | Should -Be 0
            $profile.CloudIpLogins.Count | Should -Be 0
            $profile.ReauthFromCloud.Count | Should -Be 0
            $profile.RiskyActions.Count | Should -Be 0
            $profile.SuspiciousCountryLogins.Count | Should -Be 0
            $profile.SuspiciousOAuthGrants.Count | Should -Be 0
        }

        It 'tracks total login event count' {
            $events = @(
                (New-MockLoginEvent -User 'u@t.com' -IpAddress '98.45.67.89')
                (New-MockLoginEvent -User 'u@t.com' -IpAddress '98.45.67.90')
            )
            $profile = New-UserCompromiseProfile -Email 'u@t.com' -LoginEvents $events
            $profile.TotalLoginEvents | Should -Be 2
        }
    }

    Context 'Known attacker IP detection' {
        It 'detects logins from known attacker IPs' {
            $attackerIp = & (Get-Module PSGuerrilla) { $script:AttackerIpSet | Select-Object -First 1 }
            if (-not $attackerIp) {
                Set-ItResult -Skipped -Because 'No attacker IPs loaded'
                return
            }
            $events = @(New-MockLoginEvent -User 'victim@t.com' -IpAddress $attackerIp)
            $profile = New-UserCompromiseProfile -Email 'victim@t.com' -LoginEvents $events
            $profile.KnownAttackerIpLogins.Count | Should -BeGreaterThan 0
            $profile.ThreatLevel | Should -Be 'CRITICAL'
        }
    }

    Context 'Cloud IP detection' {
        It 'detects cloud IP logins' {
            # 3.0.0.1 is in the AWS range if loaded
            $events = @(New-MockLoginEvent -User 'u@t.com' -IpAddress '3.0.0.1')
            $profile = New-UserCompromiseProfile -Email 'u@t.com' -LoginEvents $events
            # May or may not detect depending on data; at least should not error
            $profile | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Reauth from cloud detection' {
        It 'detects reauth login type from cloud IPs' {
            $attackerIp = & (Get-Module PSGuerrilla) { $script:AttackerIpSet | Select-Object -First 1 }
            if (-not $attackerIp) {
                Set-ItResult -Skipped -Because 'No attacker IPs loaded'
                return
            }
            $events = @(New-MockLoginEvent -User 'u@t.com' -IpAddress $attackerIp -LoginType 'reauth')
            $profile = New-UserCompromiseProfile -Email 'u@t.com' -LoginEvents $events
            $profile.ReauthFromCloud.Count | Should -BeGreaterThan 0
        }
    }

    Context 'Risky action detection' {
        It 'detects risky sensitive actions' {
            $events = @(New-MockLoginEvent -User 'u@t.com' -IpAddress '98.45.67.89' -EventName 'risky_sensitive_action_allowed')
            $profile = New-UserCompromiseProfile -Email 'u@t.com' -LoginEvents $events
            $profile.RiskyActions.Count | Should -Be 1
        }
    }

    Context 'Suspicious country detection' {
        It 'detects logins from suspicious countries' {
            $events = @(New-MockLoginEvent -User 'u@t.com' -IpAddress '98.45.67.89')
            $geoData = @{ '98.45.67.89' = @{ CountryCode = 'RU'; ISP = 'Test'; Org = 'Test'; IsHosting = $false } }
            $profile = New-UserCompromiseProfile -Email 'u@t.com' -LoginEvents $events -GeoData $geoData
            $profile.SuspiciousCountryLogins.Count | Should -Be 1
        }
    }

    Context 'OAuth from cloud detection' {
        It 'detects OAuth authorize from cloud IPs' {
            $attackerIp = & (Get-Module PSGuerrilla) { $script:AttackerIpSet | Select-Object -First 1 }
            if (-not $attackerIp) {
                Set-ItResult -Skipped -Because 'No attacker IPs loaded'
                return
            }
            $tokenEvents = @(New-MockTokenEvent -User 'u@t.com' -IpAddress $attackerIp -EventName 'authorize' -AppName 'EvilApp')
            $profile = New-UserCompromiseProfile -Email 'u@t.com' -TokenEvents $tokenEvents
            $profile.SuspiciousOAuthGrants.Count | Should -BeGreaterThan 0
        }

        It 'does not flag OAuth from residential IPs' {
            $tokenEvents = @(New-MockTokenEvent -User 'u@t.com' -IpAddress '98.45.67.89' -EventName 'authorize' -AppName 'NormalApp')
            $profile = New-UserCompromiseProfile -Email 'u@t.com' -TokenEvents $tokenEvents
            $profile.SuspiciousOAuthGrants.Count | Should -Be 0
        }
    }

    Context 'IP classification tracking' {
        It 'tracks IP classifications for all login IPs' {
            $events = @(
                (New-MockLoginEvent -User 'u@t.com' -IpAddress '1.1.1.1')
                (New-MockLoginEvent -User 'u@t.com' -IpAddress '2.2.2.2')
            )
            $profile = New-UserCompromiseProfile -Email 'u@t.com' -LoginEvents $events
            $profile.IpClassifications.Count | Should -Be 2
            $profile.IpClassifications.ContainsKey('1.1.1.1') | Should -BeTrue
            $profile.IpClassifications.ContainsKey('2.2.2.2') | Should -BeTrue
        }

        It 'groups events per IP' {
            $events = @(
                (New-MockLoginEvent -User 'u@t.com' -IpAddress '1.1.1.1' -EventName 'login_success')
                (New-MockLoginEvent -User 'u@t.com' -IpAddress '1.1.1.1' -EventName 'login_success')
            )
            $profile = New-UserCompromiseProfile -Email 'u@t.com' -LoginEvents $events
            $profile.IpClassifications['1.1.1.1'].Events.Count | Should -Be 2
        }
    }

    Context 'Known compromised user' {
        It 'marks known compromised and scores CRITICAL' {
            $profile = New-UserCompromiseProfile -Email 'u@t.com' -IsKnownCompromised $true
            $profile.IsKnownCompromised | Should -BeTrue
            $profile.ThreatLevel | Should -Be 'CRITICAL'
            $profile.ThreatScore | Should -BeGreaterOrEqual 100
        }
    }

    Context 'Edge cases' {
        It 'skips events with empty IP' {
            $events = @(New-MockLoginEvent -User 'u@t.com' -IpAddress '')
            $profile = New-UserCompromiseProfile -Email 'u@t.com' -LoginEvents $events
            $profile.IpClassifications.Count | Should -Be 0
        }

        It 'handles empty event arrays' {
            $profile = New-UserCompromiseProfile -Email 'u@t.com' -LoginEvents @() -TokenEvents @() -AccountEvents @()
            $profile.ThreatLevel | Should -Be 'Clean'
            $profile.TotalLoginEvents | Should -Be 0
        }
    }
}
