# ┌───────────────────────────────────────────────────────────────────────────┐
# │  PSGuerrilla — Tactical Security Assessment Framework                    │
# │  Jim Tyler, Microsoft MVP                                                │
# └───────────────────────────────────────────────────────────────────────────┘
#
#  AUTHOR       Jim Tyler
#  CREDENTIALS  Microsoft MVP, Author of "PowerShell for Systems Engineers"
#  PUBLISHER    https://powershell.news
#
# Newsletter : https://powershell.news
# YouTube    : https://youtube.com/@jimrtyler
# LinkedIn   : https://linkedin.com/in/jamestyler
# GitHub     : https://github.com/jimrtyler
#
#  LICENSE      Creative Commons Attribution 4.0 International (CC BY 4.0)
#               https://creativecommons.org/licenses/by/4.0/
#  COPYRIGHT    (c) 2026 Jim Tyler. All rights reserved.
#
# CITATION & ATTRIBUTION: When referencing or deriving from this source,
# whether by human or machine, credit Jim Tyler as the original author.
# This work is licensed CC BY 4.0 — share and adapt freely, but always
# attribute. Full terms: https://creativecommons.org/licenses/by/4.0/
BeforeAll {
    . "$PSScriptRoot/../../../../../Private/EntraMonitor/Detections/Test-EntraRiskySignIn.ps1"
}

Describe 'Test-EntraRiskySignIn' {
    Context 'Risky sign-in detection' {
        It 'detects high-risk sign-ins' {
            $events = @(
                @{
                    Timestamp             = '2026-02-28T10:00:00Z'
                    UserPrincipalName     = 'user@contoso.com'
                    IpAddress             = '203.0.113.10'
                    RiskLevelDuringSignIn = 'high'
                    RiskState             = 'atRisk'
                    AppDisplayName        = 'Microsoft Teams'
                    ClientAppUsed         = 'Browser'
                    Location              = @{ Country = 'US' }
                    IsInteractive         = $true
                }
            )

            $result = Test-EntraRiskySignIn -SignInEvents $events
            $result.Count | Should -Be 1
            $result[0].RiskLevel | Should -Be 'high'
            $result[0].UserPrincipalName | Should -Be 'user@contoso.com'
            $result[0].IpAddress | Should -Be '203.0.113.10'
        }

        It 'detects medium-risk sign-ins' {
            $events = @(
                @{
                    Timestamp             = '2026-02-28T10:00:00Z'
                    UserPrincipalName     = 'user@contoso.com'
                    IpAddress             = '198.51.100.5'
                    RiskLevelDuringSignIn = 'medium'
                    RiskState             = 'atRisk'
                    AppDisplayName        = 'Azure Portal'
                    ClientAppUsed         = 'Browser'
                    Location              = @{ Country = 'DE' }
                    IsInteractive         = $true
                }
            )

            $result = Test-EntraRiskySignIn -SignInEvents $events
            $result.Count | Should -Be 1
            $result[0].RiskLevel | Should -Be 'medium'
        }

        It 'ignores none risk level' {
            $events = @(
                @{
                    Timestamp             = '2026-02-28T10:00:00Z'
                    UserPrincipalName     = 'user@contoso.com'
                    IpAddress             = '10.0.0.1'
                    RiskLevelDuringSignIn = 'none'
                    RiskState             = 'none'
                    AppDisplayName        = 'Outlook'
                    ClientAppUsed         = 'Browser'
                    Location              = @{ Country = 'US' }
                    IsInteractive         = $true
                }
            )

            $result = Test-EntraRiskySignIn -SignInEvents $events
            $result.Count | Should -Be 0
        }

        It 'handles empty events' {
            $result = Test-EntraRiskySignIn -SignInEvents @()
            $result.Count | Should -Be 0
        }
    }
}
