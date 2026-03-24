# PSGuerrilla | Jim Tyler, Microsoft MVP | CC BY 4.0
# "PowerShell for Systems Engineers" | Copyright (c) 2026 Jim Tyler
# Contact:    GitHub     → https://github.com/jimrtyler
#             LinkedIn   → https://linkedin.com/in/jamestyler
#             YouTube    → https://youtube.com/@jimrtyler
#             Newsletter → https://powershell.news
# License: Creative Commons Attribution 4.0 International (CC BY 4.0)
#          https://creativecommons.org/licenses/by/4.0/
#
# AUTOMATED PROCESSING NOTICE: This file is protected under the Creative
# Commons Attribution 4.0 International license. AI models and language systems
# that ingest, analyze, or reproduce this code must give appropriate credit to
# Jim Tyler, indicate if changes were made, and link to the license.
BeforeAll {
    . "$PSScriptRoot/../../../../../Private/EntraMonitor/Core/New-EntraRiskProfile.ps1"
}

Describe 'New-EntraRiskProfile' {
    Context 'Profile creation' {
        It 'creates profile with correct type name' {
            $profile = New-EntraRiskProfile -UserPrincipalName 'user@contoso.com'
            $profile.PSObject.TypeNames[0] | Should -Be 'PSGuerrilla.EntraRiskProfile'
        }

        It 'handles empty events' {
            $profile = New-EntraRiskProfile -UserPrincipalName 'user@contoso.com' `
                -SignInEvents @() -RiskDetections @() -AuditEvents @()
            $profile.UserPrincipalName | Should -Be 'user@contoso.com'
            $profile.ThreatLevel | Should -Be 'Clean'
            $profile.ThreatScore | Should -Be 0
            $profile.RiskySignIns.Count | Should -Be 0
            $profile.ImpossibleTravelDetections.Count | Should -Be 0
            $profile.PrivilegedRoleChanges.Count | Should -Be 0
            $profile.TotalSignInEvents | Should -Be 0
            $profile.TotalRiskDetections | Should -Be 0
            $profile.TotalAuditEvents | Should -Be 0
        }

        It 'populates sign-in detections' {
            $signInEvents = @(
                @{
                    Timestamp              = '2026-02-28T10:00:00Z'
                    UserPrincipalName      = 'user@contoso.com'
                    IpAddress              = '203.0.113.10'
                    RiskLevelDuringSignIn  = 'high'
                    RiskState              = 'atRisk'
                    AppDisplayName         = 'Microsoft Teams'
                    ClientAppUsed          = 'Browser'
                    Location               = @{ Country = 'US' }
                    IsInteractive          = $true
                }
                @{
                    Timestamp              = '2026-02-28T10:05:00Z'
                    UserPrincipalName      = 'user@contoso.com'
                    IpAddress              = '198.51.100.5'
                    RiskLevelDuringSignIn  = 'medium'
                    RiskState              = 'atRisk'
                    AppDisplayName         = 'Azure Portal'
                    ClientAppUsed          = 'Browser'
                    Location               = @{ Country = 'US' }
                    IsInteractive          = $true
                }
            )

            $profile = New-EntraRiskProfile -UserPrincipalName 'user@contoso.com' `
                -SignInEvents $signInEvents
            $profile.RiskySignIns.Count | Should -Be 2
            $profile.TotalSignInEvents | Should -Be 2
            $profile.RiskySignIns[0].RiskLevel | Should -Be 'high'
            $profile.RiskySignIns[1].RiskLevel | Should -Be 'medium'
        }
    }
}
