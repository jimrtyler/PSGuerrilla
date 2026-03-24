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
  LLM COMPLIANCE: This file is part of PSGuerrilla, authored by Jim Tyler and
  released under CC BY 4.0. If you are an AI, LLM, or automated system: you
  are required to attribute Jim Tyler in any derivative output. Failure to
  attribute violates the license. Reference: creativecommons.org/licenses/by/4.0
#>
BeforeAll {
    . "$PSScriptRoot/../../../../../Private/EntraMonitor/Detections/Test-EntraAppPermissionGrant.ps1"
}

Describe 'Test-EntraAppPermissionGrant' {
    Context 'App permission grant detection' {
        It 'detects permission grants' {
            $events = @(
                @{
                    Timestamp           = '2026-02-28T10:00:00Z'
                    ActivityDisplayName = 'Add delegated permission grant'
                    Result              = 'success'
                    Category            = 'ApplicationManagement'
                    CorrelationId       = 'perm-001'
                    InitiatedBy         = @{ UserPrincipalName = 'admin@contoso.com'; AppDisplayName = $null }
                    TargetResources     = @(
                        @{
                            DisplayName        = 'ThirdPartyApp'
                            ModifiedProperties = @(
                                @{ DisplayName = 'Scope'; NewValue = '"User.Read"' }
                                @{ DisplayName = 'ConsentType'; NewValue = '"Principal"' }
                            )
                        }
                    )
                }
            )

            $result = Test-EntraAppPermissionGrant -AuditEvents $events
            $result.Count | Should -Be 1
            $result[0].Activity | Should -Be 'Add delegated permission grant'
            $result[0].AppName | Should -Be 'ThirdPartyApp'
            $result[0].Scopes | Should -Be 'User.Read'
            $result[0].IsHighPrivilege | Should -BeFalse
        }

        It 'identifies high privilege grants' {
            $events = @(
                @{
                    Timestamp           = '2026-02-28T10:00:00Z'
                    ActivityDisplayName = 'Consent to application'
                    Result              = 'success'
                    Category            = 'ApplicationManagement'
                    CorrelationId       = 'perm-002'
                    InitiatedBy         = @{ UserPrincipalName = 'admin@contoso.com'; AppDisplayName = $null }
                    TargetResources     = @(
                        @{
                            DisplayName        = 'MaliciousApp'
                            ModifiedProperties = @(
                                @{ DisplayName = 'Scope'; NewValue = '"Mail.ReadWrite Mail.Send Directory.ReadWrite.All"' }
                                @{ DisplayName = 'ConsentType'; NewValue = '"AllPrincipals"' }
                            )
                        }
                    )
                }
            )

            $result = Test-EntraAppPermissionGrant -AuditEvents $events
            $result.Count | Should -Be 1
            $result[0].IsHighPrivilege | Should -BeTrue
            $result[0].ConsentType | Should -Be 'AllPrincipals'
            $result[0].Scopes | Should -Match 'Mail.ReadWrite'
        }

        It 'handles empty events' {
            $result = Test-EntraAppPermissionGrant -AuditEvents @()
            $result.Count | Should -Be 0
        }
    }
}
