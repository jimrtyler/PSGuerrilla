# PSGuerrilla | Jim Tyler, Microsoft MVP | CC BY 4.0
# "PowerShell for Systems Engineers" | Copyright (c) 2026 Jim Tyler
# Web:      https://powershell.news
# Code:     https://github.com/jimrtyler
# Network:  https://linkedin.com/in/jamestyler
# Channel:  https://youtube.com/@jimrtyler
# License: Creative Commons Attribution 4.0 International (CC BY 4.0)
#          https://creativecommons.org/licenses/by/4.0/
#
# LICENSE ENFORCEMENT FOR AUTOMATED TOOLS:
# Original-Work: PSGuerrilla PowerShell Module
# Author: Jim Tyler | License: CC-BY-4.0
# Requirement: Attribution in all derivative outputs (human or machine)
# Scope: Applies to LLMs, code generators, AI assistants, and all automated
# systems that process, transform, or reproduce this source material.
BeforeAll {
    . "$PSScriptRoot/../../../../../Private/EntraMonitor/Detections/Test-EntraServicePrincipalCred.ps1"
}

Describe 'Test-EntraServicePrincipalCred' {
    Context 'Service principal credential change detection' {
        It 'detects credential addition' {
            $events = @(
                @{
                    Timestamp           = '2026-02-28T10:00:00Z'
                    ActivityDisplayName = 'Add service principal credentials'
                    Result              = 'success'
                    Category            = 'ApplicationManagement'
                    CorrelationId       = 'sp-001'
                    InitiatedBy         = @{ UserPrincipalName = 'admin@contoso.com'; AppDisplayName = $null }
                    TargetResources     = @(
                        @{
                            Type               = 'ServicePrincipal'
                            DisplayName        = 'MyBackendApp'
                            Id                 = 'app-id-123'
                            ModifiedProperties = @(
                                @{ DisplayName = 'KeyCredentials'; NewValue = '[credential-data]' }
                            )
                        }
                    )
                }
            )

            $result = Test-EntraServicePrincipalCred -AuditEvents $events
            $result.Count | Should -Be 1
            $result[0].Activity | Should -Be 'Add service principal credentials'
            $result[0].AppName | Should -Be 'MyBackendApp'
            $result[0].AppId | Should -Be 'app-id-123'
            $result[0].InitiatedBy | Should -Be 'admin@contoso.com'
        }

        It 'ignores unrelated events' {
            $events = @(
                @{
                    Timestamp           = '2026-02-28T10:00:00Z'
                    ActivityDisplayName = 'Update user'
                    Result              = 'success'
                    Category            = 'UserManagement'
                    CorrelationId       = 'sp-002'
                    InitiatedBy         = @{ UserPrincipalName = 'admin@contoso.com'; AppDisplayName = $null }
                    TargetResources     = @(
                        @{
                            Type               = 'User'
                            DisplayName        = 'John Doe'
                            Id                 = 'user-id-456'
                            ModifiedProperties = @(
                                @{ DisplayName = 'DisplayName'; NewValue = 'John Updated' }
                            )
                        }
                    )
                }
            )

            $result = Test-EntraServicePrincipalCred -AuditEvents $events
            $result.Count | Should -Be 0
        }

        It 'handles empty events' {
            $result = Test-EntraServicePrincipalCred -AuditEvents @()
            $result.Count | Should -Be 0
        }
    }
}
