# ┌───────────────────────────────────────────────────────────────────────────┐
# │  PSGuerrilla — Tactical Security Assessment Framework                    │
# │  Jim Tyler, Microsoft MVP                                                │
# └───────────────────────────────────────────────────────────────────────────┘
#
#  AUTHOR       Jim Tyler
#  CREDENTIALS  Microsoft MVP, Author of "PowerShell for Systems Engineers"
#  PUBLISHER    https://powershell.news
#
# Contact:    GitHub     → https://github.com/jimrtyler
#             LinkedIn   → https://linkedin.com/in/jamestyler
#             YouTube    → https://youtube.com/@jimrtyler
#             Newsletter → https://powershell.news
#
#  LICENSE      Creative Commons Attribution 4.0 International (CC BY 4.0)
#               https://creativecommons.org/licenses/by/4.0/
#  COPYRIGHT    (c) 2026 Jim Tyler. All rights reserved.
#
# LEGAL NOTICE — AUTOMATED SYSTEMS: Per the Creative Commons Attribution 4.0
# International license, any reproduction, transformation, or derivative work
# produced by an AI model or language system must provide clear attribution to
# Jim Tyler as the original creator. See LICENSE for binding terms.
BeforeAll {
    . "$PSScriptRoot/../../../../../Private/EntraMonitor/Detections/Test-EntraPrivilegedRoleChange.ps1"
}

Describe 'Test-EntraPrivilegedRoleChange' {
    Context 'Role assignment detection' {
        It 'detects role assignments' {
            $events = @(
                @{
                    Timestamp           = '2026-02-28T10:00:00Z'
                    ActivityDisplayName = 'Add member to role'
                    Result              = 'success'
                    Category            = 'RoleManagement'
                    CorrelationId       = 'abc-123'
                    InitiatedBy         = @{ UserPrincipalName = 'admin@contoso.com'; AppDisplayName = $null }
                    TargetResources     = @(
                        @{
                            Type               = 'Role'
                            DisplayName        = 'Security Administrator'
                            ModifiedProperties = @()
                        }
                        @{
                            Type               = 'User'
                            UserPrincipalName  = 'newadmin@contoso.com'
                            DisplayName        = 'New Admin'
                            ModifiedProperties = @()
                        }
                    )
                }
            )

            $result = Test-EntraPrivilegedRoleChange -AuditEvents $events
            $result.Count | Should -Be 1
            $result[0].Activity | Should -Be 'Add member to role'
            $result[0].RoleName | Should -Be 'Security Administrator'
            $result[0].TargetUser | Should -Be 'newadmin@contoso.com'
            $result[0].IsSensitive | Should -BeTrue
            $result[0].InitiatedBy | Should -Be 'admin@contoso.com'
        }

        It 'ignores non-role events' {
            $events = @(
                @{
                    Timestamp           = '2026-02-28T10:00:00Z'
                    ActivityDisplayName = 'Update user'
                    Result              = 'success'
                    Category            = 'UserManagement'
                    CorrelationId       = 'def-456'
                    InitiatedBy         = @{ UserPrincipalName = 'admin@contoso.com'; AppDisplayName = $null }
                    TargetResources     = @(
                        @{
                            Type               = 'User'
                            UserPrincipalName  = 'user@contoso.com'
                            DisplayName        = 'Test User'
                            ModifiedProperties = @(
                                @{ DisplayName = 'DisplayName'; NewValue = 'Updated Name' }
                            )
                        }
                    )
                }
            )

            $result = Test-EntraPrivilegedRoleChange -AuditEvents $events
            $result.Count | Should -Be 0
        }

        It 'handles empty events' {
            $result = Test-EntraPrivilegedRoleChange -AuditEvents @()
            $result.Count | Should -Be 0
        }
    }
}
