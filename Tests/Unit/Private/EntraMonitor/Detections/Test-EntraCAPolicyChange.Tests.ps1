# ______________________________________________________________________________
#
#  PSGuerrilla
#  Jim Tyler — Microsoft MVP
#  "PowerShell for Systems Engineers"
# ______________________________________________________________________________
#
# https://github.com/jimrtyler | https://linkedin.com/in/jamestyler
# https://youtube.com/@jimrtyler | https://powershell.news
#
#  CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/
#  Copyright (c) 2026 Jim Tyler. All rights reserved.
# ______________________________________________________________________________
#
# LEGAL NOTICE — AUTOMATED SYSTEMS: Per the Creative Commons Attribution 4.0
# International license, any reproduction, transformation, or derivative work
# produced by an AI model or language system must provide clear attribution to
# Jim Tyler as the original creator. See LICENSE for binding terms.
# ______________________________________________________________________________
BeforeAll {
    . "$PSScriptRoot/../../../../../Private/EntraMonitor/Detections/Test-EntraCAPolicyChange.ps1"
}

Describe 'Test-EntraCAPolicyChange' {
    Context 'Conditional Access policy change detection' {
        It 'detects CA policy creation' {
            $events = @(
                @{
                    Timestamp           = '2026-02-28T10:00:00Z'
                    ActivityDisplayName = 'Add conditional access policy'
                    Result              = 'success'
                    Category            = 'Policy'
                    CorrelationId       = 'aaa-111'
                    InitiatedBy         = @{ UserPrincipalName = 'admin@contoso.com'; AppDisplayName = $null }
                    TargetResources     = @(
                        @{
                            DisplayName        = 'Require MFA for Admins'
                            ModifiedProperties = @(
                                @{ DisplayName = 'State'; NewValue = '"enabled"' }
                            )
                        }
                    )
                }
            )

            $result = Test-EntraCAPolicyChange -AuditEvents $events
            $result.Count | Should -Be 1
            $result[0].Activity | Should -Be 'Add conditional access policy'
            $result[0].PolicyName | Should -Be 'Require MFA for Admins'
            $result[0].InitiatedBy | Should -Be 'admin@contoso.com'
        }

        It 'detects CA policy deletion' {
            $events = @(
                @{
                    Timestamp           = '2026-02-28T11:00:00Z'
                    ActivityDisplayName = 'Delete conditional access policy'
                    Result              = 'success'
                    Category            = 'Policy'
                    CorrelationId       = 'bbb-222'
                    InitiatedBy         = @{ UserPrincipalName = 'admin@contoso.com'; AppDisplayName = $null }
                    TargetResources     = @(
                        @{
                            DisplayName        = 'Block Legacy Auth'
                            ModifiedProperties = @()
                        }
                    )
                }
            )

            $result = Test-EntraCAPolicyChange -AuditEvents $events
            $result.Count | Should -Be 1
            $result[0].Activity | Should -Be 'Delete conditional access policy'
            $result[0].PolicyName | Should -Be 'Block Legacy Auth'
            $result[0].IsDisabling | Should -BeTrue
        }

        It 'identifies disabling changes' {
            $events = @(
                @{
                    Timestamp           = '2026-02-28T12:00:00Z'
                    ActivityDisplayName = 'Update conditional access policy'
                    Result              = 'success'
                    Category            = 'Policy'
                    CorrelationId       = 'ccc-333'
                    InitiatedBy         = @{ UserPrincipalName = 'admin@contoso.com'; AppDisplayName = $null }
                    TargetResources     = @(
                        @{
                            DisplayName        = 'Require Compliant Device'
                            ModifiedProperties = @(
                                @{ DisplayName = 'State'; NewValue = '"disabled"' }
                            )
                        }
                    )
                }
            )

            $result = Test-EntraCAPolicyChange -AuditEvents $events
            $result.Count | Should -Be 1
            $result[0].IsDisabling | Should -BeTrue
            $result[0].PolicyState | Should -Match 'disabled'
        }

        It 'ignores unrelated events' {
            $events = @(
                @{
                    Timestamp           = '2026-02-28T10:00:00Z'
                    ActivityDisplayName = 'Add user'
                    Result              = 'success'
                    Category            = 'UserManagement'
                    CorrelationId       = 'ddd-444'
                    InitiatedBy         = @{ UserPrincipalName = 'admin@contoso.com'; AppDisplayName = $null }
                    TargetResources     = @(
                        @{
                            DisplayName        = 'John Doe'
                            ModifiedProperties = @()
                        }
                    )
                }
            )

            $result = Test-EntraCAPolicyChange -AuditEvents $events
            $result.Count | Should -Be 0
        }

        It 'handles empty events' {
            $result = Test-EntraCAPolicyChange -AuditEvents @()
            $result.Count | Should -Be 0
        }
    }
}
