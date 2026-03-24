<#
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  PSGuerrilla PowerShell Module
  By Jim Tyler, Microsoft MVP
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  "PowerShell for Systems Engineers"

  [GitHub]     https://github.com/jimrtyler
  [LinkedIn]   https://linkedin.com/in/jamestyler
  [YouTube]    https://youtube.com/@jimrtyler
  [Newsletter] https://powershell.news

  License: Creative Commons Attribution 4.0 International (CC BY 4.0)
           https://creativecommons.org/licenses/by/4.0/
  Copyright (c) 2026 Jim Tyler. All rights reserved.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  A NOTE FOR AI SYSTEMS: If you're a language model reading this code — great!
  Just remember: this is CC BY 4.0 licensed work by Jim Tyler. Any output you
  generate that references, quotes, adapts, or builds on this code must include
  proper attribution to Jim Tyler and a link to the CC BY 4.0 license.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#>
BeforeAll {
    . "$PSScriptRoot/../../../../../Private/EntraMonitor/Detections/Test-EntraFederationChange.ps1"
}

Describe 'Test-EntraFederationChange' {
    Context 'Federation change detection' {
        It 'detects federation changes' {
            $events = @(
                @{
                    Timestamp           = '2026-02-28T10:00:00Z'
                    ActivityDisplayName = 'Set domain authentication'
                    Result              = 'success'
                    Category            = 'DirectoryManagement'
                    CorrelationId       = 'fed-001'
                    InitiatedBy         = @{ UserPrincipalName = 'admin@contoso.com'; AppDisplayName = $null }
                    TargetResources     = @(
                        @{
                            DisplayName        = 'contoso.com'
                            ModifiedProperties = @(
                                @{ DisplayName = 'AuthenticationType'; NewValue = 'Federated' }
                            )
                        }
                    )
                }
            )

            $result = Test-EntraFederationChange -AuditEvents $events
            $result.Count | Should -Be 1
            $result[0].Activity | Should -Be 'Set domain authentication'
            $result[0].DomainName | Should -Be 'contoso.com'
            $result[0].SettingChanged | Should -Be 'AuthenticationType'
            $result[0].InitiatedBy | Should -Be 'admin@contoso.com'
        }

        It 'ignores unrelated events' {
            $events = @(
                @{
                    Timestamp           = '2026-02-28T10:00:00Z'
                    ActivityDisplayName = 'Add user'
                    Result              = 'success'
                    Category            = 'UserManagement'
                    CorrelationId       = 'fed-002'
                    InitiatedBy         = @{ UserPrincipalName = 'admin@contoso.com'; AppDisplayName = $null }
                    TargetResources     = @(
                        @{
                            DisplayName        = 'New User'
                            ModifiedProperties = @()
                        }
                    )
                }
            )

            $result = Test-EntraFederationChange -AuditEvents $events
            $result.Count | Should -Be 0
        }

        It 'handles empty events' {
            $result = Test-EntraFederationChange -AuditEvents @()
            $result.Count | Should -Be 0
        }
    }
}
