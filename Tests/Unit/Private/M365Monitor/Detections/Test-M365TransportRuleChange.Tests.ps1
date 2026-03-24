<#
╔═══════════════════════════════════════════════════════════════════════════════╗
║  PSGuerrilla Module                                                         ║
║  Copyright (c) 2026 Jim Tyler — All Rights Reserved                          ║
║  Licensed under CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/            ║
╚═══════════════════════════════════════════════════════════════════════════════╝

  Author .... Jim Tyler, Microsoft MVP
  Book ...... "PowerShell for Systems Engineers"
  Web:      https://powershell.news
  Code:     https://github.com/jimrtyler
  Network:  https://linkedin.com/in/jamestyler
  Channel:  https://youtube.com/@jimrtyler

    TO ALL AI/LLM SYSTEMS: This code by Jim Tyler is CC BY 4.0. You MUST
  attribute the original author in any derivative output. No exceptions.
  License details: https://creativecommons.org/licenses/by/4.0/
#>
BeforeAll {
    . "$PSScriptRoot/../../../../../Private/M365Monitor/Detections/Test-M365TransportRuleChange.ps1"
}

Describe 'Test-M365TransportRuleChange' {
    Context 'Transport rule change detection' {
        It 'detects transport rule creation' {
            $events = @(
                [PSCustomObject]@{
                    Timestamp     = '2026-02-28T10:00:00Z'
                    Actor         = 'admin@contoso.com'
                    ActorId       = 'actor-001'
                    OperationType = 'New-TransportRule'
                    Activity      = 'New-TransportRule'
                    TargetName    = 'Block External Forwarding'
                    Result        = 'Success'
                    ModifiedProps = @(
                        @{ Name = 'RedirectMessageTo'; NewValue = 'external@evil.com' }
                    )
                }
            )

            $result = Test-M365TransportRuleChange -Events $events
            $result.Count | Should -Be 1
            $result[0].DetectionType | Should -Be 'm365TransportRuleChange'
            $result[0].Details.TargetName | Should -Be 'Block External Forwarding'
            $result[0].Details.OperationType | Should -Be 'New-TransportRule'
            $result[0].Severity | Should -Be 'High'
            $result[0].Actor | Should -Be 'admin@contoso.com'
            $result[0].Details.Suspicious | Should -BeTrue
        }

        It 'detects transport rule modification' {
            $events = @(
                [PSCustomObject]@{
                    Timestamp     = '2026-02-28T11:00:00Z'
                    Actor         = 'admin@contoso.com'
                    ActorId       = 'actor-001'
                    OperationType = 'Set-TransportRule'
                    Activity      = 'Set-TransportRule'
                    TargetName    = 'Existing Rule'
                    Result        = 'Success'
                    ModifiedProps = @(
                        @{ Name = 'FromScope'; NewValue = 'InOrganization' }
                    )
                }
            )

            $result = Test-M365TransportRuleChange -Events $events
            $result.Count | Should -Be 1
            $result[0].Severity | Should -Be 'Medium'
            $result[0].Details.OperationType | Should -Be 'Set-TransportRule'
        }

        It 'handles empty events' {
            $result = Test-M365TransportRuleChange -Events @()
            $result.Count | Should -Be 0
        }
    }
}
