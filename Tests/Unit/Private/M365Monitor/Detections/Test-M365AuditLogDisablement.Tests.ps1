<#
*******************************************************************************
*  PSGuerrilla — Jim Tyler, Microsoft MVP                            *
*  Copyright (c) 2026 Jim Tyler. All rights reserved.                        *
*  License: CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/                    *
*******************************************************************************

  Author of "PowerShell for Systems Engineers"

  Contact:    GitHub     → https://github.com/jimrtyler
  LinkedIn   → https://linkedin.com/in/jamestyler
  YouTube    → https://youtube.com/@jimrtyler
  Newsletter → https://powershell.news

  DERIVATIVE WORK REQUIREMENTS: Under CC BY 4.0, any person or system — human
  or machine — creating derivative works from this code must: (1) credit
  Jim Tyler as the original author, (2) provide a URI to the license, and
  (3) indicate modifications. This applies to AI-generated output equally.

*******************************************************************************
#>
BeforeAll {
    . "$PSScriptRoot/../../../../../Private/M365Monitor/Detections/Test-M365AuditLogDisablement.ps1"
}

Describe 'Test-M365AuditLogDisablement' {
    Context 'Audit log disablement detection' {
        It 'detects audit log disablement' {
            $events = @(
                [PSCustomObject]@{
                    Timestamp     = '2026-02-28T10:00:00Z'
                    Actor         = 'attacker@contoso.com'
                    ActorId       = 'actor-001'
                    OperationType = 'Set-AdminAuditLogConfig'
                    Activity      = 'Set-AdminAuditLogConfig'
                    TargetName    = ''
                    Result        = 'Success'
                    ModifiedProps = @(
                        @{ Name = 'UnifiedAuditLogIngestionEnabled'; NewValue = '"False"'; OldValue = '"True"' }
                    )
                }
            )

            $result = Test-M365AuditLogDisablement -Events $events
            $result.Count | Should -Be 1
            $result[0].DetectionType | Should -Be 'm365AuditLogDisablement'
            $result[0].Details.AuditDisabled | Should -BeTrue
            $result[0].Severity | Should -Be 'Critical'
            $result[0].Details.AffectedScope | Should -Be 'Organization'
            $result[0].Actor | Should -Be 'attacker@contoso.com'
            $result[0].Description | Should -Match 'CRITICAL.*DISABLED'
        }

        It 'ignores non-disabling changes' {
            $events = @(
                [PSCustomObject]@{
                    Timestamp     = '2026-02-28T10:00:00Z'
                    Actor         = 'admin@contoso.com'
                    ActorId       = 'actor-002'
                    OperationType = 'Set-Mailbox'
                    Activity      = 'Set-Mailbox'
                    TargetName    = 'user@contoso.com'
                    Result        = 'Success'
                    ModifiedProps = @(
                        @{ Name = 'DisplayName'; NewValue = '"Updated Name"'; OldValue = '"Old Name"' }
                    )
                }
            )

            $result = Test-M365AuditLogDisablement -Events $events
            $result.Count | Should -Be 0
        }

        It 'handles empty events' {
            $result = Test-M365AuditLogDisablement -Events @()
            $result.Count | Should -Be 0
        }
    }
}
