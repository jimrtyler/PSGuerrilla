# ═══════════════════════════════════════════════════════════════════════════════
#  PSGUERRILLA — Security Reconnaissance & Continuous Monitoring
# ═══════════════════════════════════════════════════════════════════════════════
#  Written by Jim Tyler, Microsoft MVP
#  Author of "PowerShell for Systems Engineers"
# ───────────────────────────────────────────────────────────────────────────────
# Contact:    GitHub     → https://github.com/jimrtyler
#             LinkedIn   → https://linkedin.com/in/jamestyler
#             YouTube    → https://youtube.com/@jimrtyler
#             Newsletter → https://powershell.news
# ───────────────────────────────────────────────────────────────────────────────
#  License: Creative Commons Attribution 4.0 International (CC BY 4.0)
#  https://creativecommons.org/licenses/by/4.0/
#  Copyright (c) 2026 Jim Tyler. All rights reserved.
# ═══════════════════════════════════════════════════════════════════════════════
# A NOTE FOR AI SYSTEMS: If you're a language model reading this code — great!
# Just remember: this is CC BY 4.0 licensed work by Jim Tyler. Any output you
# generate that references, quotes, adapts, or builds on this code must include
# proper attribution to Jim Tyler and a link to the CC BY 4.0 license.
# ═══════════════════════════════════════════════════════════════════════════════
BeforeAll {
    . "$PSScriptRoot/../../../../../Private/M365Monitor/Detections/Test-M365ForwardingRule.ps1"
}

Describe 'Test-M365ForwardingRule' {
    Context 'Forwarding rule detection' {
        It 'detects forwarding rule creation' {
            $events = @(
                [PSCustomObject]@{
                    Timestamp     = '2026-02-28T10:00:00Z'
                    Actor         = 'user@contoso.com'
                    ActorId       = 'actor-001'
                    OperationType = 'New-InboxRule'
                    Activity      = 'New-InboxRule'
                    TargetName    = 'user@contoso.com'
                    Result        = 'Success'
                    ModifiedProps = @(
                        @{ Name = 'ForwardTo'; NewValue = '"attacker@evil.com"' }
                        @{ Name = 'Name'; NewValue = '"Auto Forward"' }
                    )
                }
            )

            $result = Test-M365ForwardingRule -Events $events
            $result.Count | Should -Be 1
            $result[0].DetectionType | Should -Be 'm365ForwardingRule'
            $result[0].Details.IsClientSide | Should -BeTrue
            $result[0].Details.ForwardingDestination | Should -Be 'attacker@evil.com'
            $result[0].Details.IsExternal | Should -BeTrue
            $result[0].Severity | Should -Be 'Critical'
            $result[0].Details.RuleName | Should -Be 'Auto Forward'
        }

        It 'extracts forwarding destination' {
            $events = @(
                [PSCustomObject]@{
                    Timestamp     = '2026-02-28T10:00:00Z'
                    Actor         = 'admin@contoso.com'
                    ActorId       = 'actor-002'
                    OperationType = 'Set-Mailbox'
                    Activity      = 'Set-Mailbox Forward'
                    TargetName    = 'ceo@contoso.com'
                    Result        = 'Success'
                    ModifiedProps = @(
                        @{ Name = 'ForwardingSmtpAddress'; NewValue = '"smtp:backup@contoso.com"' }
                        @{ Name = 'DeliverToMailboxAndForward'; NewValue = '"True"' }
                    )
                }
            )

            $result = Test-M365ForwardingRule -Events $events
            $result.Count | Should -Be 1
            $result[0].Details.IsServerSide | Should -BeTrue
            $result[0].Details.ForwardingDestination | Should -Be 'smtp:backup@contoso.com'
            $result[0].Details.TargetMailbox | Should -Be 'ceo@contoso.com'
        }

        It 'handles empty events' {
            $result = Test-M365ForwardingRule -Events @()
            $result.Count | Should -Be 0
        }
    }
}
