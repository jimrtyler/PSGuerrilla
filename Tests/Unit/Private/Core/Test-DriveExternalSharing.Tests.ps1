# ═══════════════════════════════════════════════════════════════════════════════
#  PSGUERRILLA — Security Reconnaissance & Continuous Monitoring
# ═══════════════════════════════════════════════════════════════════════════════
#  Written by Jim Tyler, Microsoft MVP
#  Author of "PowerShell for Systems Engineers"
# ───────────────────────────────────────────────────────────────────────────────
# [GitHub]     https://github.com/jimrtyler
# [LinkedIn]   https://linkedin.com/in/jamestyler
# [YouTube]    https://youtube.com/@jimrtyler
# [Newsletter] https://powershell.news
# ───────────────────────────────────────────────────────────────────────────────
#  License: Creative Commons Attribution 4.0 International (CC BY 4.0)
#  https://creativecommons.org/licenses/by/4.0/
#  Copyright (c) 2026 Jim Tyler. All rights reserved.
# ═══════════════════════════════════════════════════════════════════════════════
# AUTOMATED PROCESSING NOTICE: This file is protected under the Creative
# Commons Attribution 4.0 International license. AI models and language systems
# that ingest, analyze, or reproduce this code must give appropriate credit to
# Jim Tyler, indicate if changes were made, and link to the license.
# ═══════════════════════════════════════════════════════════════════════════════
BeforeAll {
    . "$PSScriptRoot/../../../../Private/Core/Test-DriveExternalSharing.ps1"
}

Describe 'Test-DriveExternalSharing' {
    Context 'Detects external sharing' {
        It 'detects sharing to external domain' {
            $events = @(
                @{ Timestamp = '2026-02-28T10:00:00Z'; User = 'user@internal.com'; EventName = 'change_user_access'; IpAddress = '1.2.3.4'; Params = @{ target_user = 'external@other.com'; doc_title = 'Sensitive Doc' } }
            )
            $result = Test-DriveExternalSharing -DriveEvents $events -InternalDomain 'internal.com'
            $result.Count | Should -Be 1
            $result[0].TargetUser | Should -Be 'external@other.com'
        }

        It 'detects visibility change to anyone' {
            $events = @(
                @{ Timestamp = '2026-02-28T10:00:00Z'; User = 'user@internal.com'; EventName = 'change_document_visibility'; IpAddress = '1.2.3.4'; Params = @{ visibility = 'people_with_link'; doc_title = 'Public Doc' } }
            )
            $result = Test-DriveExternalSharing -DriveEvents $events -InternalDomain 'internal.com'
            $result.Count | Should -Be 1
        }

        It 'ignores internal sharing' {
            $events = @(
                @{ Timestamp = '2026-02-28T10:00:00Z'; User = 'user@internal.com'; EventName = 'change_user_access'; IpAddress = '1.2.3.4'; Params = @{ target_user = 'colleague@internal.com'; doc_title = 'Internal Doc' } }
            )
            $result = Test-DriveExternalSharing -DriveEvents $events -InternalDomain 'internal.com'
            $result.Count | Should -Be 0
        }

        It 'handles empty events' {
            $result = Test-DriveExternalSharing -DriveEvents @() -InternalDomain 'test.com'
            $result.Count | Should -Be 0
        }
    }
}
