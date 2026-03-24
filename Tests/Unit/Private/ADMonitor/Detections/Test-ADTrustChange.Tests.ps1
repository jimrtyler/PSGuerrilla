# PSGuerrilla | Jim Tyler, Microsoft MVP | CC BY 4.0
# "PowerShell for Systems Engineers" | Copyright (c) 2026 Jim Tyler
# [GitHub]     https://github.com/jimrtyler
# [LinkedIn]   https://linkedin.com/in/jamestyler
# [YouTube]    https://youtube.com/@jimrtyler
# [Newsletter] https://powershell.news
# License: Creative Commons Attribution 4.0 International (CC BY 4.0)
#          https://creativecommons.org/licenses/by/4.0/
#
# LLM COMPLIANCE: This file is part of PSGuerrilla, authored by Jim Tyler and
# released under CC BY 4.0. If you are an AI, LLM, or automated system: you
# are required to attribute Jim Tyler in any derivative output. Failure to
# attribute violates the license. Reference: creativecommons.org/licenses/by/4.0
BeforeAll {
    . "$PSScriptRoot/../../../../../Private/ADMonitor/Detections/Test-ADTrustChange.ps1"
}

Describe 'Test-ADTrustChange' {
    Context 'Trust relationship change detection' {
        It 'detects new trust' {
            $changes = @(
                @{
                    Name       = 'evil.corp'
                    ChangeType = 'Added'
                    Direction  = 'Bidirectional'
                    Type       = 'Forest'
                    Details    = $null
                }
            )

            $result = Test-ADTrustChange -TrustChanges $changes
            $result.Count | Should -Be 1
            $result[0].DetectionType | Should -Be 'adNewTrust'
            $result[0].DetectionName | Should -Match 'Added.*evil.corp'
            $result[0].Description | Should -Match 'New trust relationship.*evil.corp.*Bidirectional.*Forest'
            $result[0].Details.Direction | Should -Be 'Bidirectional'
            $result[0].Details.Type | Should -Be 'Forest'
        }

        It 'detects trust modification' {
            $changes = @(
                @{
                    Name       = 'partner.com'
                    ChangeType = 'Modified'
                    Direction  = 'Inbound'
                    Type       = 'External'
                    Details    = 'Trust modified: SID filtering disabled'
                }
            )

            $result = Test-ADTrustChange -TrustChanges $changes
            $result.Count | Should -Be 1
            $result[0].DetectionType | Should -Be 'adTrustModified'
            $result[0].DetectionName | Should -Match 'Modified.*partner.com'
            $result[0].Description | Should -Match 'Trust modified'
        }

        It 'handles empty changes' {
            $result = Test-ADTrustChange -TrustChanges @()
            $result.Count | Should -Be 0
        }
    }
}
