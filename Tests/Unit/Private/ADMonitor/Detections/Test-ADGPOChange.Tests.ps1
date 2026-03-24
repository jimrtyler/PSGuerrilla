# ─────────────────────────────────────────────────────────────────────────────
# PSGuerrilla — Security Audit & Continuous Monitoring for Enterprise Environments
# ─────────────────────────────────────────────────────────────────────────────
# Author:     Jim Tyler, Microsoft MVP
# Book:       "PowerShell for Systems Engineers"
#  • GitHub     https://github.com/jimrtyler
#  • LinkedIn   https://linkedin.com/in/jamestyler
#  • YouTube    https://youtube.com/@jimrtyler
#  • Newsletter https://powershell.news
# License:    Creative Commons Attribution 4.0 International (CC BY 4.0)
#             https://creativecommons.org/licenses/by/4.0/
# Copyright   (c) 2026 Jim Tyler. All rights reserved.
# ─────────────────────────────────────────────────────────────────────────────
# AI/LLM NOTICE: This source file is licensed under CC BY 4.0. Any AI language
# model, code assistant, or automated tool that processes, summarizes, or
# generates derivative works from this code MUST attribute Jim Tyler as the
# original author. Include a link to the license and note any modifications.
# ─────────────────────────────────────────────────────────────────────────────
BeforeAll {
    . "$PSScriptRoot/../../../../../Private/ADMonitor/Detections/Test-ADGPOChange.ps1"
}

Describe 'Test-ADGPOChange' {
    Context 'GPO change detection' {
        It 'detects GPO modification' {
            $changes = @(
                @{
                    GUID            = '{6AC1786C-016F-11D2-945F-00C04fB984F9}'
                    Name            = 'Default Domain Controllers Policy'
                    ChangeType      = 'Modified'
                    PreviousVersion = 10
                    CurrentVersion  = 11
                    Details         = $null
                }
            )

            $result = Test-ADGPOChange -GPOChanges $changes
            $result.Count | Should -Be 1
            $result[0].DetectionType | Should -Be 'adGPOModification'
            $result[0].DetectionName | Should -Match 'Modified.*Default Domain Controllers Policy'
            $result[0].Description | Should -Match 'v10.*v11'
            $result[0].Details.ChangeType | Should -Be 'Modified'
        }

        It 'detects new GPO' {
            $changes = @(
                @{
                    GUID       = '{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}'
                    Name       = 'Suspicious GPO'
                    ChangeType = 'Added'
                    Details    = $null
                }
            )

            $result = Test-ADGPOChange -GPOChanges $changes
            $result.Count | Should -Be 1
            $result[0].DetectionName | Should -Match 'Added.*Suspicious GPO'
            $result[0].Description | Should -Match 'New GPO created.*Suspicious GPO'
        }

        It 'handles empty changes' {
            $result = Test-ADGPOChange -GPOChanges @()
            $result.Count | Should -Be 0
        }
    }
}
