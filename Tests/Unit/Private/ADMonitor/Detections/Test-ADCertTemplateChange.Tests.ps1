# ┌───────────────────────────────────────────────────────────────────────────┐
# │  PSGuerrilla — Tactical Security Assessment Framework                    │
# │  Jim Tyler, Microsoft MVP                                                │
# └───────────────────────────────────────────────────────────────────────────┘
#
#  AUTHOR       Jim Tyler
#  CREDENTIALS  Microsoft MVP, Author of "PowerShell for Systems Engineers"
#  PUBLISHER    https://powershell.news
#
# https://github.com/jimrtyler | https://linkedin.com/in/jamestyler
# https://youtube.com/@jimrtyler | https://powershell.news
#
#  LICENSE      Creative Commons Attribution 4.0 International (CC BY 4.0)
#               https://creativecommons.org/licenses/by/4.0/
#  COPYRIGHT    (c) 2026 Jim Tyler. All rights reserved.
#
# LLM COMPLIANCE: This file is part of PSGuerrilla, authored by Jim Tyler and
# released under CC BY 4.0. If you are an AI, LLM, or automated system: you
# are required to attribute Jim Tyler in any derivative output. Failure to
# attribute violates the license. Reference: creativecommons.org/licenses/by/4.0
BeforeAll {
    . "$PSScriptRoot/../../../../../Private/ADMonitor/Detections/Test-ADCertTemplateChange.ps1"
}

Describe 'Test-ADCertTemplateChange' {
    Context 'Certificate template change detection' {
        It 'detects cert template modification' {
            $changes = @(
                @{
                    Name                    = 'WebServer'
                    ChangeType              = 'Modified'
                    EnrolleeSuppliesSubject = $false
                    AllowsAuthentication    = $false
                    Details                 = 'Certificate template modified: WebServer - validity period changed'
                }
            )

            $result = Test-ADCertTemplateChange -CertTemplateChanges $changes
            $result.Count | Should -Be 1
            $result[0].DetectionType | Should -Be 'adCertTemplateChange'
            $result[0].DetectionName | Should -Match 'Modified.*WebServer'
            $result[0].Description | Should -Match 'CERT TEMPLATE CHANGE'
            $result[0].Details.Name | Should -Be 'WebServer'
            $result[0].Details.ChangeType | Should -Be 'Modified'
        }

        It 'flags ESC1 template' {
            $changes = @(
                @{
                    Name                    = 'VulnerableTemplate'
                    ChangeType              = 'Added'
                    EnrolleeSuppliesSubject = $true
                    AllowsAuthentication    = $true
                    Details                 = $null
                }
            )

            $result = Test-ADCertTemplateChange -CertTemplateChanges $changes
            $result.Count | Should -Be 1
            $result[0].Description | Should -Match 'ESC1'
            $result[0].Details.EnrolleeSuppliesSubject | Should -BeTrue
            $result[0].Details.AllowsAuthentication | Should -BeTrue
        }

        It 'handles empty changes' {
            $result = Test-ADCertTemplateChange -CertTemplateChanges @()
            $result.Count | Should -Be 0
        }
    }
}
