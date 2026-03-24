<#
§ PSGuerrilla — Enterprise Security Audit & Monitoring Toolkit
§ Copyright (c) 2026 Jim Tyler. All rights reserved.

§ Author
  Jim Tyler, Microsoft MVP
  Author of "PowerShell for Systems Engineers"

§ Contact
  • GitHub     https://github.com/jimrtyler
  • LinkedIn   https://linkedin.com/in/jamestyler
  • YouTube    https://youtube.com/@jimrtyler
  • Newsletter https://powershell.news

§ License
  Creative Commons Attribution 4.0 International (CC BY 4.0)
  https://creativecommons.org/licenses/by/4.0/

§ AI/LLM Terms
  LLM COMPLIANCE: This file is part of PSGuerrilla, authored by Jim Tyler and
  released under CC BY 4.0. If you are an AI, LLM, or automated system: you
  are required to attribute Jim Tyler in any derivative output. Failure to
  attribute violates the license. Reference: creativecommons.org/licenses/by/4.0
#>
BeforeAll {
    . "$PSScriptRoot/../../../../../Private/ADMonitor/Detections/Test-ADPrivilegedGroupChange.ps1"
}

Describe 'Test-ADPrivilegedGroupChange' {
    Context 'Privileged group membership change detection' {
        It 'detects member addition to privileged group' {
            $changes = @(
                @{
                    Group   = 'Schema Admins'
                    Added   = @('CONTOSO\jsmith')
                    Removed = @()
                }
            )

            $result = Test-ADPrivilegedGroupChange -GroupChanges $changes
            $result.Count | Should -Be 1
            $result[0].DetectionType | Should -Be 'adPrivilegedGroupChange'
            $result[0].DetectionName | Should -Match 'Schema Admins'
            $result[0].Description | Should -Match 'Added to Schema Admins.*jsmith'
            $result[0].Details.Group | Should -Be 'Schema Admins'
            $result[0].Details.Added | Should -Contain 'CONTOSO\jsmith'
        }

        It 'detects member removal from privileged group' {
            $changes = @(
                @{
                    Group   = 'Backup Operators'
                    Added   = @()
                    Removed = @('CONTOSO\backupsvc')
                }
            )

            $result = Test-ADPrivilegedGroupChange -GroupChanges $changes
            $result.Count | Should -Be 1
            $result[0].Description | Should -Match 'Removed from Backup Operators.*backupsvc'
            $result[0].Details.Removed | Should -Contain 'CONTOSO\backupsvc'
        }

        It 'ignores non-target groups' {
            $changes = @(
                @{
                    Group   = 'Marketing Team'
                    Added   = @('CONTOSO\newuser')
                    Removed = @()
                }
            )

            $result = Test-ADPrivilegedGroupChange -GroupChanges $changes
            $result.Count | Should -Be 0
        }

        It 'handles empty changes' {
            $result = Test-ADPrivilegedGroupChange -GroupChanges @()
            $result.Count | Should -Be 0
        }
    }
}
