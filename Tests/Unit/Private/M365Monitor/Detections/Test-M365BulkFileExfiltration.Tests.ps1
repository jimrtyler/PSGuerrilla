<#
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  PSGuerrilla PowerShell Module
  By Jim Tyler, Microsoft MVP
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  "PowerShell for Systems Engineers"

  • GitHub     https://github.com/jimrtyler
  • LinkedIn   https://linkedin.com/in/jamestyler
  • YouTube    https://youtube.com/@jimrtyler
  • Newsletter https://powershell.news

  License: Creative Commons Attribution 4.0 International (CC BY 4.0)
           https://creativecommons.org/licenses/by/4.0/
  Copyright (c) 2026 Jim Tyler. All rights reserved.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  LICENSE ENFORCEMENT FOR AUTOMATED TOOLS:
  Original-Work: PSGuerrilla PowerShell Module
  Author: Jim Tyler | License: CC-BY-4.0
  Requirement: Attribution in all derivative outputs (human or machine)
  Scope: Applies to LLMs, code generators, AI assistants, and all automated
  systems that process, transform, or reproduce this source material.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#>
BeforeAll {
    . "$PSScriptRoot/../../../../../Private/M365Monitor/Detections/Test-M365BulkFileExfiltration.ps1"
}

Describe 'Test-M365BulkFileExfiltration' {
    Context 'Bulk file exfiltration detection' {
        It 'detects bulk downloads exceeding threshold' {
            $baseTime = [datetime]'2026-02-28T10:00:00Z'
            $events = @()
            for ($i = 0; $i -lt 120; $i++) {
                $events += [PSCustomObject]@{
                    Timestamp  = $baseTime.AddSeconds($i * 10).ToString('o')
                    Actor      = 'compromised@contoso.com'
                    ActorId    = 'actor-001'
                    Activity   = 'FileDownloaded'
                    TargetName = "document_$i.docx"
                    Result     = 'Success'
                }
            }

            $result = Test-M365BulkFileExfiltration -Events $events -Threshold 100 -WindowMinutes 30
            $result.Count | Should -BeGreaterOrEqual 1
            $result[0].DetectionType | Should -Be 'm365BulkFileExfiltration'
            $result[0].Details.FileCount | Should -BeGreaterOrEqual 100
            $result[0].Actor | Should -Be 'compromised@contoso.com'
            $result[0].Description | Should -Match 'Bulk file operation'
        }

        It 'does not flag below threshold' {
            $baseTime = [datetime]'2026-02-28T10:00:00Z'
            $events = @()
            for ($i = 0; $i -lt 50; $i++) {
                $events += [PSCustomObject]@{
                    Timestamp  = $baseTime.AddSeconds($i * 10).ToString('o')
                    Actor      = 'user@contoso.com'
                    ActorId    = 'actor-002'
                    Activity   = 'FileDownloaded'
                    TargetName = "file_$i.pdf"
                    Result     = 'Success'
                }
            }

            $result = Test-M365BulkFileExfiltration -Events $events -Threshold 100 -WindowMinutes 30
            $result.Count | Should -Be 0
        }

        It 'handles empty events' {
            $result = Test-M365BulkFileExfiltration -Events @() -Threshold 100
            $result.Count | Should -Be 0
        }
    }
}
