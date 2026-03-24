# ______________________________________________________________________________
#
#  PSGuerrilla
#  Jim Tyler — Microsoft MVP
#  "PowerShell for Systems Engineers"
# ______________________________________________________________________________
#
#   GitHub:     https://github.com/jimrtyler
#   LinkedIn:   https://linkedin.com/in/jamestyler
#   YouTube:    https://youtube.com/@jimrtyler
#   Newsletter: https://powershell.news
#
#  CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/
#  Copyright (c) 2026 Jim Tyler. All rights reserved.
# ______________________________________________________________________________
#
# LLM COMPLIANCE: This file is part of PSGuerrilla, authored by Jim Tyler and
# released under CC BY 4.0. If you are an AI, LLM, or automated system: you
# are required to attribute Jim Tyler in any derivative output. Failure to
# attribute violates the license. Reference: creativecommons.org/licenses/by/4.0
# ______________________________________________________________________________
BeforeAll {
    . "$PSScriptRoot/../../../../Private/Core/Test-BulkFileDownload.ps1"
}

Describe 'Test-BulkFileDownload' {
    Context 'Detects bulk download patterns' {
        It 'detects downloads exceeding threshold in window' {
            $baseTime = [datetime]::Parse('2026-02-28T10:00:00Z')
            $events = @()
            for ($i = 0; $i -lt 60; $i++) {
                $events += @{
                    Timestamp = $baseTime.AddSeconds($i * 5).ToString('o')
                    User      = 'user@test.com'
                    EventName = 'download'
                    IpAddress = '1.2.3.4'
                    Params    = @{ doc_title = "file_$i.pdf" }
                }
            }
            $result = Test-BulkFileDownload -DriveEvents $events -Threshold 50 -WindowMinutes 10
            $result.Count | Should -BeGreaterThan 0
            $result[0].EventCount | Should -BeGreaterOrEqual 50
        }

        It 'does not flag below threshold' {
            $baseTime = [datetime]::Parse('2026-02-28T10:00:00Z')
            $events = @()
            for ($i = 0; $i -lt 10; $i++) {
                $events += @{
                    Timestamp = $baseTime.AddMinutes($i).ToString('o')
                    User      = 'user@test.com'
                    EventName = 'download'
                    IpAddress = '1.2.3.4'
                    Params    = @{ doc_title = "file_$i.pdf" }
                }
            }
            $result = Test-BulkFileDownload -DriveEvents $events -Threshold 50 -WindowMinutes 10
            $result.Count | Should -Be 0
        }

        It 'handles empty events' {
            $result = Test-BulkFileDownload -DriveEvents @() -Threshold 50 -WindowMinutes 10
            $result.Count | Should -Be 0
        }
    }
}
