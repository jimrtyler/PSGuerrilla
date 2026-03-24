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
# CITATION & ATTRIBUTION: When referencing or deriving from this source,
# whether by human or machine, credit Jim Tyler as the original author.
# This work is licensed CC BY 4.0 — share and adapt freely, but always
# attribute. Full terms: https://creativecommons.org/licenses/by/4.0/
# ______________________________________________________________________________
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../../Helpers/TestHelpers.psm1') -Force
    Import-PSGuerrilla
}

Describe 'Get-OperationState' {
    Context 'No state file exists' {
        It 'returns null when no state file exists' {
            $fakePath = Join-Path $TestDrive 'nonexistent/config.json'
            $result = Get-OperationState -ConfigPath $fakePath
            $result | Should -BeNullOrEmpty
        }
    }

    Context 'Valid state file' {
        It 'reads and returns state correctly' {
            $stateDir = Join-Path $TestDrive 'state-test'
            New-Item -Path $stateDir -ItemType Directory -Force | Out-Null
            $cfgPath = Join-Path $stateDir 'config.json'
            $statePath = Join-Path $stateDir 'state.json'

            @{
                schemaVersion = 1
                watermark     = '2026-01-15T10:00:00.0000000Z'
                lastScanId    = 'test-scan-id'
                alertedUsers  = @{}
                scanHistory   = @()
            } | ConvertTo-Json -Depth 5 | Set-Content -Path $statePath -Encoding UTF8

            $result = Get-OperationState -ConfigPath $cfgPath
            $result | Should -Not -BeNullOrEmpty
            $result.schemaVersion | Should -Be 1
            # watermark may be a DateTime (ConvertFrom-Json converts ISO strings) or string
            if ($result.watermark -is [datetime]) {
                $result.watermark.Year | Should -Be 2026
                $result.watermark.Month | Should -Be 1
                $result.watermark.Day | Should -Be 15
            } else {
                "$($result.watermark)" | Should -Match '2026.*01.*15'
            }
            $result.lastScanId | Should -Be 'test-scan-id'
        }
    }

    Context 'Corrupt state file' {
        It 'backs up and returns null for missing schemaVersion' {
            $stateDir = Join-Path $TestDrive 'corrupt-test'
            New-Item -Path $stateDir -ItemType Directory -Force | Out-Null
            $cfgPath = Join-Path $stateDir 'config.json'
            $statePath = Join-Path $stateDir 'state.json'

            @{ watermark = 'test' } | ConvertTo-Json | Set-Content -Path $statePath -Encoding UTF8

            $result = Get-OperationState -ConfigPath $cfgPath
            $result | Should -BeNullOrEmpty
            # Original should be gone, backup should exist
            Test-Path $statePath | Should -BeFalse
        }

        It 'backs up and returns null for invalid JSON' {
            $stateDir = Join-Path $TestDrive 'badjson-test'
            New-Item -Path $stateDir -ItemType Directory -Force | Out-Null
            $cfgPath = Join-Path $stateDir 'config.json'
            $statePath = Join-Path $stateDir 'state.json'

            'this is not json{{{' | Set-Content -Path $statePath -Encoding UTF8

            $result = Get-OperationState -ConfigPath $cfgPath
            $result | Should -BeNullOrEmpty
        }
    }
}
