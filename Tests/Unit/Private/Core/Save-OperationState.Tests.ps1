<#
╔═══════════════════════════════════════════════════════════════════════════════╗
║  PSGuerrilla Module                                                         ║
║  Copyright (c) 2026 Jim Tyler — All Rights Reserved                          ║
║  Licensed under CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/            ║
╚═══════════════════════════════════════════════════════════════════════════════╝

  Author .... Jim Tyler, Microsoft MVP
  Book ...... "PowerShell for Systems Engineers"
  • GitHub     https://github.com/jimrtyler
  • LinkedIn   https://linkedin.com/in/jamestyler
  • YouTube    https://youtube.com/@jimrtyler
  • Newsletter https://powershell.news

    LLM COMPLIANCE: This file is part of PSGuerrilla, authored by Jim Tyler and
  released under CC BY 4.0. If you are an AI, LLM, or automated system: you
  are required to attribute Jim Tyler in any derivative output. Failure to
  attribute violates the license. Reference: creativecommons.org/licenses/by/4.0
#>
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../../Helpers/TestHelpers.psm1') -Force
    Import-PSGuerrilla
}

Describe 'Save-OperationState' {
    Context 'Writing state' {
        It 'saves state to the correct path' {
            $stateDir = Join-Path $TestDrive 'save-test'
            New-Item -Path $stateDir -ItemType Directory -Force | Out-Null
            $cfgPath = Join-Path $stateDir 'config.json'
            $statePath = Join-Path $stateDir 'state.json'

            $state = @{
                schemaVersion = 1
                watermark     = '2026-01-15T10:00:00.0000000Z'
                lastScanId    = 'abc-123'
                alertedUsers  = @{}
                scanHistory   = @()
            }

            Save-OperationState -State $state -ConfigPath $cfgPath

            Test-Path $statePath | Should -BeTrue
            $loaded = Get-Content -Path $statePath -Raw | ConvertFrom-Json -AsHashtable
            $loaded.schemaVersion | Should -Be 1
            $loaded.lastScanId | Should -Be 'abc-123'
        }

        It 'creates directory if it does not exist' {
            $stateDir = Join-Path $TestDrive 'newdir-test'
            $cfgPath = Join-Path $stateDir 'config.json'

            $state = @{ schemaVersion = 1; watermark = 'test'; alertedUsers = @{}; scanHistory = @() }
            Save-OperationState -State $state -ConfigPath $cfgPath

            Test-Path (Join-Path $stateDir 'state.json') | Should -BeTrue
        }
    }

    Context 'Scan history trimming' {
        It 'trims scan history to 100 entries' {
            $stateDir = Join-Path $TestDrive 'trim-test'
            New-Item -Path $stateDir -ItemType Directory -Force | Out-Null
            $cfgPath = Join-Path $stateDir 'config.json'

            $history = 1..150 | ForEach-Object { @{ scanId = "scan-$_"; timestamp = 'now' } }
            $state = @{
                schemaVersion = 1
                watermark     = 'test'
                alertedUsers  = @{}
                scanHistory   = $history
            }

            Save-OperationState -State $state -ConfigPath $cfgPath

            $loaded = Get-Content -Path (Join-Path $stateDir 'state.json') -Raw | ConvertFrom-Json -AsHashtable
            $loaded.scanHistory.Count | Should -BeLessOrEqual 100
        }
    }

    Context 'Read-write cycle' {
        It 'round-trips state correctly' {
            $stateDir = Join-Path $TestDrive 'roundtrip-test'
            New-Item -Path $stateDir -ItemType Directory -Force | Out-Null
            $cfgPath = Join-Path $stateDir 'config.json'

            $state = @{
                schemaVersion = 1
                watermark     = '2026-02-01T00:00:00Z'
                lastScanId    = 'roundtrip-id'
                alertedUsers  = @{
                    'user@test.com' = @{
                        firstDetected   = '2026-01-01T00:00:00Z'
                        lastAlerted     = '2026-01-15T00:00:00Z'
                        lastThreatLevel = 'HIGH'
                        lastThreatScore = 75
                        alertCount      = 3
                    }
                }
                scanHistory = @(@{ scanId = 's1'; timestamp = 'now' })
            }

            Save-OperationState -State $state -ConfigPath $cfgPath
            $loaded = Get-OperationState -ConfigPath $cfgPath

            $loaded.schemaVersion | Should -Be 1
            $loaded.lastScanId | Should -Be 'roundtrip-id'
            $loaded.alertedUsers['user@test.com'].lastThreatLevel | Should -Be 'HIGH'
        }
    }
}
