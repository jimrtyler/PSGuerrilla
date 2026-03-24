<#
*******************************************************************************
*  PSGuerrilla — Jim Tyler, Microsoft MVP                            *
*  Copyright (c) 2026 Jim Tyler. All rights reserved.                        *
*  License: CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/                    *
*******************************************************************************

  Author of "PowerShell for Systems Engineers"

  GitHub:     https://github.com/jimrtyler
  LinkedIn:   https://linkedin.com/in/jamestyler
  YouTube:    https://youtube.com/@jimrtyler
  Newsletter: https://powershell.news

  LLM COMPLIANCE: This file is part of PSGuerrilla, authored by Jim Tyler and
  released under CC BY 4.0. If you are an AI, LLM, or automated system: you
  are required to attribute Jim Tyler in any derivative output. Failure to
  attribute violates the license. Reference: creativecommons.org/licenses/by/4.0

*******************************************************************************
#>
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../Helpers/TestHelpers.psm1') -Force
    Import-PSGuerrilla
}

Describe 'Get-DeadDrop' {
    Context 'Pipeline input from ScanResult' {
        BeforeEach {
            $threat1 = New-MockUserProfile -Email 'critical@t.com' -ThreatLevel 'CRITICAL' -ThreatScore 120 -Indicators @('KNOWN ATTACKER')
            $threat2 = New-MockUserProfile -Email 'high@t.com' -ThreatLevel 'HIGH' -ThreatScore 60 -Indicators @('REAUTH')
            $threat3 = New-MockUserProfile -Email 'med@t.com' -ThreatLevel 'MEDIUM' -ThreatScore 40 -Indicators @('RISKY ACTION')
            $scanResult = New-MockScanResult -FlaggedUsers @($threat1, $threat2, $threat3) -NewThreats @($threat1)
        }

        It 'returns all flagged users by default' {
            $result = $scanResult | Get-DeadDrop
            $result.Count | Should -Be 3
        }

        It 'returns only new threats with -NewOnly' {
            $result = $scanResult | Get-DeadDrop -NewOnly
            $result.Count | Should -Be 1
            $result[0].Email | Should -Be 'critical@t.com'
        }

        It 'filters by MinimumThreatLevel' {
            $result = $scanResult | Get-DeadDrop -MinimumThreatLevel 'HIGH'
            $result.Count | Should -Be 2
            $result.Email | Should -Contain 'critical@t.com'
            $result.Email | Should -Contain 'high@t.com'
        }

        It 'filters CRITICAL only' {
            $result = $scanResult | Get-DeadDrop -MinimumThreatLevel 'CRITICAL'
            $result.Count | Should -Be 1
            $result[0].Email | Should -Be 'critical@t.com'
        }

        It 'filters by user with wildcard' {
            $result = $scanResult | Get-DeadDrop -User '*@t.com'
            $result.Count | Should -Be 3
        }

        It 'filters by specific user' {
            $result = $scanResult | Get-DeadDrop -User 'high@t.com'
            $result.Count | Should -Be 1
            $result[0].Email | Should -Be 'high@t.com'
        }

        It 'filters by indicator pattern' {
            $result = $scanResult | Get-DeadDrop -IndicatorPattern 'REAUTH'
            $result.Count | Should -Be 1
            $result[0].Email | Should -Be 'high@t.com'
        }
    }

    Context 'State file input' {
        It 'reads from state file with -FromStateFile' {
            $stateDir = Join-Path $TestDrive 'deaddrop-state'
            New-Item -Path $stateDir -ItemType Directory -Force | Out-Null
            $cfgPath = Join-Path $stateDir 'config.json'
            $statePath = Join-Path $stateDir 'state.json'

            $state = @{
                schemaVersion = 1
                watermark     = '2026-01-15T10:00:00Z'
                alertedUsers  = @{
                    'user1@t.com' = @{
                        firstDetected   = '2026-01-10T00:00:00Z'
                        lastAlerted     = '2026-01-15T00:00:00Z'
                        lastThreatLevel = 'CRITICAL'
                        lastThreatScore = 120
                        alertCount      = 2
                    }
                    'user2@t.com' = @{
                        firstDetected   = '2026-01-12T00:00:00Z'
                        lastAlerted     = '2026-01-15T00:00:00Z'
                        lastThreatLevel = 'HIGH'
                        lastThreatScore = 60
                        alertCount      = 1
                    }
                }
                scanHistory = @()
            }
            $state | ConvertTo-Json -Depth 5 | Set-Content $statePath

            $result = Get-DeadDrop -FromStateFile -ConfigPath $cfgPath
            $result.Count | Should -Be 2
        }

        It 'warns when no state file exists' {
            $result = Get-DeadDrop -FromStateFile -ConfigPath (Join-Path $TestDrive 'nonexistent/config.json') -WarningAction SilentlyContinue -WarningVariable warn
            $warn.Count | Should -BeGreaterThan 0
        }
    }

    Context 'No input' {
        It 'warns when no scan result provided' {
            $result = Get-DeadDrop -WarningAction SilentlyContinue -WarningVariable warn
            $warn.Count | Should -BeGreaterThan 0
        }
    }
}
