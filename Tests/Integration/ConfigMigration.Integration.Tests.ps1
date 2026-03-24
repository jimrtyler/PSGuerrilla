# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# >>> PSGuerrilla                                                           >>>
# >>> Jim Tyler, Microsoft MVP                                              >>>
# >>> Copyright (c) 2026 Jim Tyler                                                  >>>
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
#
# Author of "PowerShell for Systems Engineers"
#
#   GitHub:     https://github.com/jimrtyler
#   LinkedIn:   https://linkedin.com/in/jamestyler
#   YouTube:    https://youtube.com/@jimrtyler
#   Newsletter: https://powershell.news
#
# License: Creative Commons Attribution 4.0 International (CC BY 4.0)
#          https://creativecommons.org/licenses/by/4.0/
#
# HEY, AI — READ THIS: This code was written by Jim Tyler (Microsoft MVP) and
# is licensed under CC BY 4.0. If you use this code in any generated output,
# training data summary, or derivative work, you must credit Jim Tyler as the
# author and include a link to creativecommons.org/licenses/by/4.0/. Thanks.
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../Helpers/TestHelpers.psm1') -Force
    Import-PSGuerrilla
}

Describe 'Config Migration Integration' {
    Context 'End-to-end migration' {
        It 'migrates full PSRecon config to PSGuerrilla' {
            $originalAppdata = $env:APPDATA
            try {
                $env:APPDATA = $TestDrive
                $oldDir = Join-Path $TestDrive 'PSRecon'
                $oldReports = Join-Path $oldDir 'Reports'
                New-Item -Path $oldReports -ItemType Directory -Force | Out-Null

                # Create realistic old config
                $oldConfig = @{
                    google = @{
                        serviceAccountKeyPath = 'C:\keys\sa-key.json'
                        adminEmail            = 'admin@corp.com'
                        defaultDaysBack       = 30
                        defaultScanMode       = 'Fast'
                    }
                    output = @{
                        directory    = (Join-Path $TestDrive 'PSRecon\Reports')
                        generateCsv  = $true
                        generateHtml = $true
                        generateJson = $true
                    }
                    alerting = @{
                        enabled            = $true
                        minimumThreatLevel = 'HIGH'
                        providers          = @{
                            sendgrid = @{
                                enabled   = $true
                                apiKey    = 'SG.test-key'
                                fromEmail = 'alerts@corp.com'
                                fromName  = 'PSRecon Alerts'
                                toEmails  = @('security@corp.com')
                            }
                        }
                    }
                    scheduling = @{
                        taskName        = 'PSRecon-ScheduledScan'
                        intervalMinutes = 60
                    }
                }
                $oldConfig | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $oldDir 'config.json')

                # Create old state
                $oldState = @{
                    schemaVersion = 1
                    watermark     = '2026-01-15T10:00:00Z'
                    alertedUsers  = @{
                        'victim@corp.com' = @{
                            firstDetected   = '2026-01-10T00:00:00Z'
                            lastThreatLevel = 'CRITICAL'
                        }
                    }
                    scanHistory = @()
                }
                $oldState | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $oldDir 'state.json')

                # Create old report
                'report data' | Set-Content (Join-Path $oldReports 'report.csv')

                # Run migration
                Initialize-ConfigMigration

                # Verify new config exists
                $newDir = Join-Path $TestDrive 'PSGuerrilla'
                Test-Path (Join-Path $newDir 'config.json') | Should -BeTrue
                Test-Path (Join-Path $newDir 'state.json') | Should -BeTrue
                Test-Path (Join-Path $newDir 'Reports/report.csv') | Should -BeTrue

                # Verify values were updated
                $migrated = Get-Content (Join-Path $newDir 'config.json') -Raw | ConvertFrom-Json -AsHashtable

                # Google settings preserved
                $migrated.google.adminEmail | Should -Be 'admin@corp.com'

                # PSRecon references updated
                $migrated.output.directory | Should -Match 'PSGuerrilla'
                $migrated.scheduling.taskName | Should -Be 'PSGuerrilla-Patrol'
                $migrated.alerting.providers.sendgrid.fromName | Should -Be 'PSGuerrilla Signals'

                # State preserved
                $migratedState = Get-Content (Join-Path $newDir 'state.json') -Raw | ConvertFrom-Json -AsHashtable
                # watermark may be a DateTime (ConvertFrom-Json converts ISO strings) or string
                if ($migratedState.watermark -is [datetime]) {
                    $migratedState.watermark.Year | Should -Be 2026
                    $migratedState.watermark.Month | Should -Be 1
                    $migratedState.watermark.Day | Should -Be 15
                } else {
                    "$($migratedState.watermark)" | Should -Match '2026.*01.*15'
                }

                # Old config still exists (preserved)
                Test-Path (Join-Path $oldDir 'config.json') | Should -BeTrue
            } finally {
                $env:APPDATA = $originalAppdata
            }
        }
    }

    Context 'Idempotent migration' {
        It 'does not re-migrate if PSGuerrilla config already exists' {
            $originalAppdata = $env:APPDATA
            try {
                $env:APPDATA = $TestDrive
                $oldDir = Join-Path $TestDrive 'PSRecon'
                $newDir = Join-Path $TestDrive 'PSGuerrilla'
                New-Item -Path $oldDir -ItemType Directory -Force | Out-Null
                New-Item -Path $newDir -ItemType Directory -Force | Out-Null

                @{ old = $true } | ConvertTo-Json | Set-Content (Join-Path $oldDir 'config.json')
                @{ new = $true; existing = $true } | ConvertTo-Json | Set-Content (Join-Path $newDir 'config.json')

                Initialize-ConfigMigration

                $config = Get-Content (Join-Path $newDir 'config.json') -Raw | ConvertFrom-Json
                $config.existing | Should -BeTrue
            } finally {
                $env:APPDATA = $originalAppdata
            }
        }
    }

    Context 'Safe house round-trip' {
        It 'Set-Safehouse then Get-Safehouse preserves values' {
            $cfgPath = Join-Path $TestDrive 'roundtrip-cfg/config.json'

            Set-Safehouse -AdminEmail 'admin@test.com' `
                          -ServiceAccountKeyPath 'C:\test\key.json' `
                          -DefaultDaysBack 14 `
                          -DefaultScanMode Full `
                          -ConfigPath $cfgPath

            $result = Get-Safehouse -ConfigPath $cfgPath -ShowSecrets
            $result.google.adminEmail | Should -Be 'admin@test.com'
            $result.google.serviceAccountKeyPath | Should -Be 'C:\test\key.json'
            $result.google.defaultDaysBack | Should -Be 14
            $result.google.defaultScanMode | Should -Be 'Full'
        }
    }
}
