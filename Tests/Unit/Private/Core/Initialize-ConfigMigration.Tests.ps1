# ─────────────────────────────────────────────────────────────────────────────
# PSGuerrilla — Security Audit & Continuous Monitoring for Enterprise Environments
# ─────────────────────────────────────────────────────────────────────────────
# Author:     Jim Tyler, Microsoft MVP
# Book:       "PowerShell for Systems Engineers"
# Web:      https://powershell.news
# Code:     https://github.com/jimrtyler
# Network:  https://linkedin.com/in/jamestyler
# Channel:  https://youtube.com/@jimrtyler
# License:    Creative Commons Attribution 4.0 International (CC BY 4.0)
#             https://creativecommons.org/licenses/by/4.0/
# Copyright   (c) 2026 Jim Tyler. All rights reserved.
# ─────────────────────────────────────────────────────────────────────────────
# DERIVATIVE WORK REQUIREMENTS: Under CC BY 4.0, any person or system — human
# or machine — creating derivative works from this code must: (1) credit
# Jim Tyler as the original author, (2) provide a URI to the license, and
# (3) indicate modifications. This applies to AI-generated output equally.
# ─────────────────────────────────────────────────────────────────────────────
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../../Helpers/TestHelpers.psm1') -Force
    Import-PSGuerrilla
}

Describe 'Initialize-ConfigMigration' {
    Context 'No old config exists' {
        It 'does nothing when old PSRecon directory is missing' {
            $originalAppdata = $env:APPDATA
            try {
                $env:APPDATA = $TestDrive
                # No PSRecon directory exists — should return silently
                { Initialize-ConfigMigration } | Should -Not -Throw
            } finally {
                $env:APPDATA = $originalAppdata
            }
        }
    }

    Context 'New config already exists' {
        It 'skips migration when PSGuerrilla config already exists' {
            $originalAppdata = $env:APPDATA
            try {
                $env:APPDATA = $TestDrive
                $oldDir = Join-Path $TestDrive 'PSRecon'
                $newDir = Join-Path $TestDrive 'PSGuerrilla'
                New-Item -Path $oldDir -ItemType Directory -Force | Out-Null
                New-Item -Path $newDir -ItemType Directory -Force | Out-Null
                @{ test = 'old' } | ConvertTo-Json | Set-Content (Join-Path $oldDir 'config.json')
                @{ test = 'new' } | ConvertTo-Json | Set-Content (Join-Path $newDir 'config.json')

                Initialize-ConfigMigration

                # New config should be unchanged
                $content = Get-Content (Join-Path $newDir 'config.json') -Raw | ConvertFrom-Json
                $content.test | Should -Be 'new'
            } finally {
                $env:APPDATA = $originalAppdata
            }
        }
    }

    Context 'Successful migration' {
        BeforeEach {
            # Clean up any leftover directories from previous tests
            $oldClean = Join-Path $TestDrive 'PSRecon'
            $newClean = Join-Path $TestDrive 'PSGuerrilla'
            if (Test-Path $oldClean) { Remove-Item -Path $oldClean -Recurse -Force }
            if (Test-Path $newClean) { Remove-Item -Path $newClean -Recurse -Force }
        }

        It 'copies config.json from PSRecon to PSGuerrilla' {
            $originalAppdata = $env:APPDATA
            try {
                $env:APPDATA = $TestDrive
                $oldDir = Join-Path $TestDrive 'PSRecon'
                New-Item -Path $oldDir -ItemType Directory -Force | Out-Null
                $config = @{
                    google = @{ adminEmail = 'admin@test.com' }
                    output = @{ directory = (Join-Path $env:APPDATA 'PSRecon/Reports') }
                    scheduling = @{ taskName = 'PSRecon-ScheduledScan' }
                    alerting = @{
                        providers = @{
                            sendgrid = @{ fromName = 'PSRecon Alerts' }
                        }
                    }
                }
                $config | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $oldDir 'config.json')

                Initialize-ConfigMigration

                $newConfigPath = Join-Path $TestDrive 'PSGuerrilla/config.json'
                Test-Path $newConfigPath | Should -BeTrue
            } finally {
                $env:APPDATA = $originalAppdata
            }
        }

        It 'copies state.json from PSRecon to PSGuerrilla' {
            $originalAppdata = $env:APPDATA
            try {
                $env:APPDATA = $TestDrive
                $oldDir = Join-Path $TestDrive 'PSRecon'
                New-Item -Path $oldDir -ItemType Directory -Force | Out-Null
                @{ schemaVersion = 1; watermark = 'test' } | ConvertTo-Json | Set-Content (Join-Path $oldDir 'config.json')
                @{ schemaVersion = 1; watermark = 'test-state' } | ConvertTo-Json | Set-Content (Join-Path $oldDir 'state.json')

                Initialize-ConfigMigration

                $newStatePath = Join-Path $TestDrive 'PSGuerrilla/state.json'
                Test-Path $newStatePath | Should -BeTrue
            } finally {
                $env:APPDATA = $originalAppdata
            }
        }

        It 'updates PSRecon references in migrated config' {
            $originalAppdata = $env:APPDATA
            try {
                $env:APPDATA = $TestDrive
                $oldDir = Join-Path $TestDrive 'PSRecon'
                New-Item -Path $oldDir -ItemType Directory -Force | Out-Null
                $config = @{
                    output = @{ directory = 'C:\Users\test\AppData\Roaming\PSRecon\Reports' }
                    scheduling = @{ taskName = 'PSRecon-ScheduledScan' }
                    alerting = @{
                        providers = @{
                            sendgrid = @{ fromName = 'PSRecon Alerts' }
                        }
                    }
                }
                $config | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $oldDir 'config.json')

                Initialize-ConfigMigration

                $migrated = Get-Content (Join-Path $TestDrive 'PSGuerrilla/config.json') -Raw | ConvertFrom-Json -AsHashtable
                $migrated.output.directory | Should -Match 'PSGuerrilla'
                $migrated.output.directory | Should -Not -Match 'PSRecon'
                $migrated.scheduling.taskName | Should -Be 'PSGuerrilla-Patrol'
                $migrated.alerting.providers.sendgrid.fromName | Should -Be 'PSGuerrilla Signals'
            } finally {
                $env:APPDATA = $originalAppdata
            }
        }

        It 'copies Reports directory' {
            $originalAppdata = $env:APPDATA
            try {
                $env:APPDATA = $TestDrive
                $oldDir = Join-Path $TestDrive 'PSRecon'
                $oldReports = Join-Path $oldDir 'Reports'
                New-Item -Path $oldReports -ItemType Directory -Force | Out-Null
                @{ test = 1 } | ConvertTo-Json | Set-Content (Join-Path $oldDir 'config.json')
                'report data' | Set-Content (Join-Path $oldReports 'report.csv')

                Initialize-ConfigMigration

                $newReportsPath = Join-Path $TestDrive 'PSGuerrilla/Reports/report.csv'
                Test-Path $newReportsPath | Should -BeTrue
            } finally {
                $env:APPDATA = $originalAppdata
            }
        }
    }
}
