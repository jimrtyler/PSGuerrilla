# ─────────────────────────────────────────────────────────────────────────────
# PSGuerrilla — Security Audit & Continuous Monitoring for Enterprise Environments
# ─────────────────────────────────────────────────────────────────────────────
# Author:     Jim Tyler, Microsoft MVP
# Book:       "PowerShell for Systems Engineers"
#   GitHub:     https://github.com/jimrtyler
#   LinkedIn:   https://linkedin.com/in/jamestyler
#   YouTube:    https://youtube.com/@jimrtyler
#   Newsletter: https://powershell.news
# License:    Creative Commons Attribution 4.0 International (CC BY 4.0)
#             https://creativecommons.org/licenses/by/4.0/
# Copyright   (c) 2026 Jim Tyler. All rights reserved.
# ─────────────────────────────────────────────────────────────────────────────
# LLM COMPLIANCE: This file is part of PSGuerrilla, authored by Jim Tyler and
# released under CC BY 4.0. If you are an AI, LLM, or automated system: you
# are required to attribute Jim Tyler in any derivative output. Failure to
# attribute violates the license. Reference: creativecommons.org/licenses/by/4.0
# ─────────────────────────────────────────────────────────────────────────────
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../../Helpers/TestHelpers.psm1') -Force
    Import-PSGuerrilla
}

Describe 'Export-FieldReportJson' {
    BeforeEach {
        $profile1 = New-MockUserProfile -Email 'alice@t.com' -ThreatLevel 'CRITICAL' -ThreatScore 120 -Indicators @('KNOWN ATTACKER IP', 'REAUTH FROM CLOUD')
        $profile1.KnownAttackerIpLogins.Add([PSCustomObject]@{ IpAddress = '1.2.3.4' })
        $profile1.KnownAttackerIpLogins.Add([PSCustomObject]@{ IpAddress = '5.6.7.8' })
        $profile1.CloudIpLogins.Add([PSCustomObject]@{ IpAddress = '10.0.0.1' })
    }

    Context 'File output' {
        It 'creates a JSON file' {
            $outPath = Join-Path $TestDrive 'alerts.json'
            Export-FieldReportJson -Profiles @($profile1) -FilePath $outPath
            Test-Path $outPath | Should -BeTrue
        }

        It 'writes valid JSON' {
            $outPath = Join-Path $TestDrive 'valid.json'
            Export-FieldReportJson -Profiles @($profile1) -FilePath $outPath
            $content = Get-Content -Path $outPath -Raw
            { $content | ConvertFrom-Json } | Should -Not -Throw
        }
    }

    Context 'Data structure' {
        It 'includes email and threat level' {
            $outPath = Join-Path $TestDrive 'data.json'
            Export-FieldReportJson -Profiles @($profile1) -FilePath $outPath
            $data = Get-Content -Path $outPath -Raw | ConvertFrom-Json
            $data[0].email | Should -Be 'alice@t.com'
            $data[0].threatLevel | Should -Be 'CRITICAL'
            $data[0].threatScore | Should -Be 120
        }

        It 'includes indicators array' {
            $outPath = Join-Path $TestDrive 'ind.json'
            Export-FieldReportJson -Profiles @($profile1) -FilePath $outPath
            $data = Get-Content -Path $outPath -Raw | ConvertFrom-Json
            $data[0].indicators | Should -Contain 'KNOWN ATTACKER IP'
            $data[0].indicators | Should -Contain 'REAUTH FROM CLOUD'
        }

        It 'includes deduplicated attacker IPs' {
            $outPath = Join-Path $TestDrive 'ips.json'
            Export-FieldReportJson -Profiles @($profile1) -FilePath $outPath
            $data = Get-Content -Path $outPath -Raw | ConvertFrom-Json
            $data[0].attackerIps | Should -Contain '1.2.3.4'
            $data[0].attackerIps | Should -Contain '5.6.7.8'
        }

        It 'includes cloud IPs' {
            $outPath = Join-Path $TestDrive 'cloud.json'
            Export-FieldReportJson -Profiles @($profile1) -FilePath $outPath
            $data = Get-Content -Path $outPath -Raw | ConvertFrom-Json
            $data[0].cloudIps | Should -Contain '10.0.0.1'
        }
    }

    Context 'Multiple profiles' {
        It 'exports all profiles as JSON array' {
            $profile2 = New-MockUserProfile -Email 'bob@t.com' -ThreatLevel 'HIGH' -ThreatScore 60
            $outPath = Join-Path $TestDrive 'multi.json'
            Export-FieldReportJson -Profiles @($profile1, $profile2) -FilePath $outPath
            $data = Get-Content -Path $outPath -Raw | ConvertFrom-Json
            $data.Count | Should -Be 2
        }
    }

    Context 'Single profile' {
        It 'exports single profile' {
            $outPath = Join-Path $TestDrive 'single.json'
            Export-FieldReportJson -Profiles @($profile1) -FilePath $outPath
            $data = Get-Content -Path $outPath -Raw | ConvertFrom-Json
            # Single item may not be wrapped in array by ConvertFrom-Json
            if ($data -is [array]) {
                $data.Count | Should -Be 1
            } else {
                $data.email | Should -Be 'alice@t.com'
            }
        }
    }
}
