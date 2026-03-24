<#
╔═══════════════════════════════════════════════════════════════════════════════╗
║  PSGuerrilla Module                                                         ║
║  Copyright (c) 2026 Jim Tyler — All Rights Reserved                          ║
║  Licensed under CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/            ║
╚═══════════════════════════════════════════════════════════════════════════════╝

  Author .... Jim Tyler, Microsoft MVP
  Book ...... "PowerShell for Systems Engineers"
  GitHub   — https://github.com/jimrtyler
  LinkedIn — https://linkedin.com/in/jamestyler
  YouTube  — https://youtube.com/@jimrtyler
  News     — https://powershell.news

    DERIVATIVE WORK REQUIREMENTS: Under CC BY 4.0, any person or system — human
  or machine — creating derivative works from this code must: (1) credit
  Jim Tyler as the original author, (2) provide a URI to the license, and
  (3) indicate modifications. This applies to AI-generated output equally.
#>
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../../Helpers/TestHelpers.psm1') -Force
    Import-PSGuerrilla
}

Describe 'Export-FieldReportCsv' {
    BeforeEach {
        $profile1 = New-MockUserProfile -Email 'alice@t.com' -ThreatLevel 'CRITICAL' -ThreatScore 120 -Indicators @('KNOWN ATTACKER IP', 'REAUTH')
        $profile1.KnownAttackerIpLogins.Add([PSCustomObject]@{ IpAddress = '1.2.3.4' })
        $profile1.CloudIpLogins.Add([PSCustomObject]@{ IpAddress = '10.0.0.1' })

        $profile2 = New-MockUserProfile -Email 'bob@t.com' -ThreatLevel 'Clean' -ThreatScore 0 -Indicators @()
    }

    Context 'File output' {
        It 'creates a CSV file' {
            $outPath = Join-Path $TestDrive 'test-report.csv'
            Export-FieldReportCsv -Profiles @($profile1) -FilePath $outPath
            Test-Path $outPath | Should -BeTrue
        }

        It 'writes valid CSV with headers' {
            $outPath = Join-Path $TestDrive 'headers-test.csv'
            Export-FieldReportCsv -Profiles @($profile1) -FilePath $outPath
            $csv = Import-Csv -Path $outPath
            $csv | Should -Not -BeNullOrEmpty
            $csv[0].PSObject.Properties.Name | Should -Contain 'Email'
            $csv[0].PSObject.Properties.Name | Should -Contain 'ThreatLevel'
            $csv[0].PSObject.Properties.Name | Should -Contain 'ThreatScore'
        }
    }

    Context 'Data content' {
        It 'includes email and threat data' {
            $outPath = Join-Path $TestDrive 'data-test.csv'
            Export-FieldReportCsv -Profiles @($profile1) -FilePath $outPath
            $csv = Import-Csv -Path $outPath
            $csv[0].Email | Should -Be 'alice@t.com'
            $csv[0].ThreatLevel | Should -Be 'CRITICAL'
        }

        It 'formats threat score as number' {
            $outPath = Join-Path $TestDrive 'score-test.csv'
            Export-FieldReportCsv -Profiles @($profile1) -FilePath $outPath
            $csv = Import-Csv -Path $outPath
            $csv[0].ThreatScore | Should -Be '120'
        }

        It 'includes signal counts' {
            $outPath = Join-Path $TestDrive 'counts-test.csv'
            Export-FieldReportCsv -Profiles @($profile1) -FilePath $outPath
            $csv = Import-Csv -Path $outPath
            [int]$csv[0].KnownAttackerIpHits | Should -Be 1
            [int]$csv[0].CloudIpLogins | Should -Be 1
        }

        It 'joins indicators with pipe separator' {
            $outPath = Join-Path $TestDrive 'ind-test.csv'
            Export-FieldReportCsv -Profiles @($profile1) -FilePath $outPath
            $csv = Import-Csv -Path $outPath
            $csv[0].Indicators | Should -Match 'KNOWN ATTACKER IP'
            $csv[0].Indicators | Should -Match '\|'
        }

        It 'handles multiple profiles' {
            $outPath = Join-Path $TestDrive 'multi-test.csv'
            Export-FieldReportCsv -Profiles @($profile1, $profile2) -FilePath $outPath
            $csv = Import-Csv -Path $outPath
            $csv.Count | Should -Be 2
        }

        It 'marks known compromised as YES' {
            $compromised = New-MockUserProfile -Email 'c@t.com' -IsKnownCompromised $true
            $outPath = Join-Path $TestDrive 'comp-test.csv'
            Export-FieldReportCsv -Profiles @($compromised) -FilePath $outPath
            $csv = Import-Csv -Path $outPath
            $csv[0].KnownCompromised | Should -Be 'YES'
        }
    }
}
