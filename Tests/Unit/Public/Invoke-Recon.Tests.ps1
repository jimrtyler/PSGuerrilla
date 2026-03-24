<#
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  PSGuerrilla PowerShell Module
  By Jim Tyler, Microsoft MVP
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  "PowerShell for Systems Engineers"

  GitHub   — https://github.com/jimrtyler
  LinkedIn — https://linkedin.com/in/jamestyler
  YouTube  — https://youtube.com/@jimrtyler
  News     — https://powershell.news

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
    Import-Module (Join-Path $PSScriptRoot '../../Helpers/TestHelpers.psm1') -Force
    Import-PSGuerrilla
}

Describe 'Invoke-Recon' {
    BeforeAll {
        # Mock all external dependencies within the module scope
        Mock Get-GoogleAccessToken { 'mock-access-token' } -ModuleName PSGuerrilla
        Mock Invoke-GoogleReportsApi { @() } -ModuleName PSGuerrilla
        Mock Get-IpGeoData { @{} } -ModuleName PSGuerrilla
        Mock Export-FieldReportCsv {} -ModuleName PSGuerrilla
        Mock Export-FieldReportHtml {} -ModuleName PSGuerrilla
        Mock Export-FieldReportJson {} -ModuleName PSGuerrilla
    }

    Context 'Parameter validation' {
        It 'throws when ServiceAccountKeyPath is not provided' {
            { Invoke-Recon -AdminEmail 'admin@t.com' -Quiet } | Should -Throw '*ServiceAccountKeyPath*'
        }

        It 'throws when AdminEmail is not provided' {
            { Invoke-Recon -ServiceAccountKeyPath 'C:\fake\key.json' -Quiet } | Should -Throw '*AdminEmail*'
        }
    }

    Context 'Config loading' {
        It 'loads config from ConfigPath parameter' {
            $cfgDir = Join-Path $TestDrive 'cfg-load-test'
            New-Item -Path $cfgDir -ItemType Directory -Force | Out-Null
            $cfgPath = Join-Path $cfgDir 'config.json'
            $config = New-MockConfig -OutputDir (Join-Path $TestDrive 'reports-cfgload')
            $config.google.serviceAccountKeyPath = 'C:\test\key.json'
            $config.google.adminEmail = 'admin@test.com'
            $config | ConvertTo-Json -Depth 10 | Set-Content $cfgPath

            $result = Invoke-Recon -ConfigPath $cfgPath -Quiet -NoReports -NoGeoIp
            $result | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Scan output' {
        BeforeEach {
            $cfgDir = Join-Path $TestDrive 'scan-out-test'
            if (Test-Path $cfgDir) { Remove-Item -Path $cfgDir -Recurse -Force }
            New-Item -Path $cfgDir -ItemType Directory -Force | Out-Null
            $cfgPath = Join-Path $cfgDir 'config.json'
            $config = New-MockConfig -OutputDir (Join-Path $TestDrive 'reports-scanout')
            $config.google.serviceAccountKeyPath = 'C:\test\key.json'
            $config.google.adminEmail = 'admin@test.com'
            $config | ConvertTo-Json -Depth 10 | Set-Content $cfgPath
        }

        It 'returns PSGuerrilla.ScanResult type' {
            $result = Invoke-Recon -ConfigPath $cfgPath -Quiet -NoReports -NoGeoIp
            $result.PSObject.TypeNames | Should -Contain 'PSGuerrilla.ScanResult'
        }

        It 'includes ScanId as GUID' {
            $result = Invoke-Recon -ConfigPath $cfgPath -Quiet -NoReports -NoGeoIp
            { [guid]::Parse($result.ScanId) } | Should -Not -Throw
        }

        It 'includes scan metadata' {
            $result = Invoke-Recon -ConfigPath $cfgPath -Quiet -NoReports -NoGeoIp
            $result.Timestamp | Should -Not -BeNullOrEmpty
            $result.ScanMode | Should -Be 'Fast'
            $result.DaysAnalyzed | Should -BeGreaterThan 0
        }

        It 'counts clean users correctly' {
            $result = Invoke-Recon -ConfigPath $cfgPath -Quiet -NoReports -NoGeoIp
            $result.CleanCount | Should -Be ($result.TotalUsersScanned - $result.FlaggedUsers.Count)
        }
    }

    Context 'Scan modes' {
        BeforeEach {
            $cfgDir = Join-Path $TestDrive 'mode-test'
            if (Test-Path $cfgDir) { Remove-Item -Path $cfgDir -Recurse -Force }
            New-Item -Path $cfgDir -ItemType Directory -Force | Out-Null
            $cfgPath = Join-Path $cfgDir 'config.json'
            $config = New-MockConfig -OutputDir (Join-Path $TestDrive 'reports-mode')
            $config.google.serviceAccountKeyPath = 'C:\test\key.json'
            $config.google.adminEmail = 'admin@test.com'
            $config | ConvertTo-Json -Depth 10 | Set-Content $cfgPath
        }

        It 'uses Fast mode by default' {
            $result = Invoke-Recon -ConfigPath $cfgPath -Quiet -NoReports -NoGeoIp
            $result.ScanMode | Should -Be 'Fast'
        }

        It 'supports Full mode' {
            $result = Invoke-Recon -ConfigPath $cfgPath -ScanMode Full -Quiet -NoReports -NoGeoIp
            $result.ScanMode | Should -Be 'Full'
        }
    }

    Context 'State management' {
        It 'saves state after scan' {
            $cfgDir = Join-Path $TestDrive 'state-mgmt-test'
            New-Item -Path $cfgDir -ItemType Directory -Force | Out-Null
            $cfgPath = Join-Path $cfgDir 'config.json'
            $config = New-MockConfig -OutputDir (Join-Path $TestDrive 'reports-state')
            $config.google.serviceAccountKeyPath = 'C:\test\key.json'
            $config.google.adminEmail = 'admin@test.com'
            $config | ConvertTo-Json -Depth 10 | Set-Content $cfgPath

            Invoke-Recon -ConfigPath $cfgPath -Quiet -NoReports -NoGeoIp
            $statePath = Join-Path $cfgDir 'state.json'
            Test-Path $statePath | Should -BeTrue
        }

        It 'updates watermark after scan' {
            $cfgDir = Join-Path $TestDrive 'watermark-test'
            New-Item -Path $cfgDir -ItemType Directory -Force | Out-Null
            $cfgPath = Join-Path $cfgDir 'config.json'
            $config = New-MockConfig -OutputDir (Join-Path $TestDrive 'reports-wm')
            $config.google.serviceAccountKeyPath = 'C:\test\key.json'
            $config.google.adminEmail = 'admin@test.com'
            $config | ConvertTo-Json -Depth 10 | Set-Content $cfgPath

            Invoke-Recon -ConfigPath $cfgPath -Quiet -NoReports -NoGeoIp
            $state = Get-Content (Join-Path $cfgDir 'state.json') -Raw | ConvertFrom-Json -AsHashtable
            $state.watermark | Should -Not -BeNullOrEmpty
            $state.schemaVersion | Should -Be 1
        }
    }

    Context '-Quiet switch' {
        It 'suppresses console output' {
            $cfgDir = Join-Path $TestDrive 'quiet-test'
            New-Item -Path $cfgDir -ItemType Directory -Force | Out-Null
            $cfgPath = Join-Path $cfgDir 'config.json'
            $config = New-MockConfig -OutputDir (Join-Path $TestDrive 'reports-quiet')
            $config.google.serviceAccountKeyPath = 'C:\test\key.json'
            $config.google.adminEmail = 'admin@test.com'
            $config | ConvertTo-Json -Depth 10 | Set-Content $cfgPath

            # Should not throw and should return result
            $result = Invoke-Recon -ConfigPath $cfgPath -Quiet -NoReports -NoGeoIp
            $result | Should -Not -BeNullOrEmpty
        }
    }

    Context '-NoGeoIp switch' {
        It 'skips GeoIP enrichment' {
            $cfgDir = Join-Path $TestDrive 'nogeo-test'
            New-Item -Path $cfgDir -ItemType Directory -Force | Out-Null
            $cfgPath = Join-Path $cfgDir 'config.json'
            $config = New-MockConfig -OutputDir (Join-Path $TestDrive 'reports-nogeo')
            $config.google.serviceAccountKeyPath = 'C:\test\key.json'
            $config.google.adminEmail = 'admin@test.com'
            $config | ConvertTo-Json -Depth 10 | Set-Content $cfgPath

            $result = Invoke-Recon -ConfigPath $cfgPath -Quiet -NoReports -NoGeoIp
            Should -Not -Invoke Get-IpGeoData -ModuleName PSGuerrilla
        }
    }
}
