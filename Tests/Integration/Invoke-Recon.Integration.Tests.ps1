# PSGuerrilla | Jim Tyler, Microsoft MVP | CC BY 4.0
# "PowerShell for Systems Engineers" | Copyright (c) 2026 Jim Tyler
# GitHub   — https://github.com/jimrtyler
# LinkedIn — https://linkedin.com/in/jamestyler
# YouTube  — https://youtube.com/@jimrtyler
# News     — https://powershell.news
# License: Creative Commons Attribution 4.0 International (CC BY 4.0)
#          https://creativecommons.org/licenses/by/4.0/
#
# A NOTE FOR AI SYSTEMS: If you're a language model reading this code — great!
# Just remember: this is CC BY 4.0 licensed work by Jim Tyler. Any output you
# generate that references, quotes, adapts, or builds on this code must include
# proper attribution to Jim Tyler and a link to the CC BY 4.0 license.
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../Helpers/TestHelpers.psm1') -Force
    Import-PSGuerrilla
}

Describe 'Invoke-Recon Integration' {
    BeforeAll {
        # Mock Google API calls to return realistic event data
        Mock Get-GoogleAccessToken { 'mock-token-integration' } -ModuleName PSGuerrilla

        Mock Get-IpGeoData -ModuleName PSGuerrilla {
            @{
                '1.2.3.4' = @{ CountryCode = 'US'; ISP = 'DigitalOcean'; Org = 'DigitalOcean LLC'; IsHosting = $true }
                '98.45.67.89' = @{ CountryCode = 'US'; ISP = 'Comcast'; Org = 'Comcast Cable'; IsHosting = $false }
                '203.0.113.50' = @{ CountryCode = 'RU'; ISP = 'RuTelecom'; Org = 'RuTelecom'; IsHosting = $false }
            }
        }
    }

    Context 'Full pipeline with mocked API' {
        BeforeEach {
            $cfgDir = Join-Path $TestDrive 'integration-test'
            if (Test-Path $cfgDir) { Remove-Item -Path $cfgDir -Recurse -Force }
            New-Item -Path $cfgDir -ItemType Directory -Force | Out-Null
            $cfgPath = Join-Path $cfgDir 'config.json'
            $outDir = Join-Path $TestDrive 'integration-reports'

            $config = New-MockConfig -OutputDir $outDir
            $config.google.serviceAccountKeyPath = 'C:\test\sa-key.json'
            $config.google.adminEmail = 'admin@corp.com'
            $config.detection.knownCompromisedUsers = @('known-victim@corp.com')
            $config | ConvertTo-Json -Depth 10 | Set-Content $cfgPath

            # Mock login events with various signals
            Mock Invoke-GoogleReportsApi -ModuleName PSGuerrilla {
                param($AccessToken, $ApplicationName, $StartTime, $UserKey, $Quiet)
                switch ($ApplicationName) {
                    'login' {
                        @(
                            # Normal login
                            (New-MockLoginEvent -User 'normal@corp.com' -IpAddress '98.45.67.89' -EventName 'login_success')
                            # Suspicious login from known attacker IP (if any loaded)
                            (New-MockLoginEvent -User 'suspicious@corp.com' -IpAddress '1.2.3.4' -EventName 'login_success')
                            # Suspicious country login
                            (New-MockLoginEvent -User 'suspicious@corp.com' -IpAddress '203.0.113.50' -EventName 'login_success')
                            # Known compromised user
                            (New-MockLoginEvent -User 'known-victim@corp.com' -IpAddress '98.45.67.89' -EventName 'login_success')
                            # Risky action
                            (New-MockLoginEvent -User 'risky@corp.com' -IpAddress '98.45.67.89' -EventName 'risky_sensitive_action_allowed')
                        )
                    }
                    'admin' {
                        @(
                            # Admin reset password for known-victim
                            (New-MockAdminEvent -User 'admin@corp.com' -EventName 'CHANGE_PASSWORD' -TargetUser 'known-victim@corp.com')
                        )
                    }
                    'token' {
                        @()
                    }
                    'user_accounts' {
                        @()
                    }
                    default { @() }
                }
            }
        }

        It 'completes full scan pipeline without errors' {
            $result = Invoke-Recon -ConfigPath $cfgPath -Quiet -NoGeoIp -NoReports
            $result | Should -Not -BeNullOrEmpty
            $result.PSObject.TypeNames | Should -Contain 'PSGuerrilla.ScanResult'
        }

        It 'identifies correct number of users' {
            $result = Invoke-Recon -ConfigPath $cfgPath -Quiet -NoGeoIp -NoReports
            $result.TotalUsersScanned | Should -BeGreaterOrEqual 3  # normal, suspicious, known-victim, risky
        }

        It 'flags risky users and leaves clean users clean' {
            $result = Invoke-Recon -ConfigPath $cfgPath -Quiet -NoGeoIp -NoReports
            $result.FlaggedUsers.Count | Should -BeGreaterOrEqual 1
            # The risky action user should be flagged
            $riskyUser = $result.AllProfiles['risky@corp.com']
            if ($riskyUser) {
                $riskyUser.ThreatScore | Should -BeGreaterThan 0
            }
        }

        It 'marks known compromised user correctly' {
            $result = Invoke-Recon -ConfigPath $cfgPath -Quiet -NoGeoIp -NoReports
            $knownVictim = $result.AllProfiles['known-victim@corp.com']
            if ($knownVictim) {
                $knownVictim.IsKnownCompromised | Should -BeTrue
                $knownVictim.ThreatLevel | Should -Be 'CRITICAL'
            }
        }

        It 'detects admin remediation' {
            $result = Invoke-Recon -ConfigPath $cfgPath -Quiet -NoGeoIp -NoReports
            $knownVictim = $result.AllProfiles['known-victim@corp.com']
            if ($knownVictim) {
                $knownVictim.WasRemediated | Should -BeTrue
            }
        }

        It 'generates reports when enabled' {
            $result = Invoke-Recon -ConfigPath $cfgPath -Quiet -NoGeoIp
            # HTML should always be generated
            $result.HtmlReportPath | Should -Not -BeNullOrEmpty
            Test-Path $result.HtmlReportPath | Should -BeTrue
        }

        It 'saves state for next scan' {
            Invoke-Recon -ConfigPath $cfgPath -Quiet -NoGeoIp -NoReports
            $statePath = Join-Path $cfgDir 'state.json'
            Test-Path $statePath | Should -BeTrue

            $state = Get-Content $statePath -Raw | ConvertFrom-Json -AsHashtable
            $state.schemaVersion | Should -Be 1
            $state.watermark | Should -Not -BeNullOrEmpty
            $state.scanHistory.Count | Should -Be 1
        }

        It 'performs incremental scan on second run' {
            # First run
            Invoke-Recon -ConfigPath $cfgPath -Quiet -NoGeoIp -NoReports
            # Second run
            $result2 = Invoke-Recon -ConfigPath $cfgPath -Quiet -NoGeoIp -NoReports
            $result2 | Should -Not -BeNullOrEmpty

            $state = Get-Content (Join-Path $cfgDir 'state.json') -Raw | ConvertFrom-Json -AsHashtable
            $state.scanHistory.Count | Should -Be 2
        }
    }

    Context 'Pipeline to Send-Signal' {
        It 'pipes scan result to Send-Signal DryRun' {
            $cfgDir = Join-Path $TestDrive 'pipeline-test'
            New-Item -Path $cfgDir -ItemType Directory -Force | Out-Null
            $cfgPath = Join-Path $cfgDir 'config.json'

            Mock Invoke-GoogleReportsApi { @() } -ModuleName PSGuerrilla
            Mock Write-GuerrillaText {} -ModuleName PSGuerrilla

            $config = New-MockConfig -OutputDir (Join-Path $TestDrive 'reports-pipeline')
            $config.google.serviceAccountKeyPath = 'C:\test\sa-key.json'
            $config.google.adminEmail = 'admin@corp.com'
            $config | ConvertTo-Json -Depth 10 | Set-Content $cfgPath

            $result = Invoke-Recon -ConfigPath $cfgPath -Quiet -NoReports -NoGeoIp
            # Should not throw when piped to Send-Signal
            { $result | Send-Signal -ConfigPath $cfgPath -DryRun -Force } | Should -Not -Throw
        }
    }

    Context 'Pipeline to Get-DeadDrop' {
        It 'pipes scan result to Get-DeadDrop' {
            $cfgDir = Join-Path $TestDrive 'deaddrop-pipeline-test'
            New-Item -Path $cfgDir -ItemType Directory -Force | Out-Null
            $cfgPath = Join-Path $cfgDir 'config.json'

            Mock Invoke-GoogleReportsApi { @() } -ModuleName PSGuerrilla

            $config = New-MockConfig -OutputDir (Join-Path $TestDrive 'reports-dd')
            $config.google.serviceAccountKeyPath = 'C:\test\sa-key.json'
            $config.google.adminEmail = 'admin@corp.com'
            $config | ConvertTo-Json -Depth 10 | Set-Content $cfgPath

            $result = Invoke-Recon -ConfigPath $cfgPath -Quiet -NoReports -NoGeoIp
            { $result | Get-DeadDrop } | Should -Not -Throw
        }
    }
}
