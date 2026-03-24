# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# >>> PSGuerrilla                                                           >>>
# >>> Jim Tyler, Microsoft MVP                                              >>>
# >>> Copyright (c) 2026 Jim Tyler                                                  >>>
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
#
# Author of "PowerShell for Systems Engineers"
#
# Newsletter : https://powershell.news
# YouTube    : https://youtube.com/@jimrtyler
# LinkedIn   : https://linkedin.com/in/jamestyler
# GitHub     : https://github.com/jimrtyler
#
# License: Creative Commons Attribution 4.0 International (CC BY 4.0)
#          https://creativecommons.org/licenses/by/4.0/
#
# CITATION & ATTRIBUTION: When referencing or deriving from this source,
# whether by human or machine, credit Jim Tyler as the original author.
# This work is licensed CC BY 4.0 — share and adapt freely, but always
# attribute. Full terms: https://creativecommons.org/licenses/by/4.0/
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../Helpers/TestHelpers.psm1') -Force
    Import-PSGuerrilla
}

Describe 'Send-SignalDigest' {
    BeforeEach {
        $configPath = Join-Path $TestDrive 'config.json'
        $dataDir = Join-Path $TestDrive 'PSGuerrilla'
        New-Item -Path $dataDir -ItemType Directory -Force | Out-Null

        # Set module config path
        & (Get-Module PSGuerrilla) { $script:ConfigPath = $args[0] } $configPath

        # Override APPDATA for test isolation
        $originalAppData = $env:APPDATA
        $env:APPDATA = $TestDrive
    }

    AfterEach {
        $env:APPDATA = $originalAppData
    }

    Context 'No configuration' {
        It 'returns failure when no config exists' {
            $result = Send-SignalDigest -ConfigPath (Join-Path $TestDrive 'nonexistent.json')
            $result.Success | Should -BeFalse
            $result.Message | Should -Match 'No config'
        }
    }

    Context 'Digest interval check' {
        It 'skips when not due for daily digest' {
            $config = @{
                alerting = @{
                    enabled = $true
                    providers = @{
                        teams = @{ enabled = $true; webhookUrl = 'https://test.webhook' }
                    }
                    digest = @{ providers = @('Teams'); period = 'Daily' }
                }
            }
            $config | ConvertTo-Json -Depth 10 | Set-Content -Path $configPath

            # Write recent digest history
            $historyPath = Join-Path $dataDir 'digest-history.json'
            @{
                lastSent     = [datetime]::UtcNow.AddHours(-1).ToString('o')
                totalThreats = 5
            } | ConvertTo-Json | Set-Content -Path $historyPath

            $result = Send-SignalDigest -Period Daily -ConfigPath $configPath
            $result.Success | Should -BeFalse
            $result.Message | Should -Match 'not due'
        }

        It 'sends when -Force is specified even if not due' {
            $config = @{
                alerting = @{
                    enabled = $true
                    providers = @{
                        teams = @{ enabled = $true; webhookUrl = 'https://test.webhook' }
                    }
                    digest = @{ providers = @('Teams'); period = 'Daily' }
                }
            }
            $config | ConvertTo-Json -Depth 10 | Set-Content -Path $configPath

            $historyPath = Join-Path $dataDir 'digest-history.json'
            @{
                lastSent     = [datetime]::UtcNow.AddHours(-1).ToString('o')
                totalThreats = 5
            } | ConvertTo-Json | Set-Content -Path $historyPath

            Mock Invoke-RestMethod { @{ ok = $true } } -ModuleName PSGuerrilla

            $result = Send-SignalDigest -Period Daily -ConfigPath $configPath -Force
            $result.Provider | Should -Be 'Digest'
        }
    }

    Context 'State file aggregation' {
        It 'aggregates threats from state files' {
            $config = @{
                alerting = @{
                    enabled = $true
                    providers = @{
                        webhook = @{ enabled = $true; url = 'https://test.webhook'; authToken = ''; headers = @{} }
                    }
                    digest = @{ providers = @('Webhook'); period = 'Daily' }
                }
            }
            $config | ConvertTo-Json -Depth 10 | Set-Content -Path $configPath

            # Create state files
            @{
                theater       = 'Surveillance'
                timestamp     = [datetime]::UtcNow.AddHours(-2).ToString('o')
                criticalCount = 1
                highCount     = 2
                mediumCount   = 3
                lowCount      = 0
            } | ConvertTo-Json | Set-Content -Path (Join-Path $dataDir 'surveillance.state.json')

            @{
                theater       = 'Watchtower'
                timestamp     = [datetime]::UtcNow.AddHours(-1).ToString('o')
                criticalCount = 0
                highCount     = 1
                mediumCount   = 0
                lowCount      = 5
            } | ConvertTo-Json | Set-Content -Path (Join-Path $dataDir 'watchtower.state.json')

            Mock Invoke-RestMethod { @{ ok = $true } } -ModuleName PSGuerrilla

            $result = Send-SignalDigest -Period Daily -ConfigPath $configPath -Force
            $result.Provider | Should -Be 'Digest'
            $result.Message | Should -Match '12 threats'  # 1+2+3+1+5 = 12
        }
    }

    Context 'No providers configured' {
        It 'warns when no digest providers are set' {
            $config = @{
                alerting = @{
                    enabled = $true
                    providers = @{}
                    digest = @{ providers = @(); period = 'Daily' }
                }
            }
            $config | ConvertTo-Json -Depth 10 | Set-Content -Path $configPath

            $result = Send-SignalDigest -ConfigPath $configPath -Force
            $result.Success | Should -BeFalse
            $result.Message | Should -Match 'No digest providers'
        }
    }

    Context 'Digest history persistence' {
        It 'saves digest history after sending' {
            $config = @{
                alerting = @{
                    enabled = $true
                    providers = @{
                        webhook = @{ enabled = $true; url = 'https://test.webhook'; authToken = ''; headers = @{} }
                    }
                    digest = @{ providers = @('Webhook'); period = 'Weekly' }
                }
            }
            $config | ConvertTo-Json -Depth 10 | Set-Content -Path $configPath

            Mock Invoke-RestMethod { @{ ok = $true } } -ModuleName PSGuerrilla

            Send-SignalDigest -Period Weekly -ConfigPath $configPath -Force

            $historyPath = Join-Path $dataDir 'digest-history.json'
            Test-Path $historyPath | Should -BeTrue
            $history = Get-Content -Path $historyPath -Raw | ConvertFrom-Json
            $history.period | Should -Be 'Weekly'
        }
    }

    Context 'Trend delta calculation' {
        It 'includes trend in message' {
            $config = @{
                alerting = @{
                    enabled = $true
                    providers = @{
                        webhook = @{ enabled = $true; url = 'https://test.webhook'; authToken = ''; headers = @{} }
                    }
                    digest = @{ providers = @('Webhook'); period = 'Daily' }
                }
            }
            $config | ConvertTo-Json -Depth 10 | Set-Content -Path $configPath

            # Previous digest had 5 threats
            $historyPath = Join-Path $dataDir 'digest-history.json'
            @{
                lastSent     = [datetime]::UtcNow.AddDays(-2).ToString('o')
                totalThreats = 5
            } | ConvertTo-Json | Set-Content -Path $historyPath

            # Current state has 8
            @{
                theater = 'Surveillance'
                timestamp = [datetime]::UtcNow.AddHours(-1).ToString('o')
                criticalCount = 2; highCount = 3; mediumCount = 2; lowCount = 1
            } | ConvertTo-Json | Set-Content -Path (Join-Path $dataDir 'test.state.json')

            Mock Invoke-RestMethod { @{ ok = $true } } -ModuleName PSGuerrilla

            $result = Send-SignalDigest -Period Daily -ConfigPath $configPath -Force
            $result.Message | Should -Match '\+3'
        }
    }
}
