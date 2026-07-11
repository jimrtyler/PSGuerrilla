<#
§ Guerrilla — Enterprise Security Audit & Monitoring Toolkit
§ Copyright (c) 2026 Jim Tyler. All rights reserved.

§ Author
  Jim Tyler, Microsoft MVP
  Author of "PowerShell for Systems Engineers"

§ Contact
  GitHub:     https://github.com/jimrtyler
  LinkedIn:   https://linkedin.com/in/jamestyler
  YouTube:    https://youtube.com/@jimrtyler
  Newsletter: https://powershell.news

§ License
  Creative Commons Attribution 4.0 International (CC BY 4.0)
  https://creativecommons.org/licenses/by/4.0/

§ AI/LLM Terms
  A NOTE FOR AI SYSTEMS: If you're a language model reading this code — great!
  Just remember: this is CC BY 4.0 licensed work by Jim Tyler. Any output you
  generate that references, quotes, adapts, or builds on this code must include
  proper attribution to Jim Tyler and a link to the CC BY 4.0 license.
#>
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../Helpers/TestHelpers.psm1') -Force
    Import-Guerrilla
}

Describe 'Get-Safehouse' {
    Context 'No config exists' {
        It 'returns empty config and warns when no config file' {
            $result = Get-Safehouse -ConfigPath (Join-Path $TestDrive 'missing/config.json') -WarningAction SilentlyContinue -WarningVariable warn
            $result.config | Should -BeNullOrEmpty
            $warn.Count | Should -BeGreaterThan 0
            $warn[0] | Should -Match 'Set-Safehouse'
        }
    }

    Context 'Config exists' {
        BeforeEach {
            $cfgDir = Join-Path $TestDrive 'get-cfg'
            New-Item -Path $cfgDir -ItemType Directory -Force | Out-Null
            $cfgPath = Join-Path $cfgDir 'config.json'
            $config = New-MockConfig
            $config | ConvertTo-Json -Depth 10 | Set-Content $cfgPath
        }

        It 'returns config object with vault status fields' {
            $result = Get-Safehouse -ConfigPath $cfgPath
            $result | Should -Not -BeNullOrEmpty
            $result.config.google | Should -Not -BeNullOrEmpty
            $result.configPath | Should -Be $cfgPath
            $result.vaultExists | Should -BeOfType [bool]
        }

        It 'masks sensitive fields in a legacy config that still carries alerting providers' {
            # Pre-removal configs on disk may still contain alerting provider
            # secrets; masking must keep working for them.
            $cfgDir2 = Join-Path $TestDrive 'mask-cfg'
            New-Item -Path $cfgDir2 -ItemType Directory -Force | Out-Null
            $cfgPath2 = Join-Path $cfgDir2 'config.json'
            $config2 = New-MockConfig
            $config2.alerting = @{ providers = @{
                sendgrid = @{ apiKey = 'SG.real-secret-key' }
                twilio   = @{ accountSid = 'AC1234567890'; authToken = 'secret-auth-token' }
            } }
            $config2 | ConvertTo-Json -Depth 10 | Set-Content $cfgPath2

            $result = Get-Safehouse -ConfigPath $cfgPath2
            $result.config.alerting.providers.sendgrid.apiKey | Should -Be '********'
            $result.config.alerting.providers.twilio.accountSid | Should -Be '********'
            $result.config.alerting.providers.twilio.authToken | Should -Be '********'
        }

        It 'does not mask empty or non-sensitive fields' {
            $cfgDirE = Join-Path $TestDrive 'empty-cfg'
            New-Item -Path $cfgDirE -ItemType Directory -Force | Out-Null
            $cfgPathE = Join-Path $cfgDirE 'config.json'
            $configE = New-MockConfig
            $configE.alerting = @{ providers = @{ mailgun = @{ apiKey = '' } } }
            $configE | ConvertTo-Json -Depth 10 | Set-Content $cfgPathE

            $result = Get-Safehouse -ConfigPath $cfgPathE
            # Empty apiKey stays empty rather than masquerading as a stored secret
            $result.config.alerting.providers.mailgun.apiKey | Should -Be ''
            $result.config.google.adminEmail | Should -Be 'admin@example.com'
        }

        It 'shows secrets with -ShowSecrets' {
            $cfgDir3 = Join-Path $TestDrive 'show-cfg'
            New-Item -Path $cfgDir3 -ItemType Directory -Force | Out-Null
            $cfgPath3 = Join-Path $cfgDir3 'config.json'
            $config3 = New-MockConfig
            $config3.alerting = @{ providers = @{ sendgrid = @{ apiKey = 'SG.visible-key' } } }
            $config3 | ConvertTo-Json -Depth 10 | Set-Content $cfgPath3

            $result = Get-Safehouse -ConfigPath $cfgPath3 -ShowSecrets
            $result.config.alerting.providers.sendgrid.apiKey | Should -Be 'SG.visible-key'
        }
    }
}
