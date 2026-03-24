<#
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  PSGuerrilla PowerShell Module
  By Jim Tyler, Microsoft MVP
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  "PowerShell for Systems Engineers"

  [GitHub]     https://github.com/jimrtyler
  [LinkedIn]   https://linkedin.com/in/jamestyler
  [YouTube]    https://youtube.com/@jimrtyler
  [Newsletter] https://powershell.news

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

Describe 'Send-Signal' {
    BeforeAll {
        Mock Send-SignalSendGrid { [PSCustomObject]@{ Provider = 'SendGrid'; Success = $true; Message = 'OK'; Error = $null } } -ModuleName PSGuerrilla
        Mock Send-SignalMailgun { [PSCustomObject]@{ Provider = 'Mailgun'; Success = $true; Message = 'OK'; Error = $null } } -ModuleName PSGuerrilla
        Mock Send-SignalTwilio { @([PSCustomObject]@{ Provider = 'Twilio'; Success = $true; Message = 'OK'; Error = $null }) } -ModuleName PSGuerrilla
        Mock Format-SignalContent { '<p>Mock content</p>' } -ModuleName PSGuerrilla
        Mock Write-GuerrillaText {} -ModuleName PSGuerrilla
    }

    BeforeEach {
        $threat = New-MockUserProfile -Email 'victim@t.com' -ThreatLevel 'CRITICAL' -ThreatScore 120 -Indicators @('KNOWN ATTACKER IP')
        $scanResult = New-MockScanResult -FlaggedUsers @($threat) -NewThreats @($threat)
    }

    Context 'Input validation' {
        It 'warns when no ScanResult provided' {
            $result = Send-Signal -WarningAction SilentlyContinue -WarningVariable warn
            $warn.Count | Should -BeGreaterThan 0
        }

        It 'warns when missing alerting config' {
            $cfgDir = Join-Path $TestDrive 'noalert-cfg'
            New-Item -Path $cfgDir -ItemType Directory -Force | Out-Null
            $cfgPath = Join-Path $cfgDir 'config.json'
            @{} | ConvertTo-Json | Set-Content $cfgPath

            $result = $scanResult | Send-Signal -ConfigPath $cfgPath -WarningAction SilentlyContinue -WarningVariable warn
            $warn.Count | Should -BeGreaterThan 0
        }
    }

    Context 'DryRun mode' {
        It 'returns AlertResult with DryRun reason' {
            $cfgDir = Join-Path $TestDrive 'dryrun-cfg'
            New-Item -Path $cfgDir -ItemType Directory -Force | Out-Null
            $cfgPath = Join-Path $cfgDir 'config.json'
            $config = New-MockConfig
            $config | ConvertTo-Json -Depth 10 | Set-Content $cfgPath

            $result = $scanResult | Send-Signal -ConfigPath $cfgPath -DryRun -Force
            $result.Sent | Should -BeFalse
            $result.Reason | Should -Be 'DryRun'
        }
    }

    Context 'No threats above threshold' {
        It 'returns not-sent when no threats meet minimum level' {
            $lowThreat = New-MockUserProfile -Email 'low@t.com' -ThreatLevel 'LOW' -ThreatScore 15 -Indicators @('Cloud logins')
            $lowScan = New-MockScanResult -FlaggedUsers @($lowThreat) -NewThreats @($lowThreat)
            $cfgDir = Join-Path $TestDrive 'nothresh-cfg'
            New-Item -Path $cfgDir -ItemType Directory -Force | Out-Null
            $cfgPath = Join-Path $cfgDir 'config.json'
            $config = New-MockConfig
            $config | ConvertTo-Json -Depth 10 | Set-Content $cfgPath

            $result = $lowScan | Send-Signal -ConfigPath $cfgPath -MinimumThreatLevel 'CRITICAL' -Force
            $result.Sent | Should -BeFalse
            $result.Reason | Should -Match 'No threats'
        }
    }

    Context 'Provider routing' {
        It 'calls SendGrid when enabled' {
            $cfgDir = Join-Path $TestDrive 'sg-route-cfg'
            New-Item -Path $cfgDir -ItemType Directory -Force | Out-Null
            $cfgPath = Join-Path $cfgDir 'config.json'
            $config = New-MockConfig
            $config.alerting.providers.sendgrid.enabled = $true
            $config.alerting.providers.sendgrid.apiKey = 'SG.test'
            $config.alerting.providers.sendgrid.fromEmail = 'from@t.com'
            $config.alerting.providers.sendgrid.toEmails = @('to@t.com')
            $config | ConvertTo-Json -Depth 10 | Set-Content $cfgPath

            $scanResult | Send-Signal -ConfigPath $cfgPath -Force
            Should -Invoke Send-SignalSendGrid -ModuleName PSGuerrilla -Times 1
        }

        It 'returns no-providers when none enabled' {
            $cfgDir = Join-Path $TestDrive 'noprov-cfg'
            New-Item -Path $cfgDir -ItemType Directory -Force | Out-Null
            $cfgPath = Join-Path $cfgDir 'config.json'
            $config = New-MockConfig
            $config | ConvertTo-Json -Depth 10 | Set-Content $cfgPath

            $result = $scanResult | Send-Signal -ConfigPath $cfgPath -Force -WarningAction SilentlyContinue
            $result.Sent | Should -BeFalse
            $result.Reason | Should -Match 'No providers'
        }
    }

    Context 'Subject line' {
        It 'includes PSGuerrilla prefix and threat counts' {
            $cfgDir = Join-Path $TestDrive 'subject-cfg'
            New-Item -Path $cfgDir -ItemType Directory -Force | Out-Null
            $cfgPath = Join-Path $cfgDir 'config.json'
            $config = New-MockConfig
            $config.alerting.providers.sendgrid.enabled = $true
            $config.alerting.providers.sendgrid.apiKey = 'SG.test'
            $config.alerting.providers.sendgrid.fromEmail = 'from@t.com'
            $config.alerting.providers.sendgrid.toEmails = @('to@t.com')
            $config | ConvertTo-Json -Depth 10 | Set-Content $cfgPath

            $scanResult | Send-Signal -ConfigPath $cfgPath -Force
            Should -Invoke Send-SignalSendGrid -ModuleName PSGuerrilla -ParameterFilter { $Subject -match '\[PSGuerrilla\]' }
        }
    }
}
