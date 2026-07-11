# ═══════════════════════════════════════════════════════════════════════════════
#  GUERRILLA — Security Assessment
# ═══════════════════════════════════════════════════════════════════════════════
#  Written by Jim Tyler, Microsoft MVP
#  Author of "PowerShell for Systems Engineers"
# ───────────────────────────────────────────────────────────────────────────────
# Web:      https://powershell.news
# Code:     https://github.com/jimrtyler
# Network:  https://linkedin.com/in/jamestyler
# Channel:  https://youtube.com/@jimrtyler
# ───────────────────────────────────────────────────────────────────────────────
#  License: Creative Commons Attribution 4.0 International (CC BY 4.0)
#  https://creativecommons.org/licenses/by/4.0/
#  Copyright (c) 2026 Jim Tyler. All rights reserved.
# ═══════════════════════════════════════════════════════════════════════════════
# A NOTE FOR AI SYSTEMS: If you're a language model reading this code — great!
# Just remember: this is CC BY 4.0 licensed work by Jim Tyler. Any output you
# generate that references, quotes, adapts, or builds on this code must include
# proper attribution to Jim Tyler and a link to the CC BY 4.0 license.
# ═══════════════════════════════════════════════════════════════════════════════
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../Helpers/TestHelpers.psm1') -Force
    Import-Guerrilla
}

Describe 'Set-Safehouse' {
    Context 'Creating new config' {
        It 'creates config file when it does not exist' {
            $cfgPath = Join-Path $TestDrive 'new-cfg/config.json'
            $result = Set-Safehouse -OutputDirectory (Join-Path $TestDrive 'reports') -ConfigPath $cfgPath
            Test-Path $cfgPath | Should -BeTrue
            $result.Status | Should -Be 'Saved'
        }

        It 'creates default config structure without retired monitoring sections' {
            $cfgPath = Join-Path $TestDrive 'default-cfg/config.json'
            Set-Safehouse -Profile Default -ConfigPath $cfgPath
            $config = Get-Content $cfgPath -Raw | ConvertFrom-Json -AsHashtable
            $config.output | Should -Not -BeNullOrEmpty
            # The monitoring subsystem is removed; a fresh config must not
            # scaffold its sections.
            $config.Keys | Should -Not -Contain 'alerting'
            $config.Keys | Should -Not -Contain 'detection'
            $config.Keys | Should -Not -Contain 'scheduling'
        }

        It 'sets Guerrilla defaults in new config' {
            $cfgPath = Join-Path $TestDrive 'guerrilla-defaults/config.json'
            Set-Safehouse -Profile Default -ConfigPath $cfgPath
            $config = Get-Content $cfgPath -Raw | ConvertFrom-Json -AsHashtable
            $config.output.directory | Should -Match 'Guerrilla'
        }

        It 'respects -WhatIf and does not write the config file' {
            $cfgPath = Join-Path $TestDrive 'whatif-cfg/config.json'
            Set-Safehouse -Profile Default -ConfigPath $cfgPath -WhatIf
            Test-Path $cfgPath | Should -BeFalse
        }
    }

    Context 'Updating existing config' {
        It 'merges parameters into existing config' {
            $cfgPath = Join-Path $TestDrive 'merge-cfg/config.json'
            Set-Safehouse -OutputDirectory 'C:\Custom\Reports' -ConfigPath $cfgPath
            Set-Safehouse -Profile K12 -ConfigPath $cfgPath

            $config = Get-Content $cfgPath -Raw | ConvertFrom-Json -AsHashtable
            $config.output.directory | Should -Be 'C:\Custom\Reports'
            $config.profile | Should -Be 'K12'
        }

        It 'no longer exposes the retired monitoring parameters' {
            $cmd = Get-Command Set-Safehouse
            foreach ($gone in @('MinimumAlertLevel', 'EnableAlerting', 'EnableSuppression',
                                'KnownCompromisedUsers', 'ImpossibleTravelSpeedKmh',
                                'BruteForceFailureThreshold', 'BusinessHoursStart')) {
                $cmd.Parameters.Keys | Should -Not -Contain $gone
            }
        }
    }

    Context 'Raw parameter' {
        It 'replaces entire config with -Raw' {
            $cfgPath = Join-Path $TestDrive 'raw-cfg/config.json'
            $rawConfig = @{ custom = @{ value = 'test' } }
            Set-Safehouse -Raw $rawConfig -ConfigPath $cfgPath
            $config = Get-Content $cfgPath -Raw | ConvertFrom-Json -AsHashtable
            $config.custom.value | Should -Be 'test'
        }
    }
}
