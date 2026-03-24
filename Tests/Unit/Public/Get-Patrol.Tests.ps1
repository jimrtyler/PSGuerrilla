# ═══════════════════════════════════════════════════════════════════════════════
#  PSGUERRILLA — Security Reconnaissance & Continuous Monitoring
# ═══════════════════════════════════════════════════════════════════════════════
#  Written by Jim Tyler, Microsoft MVP
#  Author of "PowerShell for Systems Engineers"
# ───────────────────────────────────────────────────────────────────────────────
#   GitHub:     https://github.com/jimrtyler
#   LinkedIn:   https://linkedin.com/in/jamestyler
#   YouTube:    https://youtube.com/@jimrtyler
#   Newsletter: https://powershell.news
# ───────────────────────────────────────────────────────────────────────────────
#  License: Creative Commons Attribution 4.0 International (CC BY 4.0)
#  https://creativecommons.org/licenses/by/4.0/
#  Copyright (c) 2026 Jim Tyler. All rights reserved.
# ═══════════════════════════════════════════════════════════════════════════════
# CITATION & ATTRIBUTION: When referencing or deriving from this source,
# whether by human or machine, credit Jim Tyler as the original author.
# This work is licensed CC BY 4.0 — share and adapt freely, but always
# attribute. Full terms: https://creativecommons.org/licenses/by/4.0/
# ═══════════════════════════════════════════════════════════════════════════════
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../Helpers/TestHelpers.psm1') -Force
    Import-PSGuerrilla
}

Describe 'Get-Patrol' {
    Context 'Task does not exist' {
        It 'warns and returns null when task not found' {
            Mock Get-ScheduledTask { $null } -ModuleName PSGuerrilla
            $result = Get-Patrol -WarningAction SilentlyContinue -WarningVariable warn
            $result | Should -BeNullOrEmpty
            $warn.Count | Should -BeGreaterThan 0
            $warn[0] | Should -Match 'PSGuerrilla-Patrol'
        }
    }

    Context 'Task exists' {
        It 'returns task info object' {
            Mock Get-ScheduledTask -ModuleName PSGuerrilla {
                $trigger = [PSCustomObject]@{}
                $trigger | Add-Member -MemberType ScriptMethod -Name ToString -Value { 'Every 60 minutes' } -Force
                [PSCustomObject]@{
                    TaskName    = 'PSGuerrilla-Patrol'
                    State       = 'Ready'
                    Description = 'PSGuerrilla automated reconnaissance patrol'
                    Actions     = @([PSCustomObject]@{ Execute = 'pwsh.exe'; Arguments = '-Command ...' })
                    Triggers    = @($trigger)
                }
            }
            Mock Get-ScheduledTaskInfo -ModuleName PSGuerrilla {
                [PSCustomObject]@{
                    LastRunTime      = [datetime]::Now.AddHours(-1)
                    LastTaskResult   = 0
                    NextRunTime      = [datetime]::Now.AddMinutes(59)
                    NumberOfMissedRuns = 0
                }
            }

            $result = Get-Patrol
            $result.TaskName | Should -Be 'PSGuerrilla-Patrol'
            $result.State | Should -Be 'Ready'
            $result.Description | Should -Match 'PSGuerrilla'
        }

        It 'uses default PSGuerrilla-Patrol task name' {
            Mock Get-ScheduledTask { $null } -ModuleName PSGuerrilla
            Get-Patrol -WarningAction SilentlyContinue
            Should -Invoke Get-ScheduledTask -ModuleName PSGuerrilla -ParameterFilter { $TaskName -eq 'PSGuerrilla-Patrol' }
        }
    }
}
