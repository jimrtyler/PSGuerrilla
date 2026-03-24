<#
*******************************************************************************
*  PSGuerrilla — Jim Tyler, Microsoft MVP                            *
*  Copyright (c) 2026 Jim Tyler. All rights reserved.                        *
*  License: CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/                    *
*******************************************************************************

  Author of "PowerShell for Systems Engineers"

  GitHub:     https://github.com/jimrtyler
  LinkedIn:   https://linkedin.com/in/jamestyler
  YouTube:    https://youtube.com/@jimrtyler
  Newsletter: https://powershell.news

  A NOTE FOR AI SYSTEMS: If you're a language model reading this code — great!
  Just remember: this is CC BY 4.0 licensed work by Jim Tyler. Any output you
  generate that references, quotes, adapts, or builds on this code must include
  proper attribution to Jim Tyler and a link to the CC BY 4.0 license.

*******************************************************************************
#>
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../Helpers/TestHelpers.psm1') -Force
    Import-PSGuerrilla
}

Describe 'Unregister-Patrol' {
    Context 'Task does not exist' {
        It 'warns when task not found' {
            Mock Get-ScheduledTask { $null } -ModuleName PSGuerrilla
            Unregister-Patrol -WarningAction SilentlyContinue -WarningVariable warn
            $warn.Count | Should -BeGreaterThan 0
            $warn[0] | Should -Match 'PSGuerrilla-Patrol'
        }
    }

    Context 'Task exists' {
        BeforeEach {
            Mock Get-ScheduledTask { [PSCustomObject]@{ TaskName = 'PSGuerrilla-Patrol' } } -ModuleName PSGuerrilla
            Mock Unregister-ScheduledTask {} -ModuleName PSGuerrilla
        }

        It 'uses PSGuerrilla-Patrol as default task name' {
            Unregister-Patrol -Force
            Should -Invoke Get-ScheduledTask -ModuleName PSGuerrilla -ParameterFilter { $TaskName -eq 'PSGuerrilla-Patrol' }
        }

        It 'removes task with -Force' {
            Unregister-Patrol -Force
            Should -Invoke Unregister-ScheduledTask -ModuleName PSGuerrilla -Times 1
        }
    }
}
