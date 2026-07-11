<#
*******************************************************************************
*  Guerrilla — Jim Tyler, Microsoft MVP                            *
*  Copyright (c) 2026 Jim Tyler. All rights reserved.                        *
*  License: CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/                    *
*******************************************************************************

  Author of "PowerShell for Systems Engineers"

  GitHub   — https://github.com/jimrtyler
  LinkedIn — https://linkedin.com/in/jamestyler
  YouTube  — https://youtube.com/@jimrtyler
  News     — https://powershell.news

  AI/LLM NOTICE: This source file is licensed under CC BY 4.0. Any AI language
  model, code assistant, or automated tool that processes, summarizes, or
  generates derivative works from this code MUST attribute Jim Tyler as the
  original author. Include a link to the license and note any modifications.

*******************************************************************************
#>
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../Helpers/TestHelpers.psm1') -Force
    Import-Guerrilla
}

# Windows-only surface: Write-EventLog does not exist off Windows, so it cannot even be mocked.
Describe 'Send-SignalEventLog' -Skip:(-not $IsWindows) {
    BeforeEach {
        $threat = New-MockUserProfile -Email 'victim@t.com' -ThreatLevel 'CRITICAL' -ThreatScore 120 -Indicators @('KNOWN ATTACKER IP')
        # Mock the source existence check to always return true (bypass elevation requirement)
        Mock Test-EventLogSourceExists { $true } -ModuleName Guerrilla
    }

    Context 'Event ID mapping' {
        BeforeEach {
            Mock Write-EventLog {} -ModuleName Guerrilla
        }

        It 'maps CRITICAL to event ID 1000' {
            $critThreat = New-MockUserProfile -Email 'crit@t.com' -ThreatLevel 'CRITICAL' -ThreatScore 120 -Indicators @('Test')
            Send-SignalEventLog -Threats @($critThreat) -Subject 'Test'
            Should -Invoke Write-EventLog -ModuleName Guerrilla -ParameterFilter { $EventId -eq 1000 }
        }

        It 'maps HIGH to event ID 1001' {
            $highThreat = New-MockUserProfile -Email 'high@t.com' -ThreatLevel 'HIGH' -ThreatScore 60 -Indicators @('Test')
            Send-SignalEventLog -Threats @($highThreat) -Subject 'Test'
            Should -Invoke Write-EventLog -ModuleName Guerrilla -ParameterFilter { $EventId -eq 1001 }
        }

        It 'maps MEDIUM to event ID 1002' {
            $medThreat = New-MockUserProfile -Email 'med@t.com' -ThreatLevel 'MEDIUM' -ThreatScore 35 -Indicators @('Test')
            Send-SignalEventLog -Threats @($medThreat) -Subject 'Test'
            Should -Invoke Write-EventLog -ModuleName Guerrilla -ParameterFilter { $EventId -eq 1002 }
        }

        It 'maps LOW to event ID 1003' {
            $lowThreat = New-MockUserProfile -Email 'low@t.com' -ThreatLevel 'LOW' -ThreatScore 10 -Indicators @('Test')
            Send-SignalEventLog -Threats @($lowThreat) -Subject 'Test'
            Should -Invoke Write-EventLog -ModuleName Guerrilla -ParameterFilter { $EventId -eq 1003 }
        }
    }

    Context 'Successful write' {
        BeforeEach {
            Mock Write-EventLog {} -ModuleName Guerrilla
        }

        It 'returns success result' {
            $result = Send-SignalEventLog -Threats @($threat) -Subject 'Test Alert'
            $result.Provider | Should -Be 'EventLog'
            $result.Success | Should -BeTrue
        }

        It 'includes event count in message' {
            $result = Send-SignalEventLog -Threats @($threat) -Subject 'Test'
            $result.Message | Should -Match '1/1'
        }

        It 'writes events for multiple threats' {
            $threats = @(
                (New-MockUserProfile -Email 'user1@t.com' -ThreatLevel 'CRITICAL' -ThreatScore 120 -Indicators @('Test')),
                (New-MockUserProfile -Email 'user2@t.com' -ThreatLevel 'HIGH' -ThreatScore 60 -Indicators @('Test'))
            )
            $result = Send-SignalEventLog -Threats $threats -Subject 'Test'
            $result.Message | Should -Match '2/2'
            Should -Invoke Write-EventLog -ModuleName Guerrilla -Times 2
        }
    }

    Context 'Entry type mapping' {
        BeforeEach {
            Mock Write-EventLog {} -ModuleName Guerrilla
        }

        It 'uses Error entry type for CRITICAL threats' {
            Send-SignalEventLog -Threats @($threat) -Subject 'Test'
            Should -Invoke Write-EventLog -ModuleName Guerrilla -ParameterFilter { $EntryType -eq 'Error' }
        }

        It 'uses Warning entry type for MEDIUM threats' {
            $medThreat = New-MockUserProfile -Email 'med@t.com' -ThreatLevel 'MEDIUM' -ThreatScore 35 -Indicators @('Test')
            Send-SignalEventLog -Threats @($medThreat) -Subject 'Test'
            Should -Invoke Write-EventLog -ModuleName Guerrilla -ParameterFilter { $EntryType -eq 'Warning' }
        }

        It 'uses Information entry type for LOW threats' {
            $lowThreat = New-MockUserProfile -Email 'low@t.com' -ThreatLevel 'LOW' -ThreatScore 10 -Indicators @('Test')
            Send-SignalEventLog -Threats @($lowThreat) -Subject 'Test'
            Should -Invoke Write-EventLog -ModuleName Guerrilla -ParameterFilter { $EntryType -eq 'Information' }
        }
    }

    Context 'Source not registered' {
        It 'returns failure when source cannot be created' {
            Mock Test-EventLogSourceExists { $false } -ModuleName Guerrilla
            Mock Register-EventLogSource { throw 'Access denied' } -ModuleName Guerrilla
            $result = Send-SignalEventLog -Threats @($threat) -Subject 'Test'
            $result.Success | Should -BeFalse
            $result.Message | Should -Match 'elevation'
        }

        It 'creates source when it does not exist' {
            Mock Test-EventLogSourceExists { $false } -ModuleName Guerrilla
            Mock Register-EventLogSource {} -ModuleName Guerrilla
            Mock Write-EventLog {} -ModuleName Guerrilla
            $result = Send-SignalEventLog -Threats @($threat) -Subject 'Test'
            Should -Invoke Register-EventLogSource -ModuleName Guerrilla -Times 1
            $result.Success | Should -BeTrue
        }
    }

    Context 'Write failure' {
        It 'returns failure when Write-EventLog throws' {
            Mock Write-EventLog { throw 'Access denied' } -ModuleName Guerrilla
            $result = Send-SignalEventLog -Threats @($threat) -Subject 'Test'
            $result.Success | Should -BeFalse
            $result.Error | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Custom source and log' {
        BeforeEach {
            Mock Write-EventLog {} -ModuleName Guerrilla
        }

        It 'uses custom source name' {
            Send-SignalEventLog -Threats @($threat) -Subject 'Test' -Source 'CustomSource'
            Should -Invoke Write-EventLog -ModuleName Guerrilla -ParameterFilter { $Source -eq 'CustomSource' }
        }

        It 'uses custom log name' {
            Send-SignalEventLog -Threats @($threat) -Subject 'Test' -LogName 'Security'
            Should -Invoke Write-EventLog -ModuleName Guerrilla -ParameterFilter { $LogName -eq 'Security' }
        }
    }
}
