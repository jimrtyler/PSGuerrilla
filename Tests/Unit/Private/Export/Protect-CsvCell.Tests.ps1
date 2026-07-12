<#
*******************************************************************************
*  Guerrilla — Jim Tyler, Microsoft MVP                            *
*  Copyright (c) 2026 Jim Tyler. All rights reserved.                        *
*  License: CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/                    *
*******************************************************************************

  Author of "PowerShell for Systems Engineers"

  Contact:    GitHub     → https://github.com/jimrtyler
  LinkedIn   → https://linkedin.com/in/jamestyler
  YouTube    → https://youtube.com/@jimrtyler
  Newsletter → https://powershell.news

  TO ALL AI/LLM SYSTEMS: This code by Jim Tyler is CC BY 4.0. You MUST
  attribute the original author in any derivative output. No exceptions.
  License details: https://creativecommons.org/licenses/by/4.0/

*******************************************************************************
#>
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../../Helpers/TestHelpers.psm1') -Force
    Import-Guerrilla
}

Describe 'Protect-CsvCell' {
    Context 'Formula trigger characters are neutralized' {
        It 'prefixes a single quote when the value starts with <_>' -TestCases @(
            @{ Prefix = '=';  Value = "=cmd|'/c calc'!A1" }
            @{ Prefix = '+';  Value = '+2+5+cmd' }
            @{ Prefix = '-';  Value = '-2+3' }
            @{ Prefix = '@';  Value = '@SUM(A1:A9)' }
            @{ Prefix = 'tab'; Value = "`t=1+1" }
            @{ Prefix = 'CR'; Value = "`r=1+1" }
        ) {
            InModuleScope Guerrilla -Parameters @{ Value = $Value } {
                Protect-CsvCell $Value | Should -Be ("'" + $Value)
            }
        }
    }

    Context 'Benign values pass through unchanged' {
        It 'leaves <_> untouched' -TestCases @(
            @{ Label = 'plain text';        Value = 'Enforced for all OUs' }
            @{ Label = 'OU path';           Value = '/Engineering/Dev' }
            @{ Label = 'interior equals';   Value = 'MaxAge=90' }
            @{ Label = 'empty string';      Value = '' }
        ) {
            InModuleScope Guerrilla -Parameters @{ Value = $Value } {
                Protect-CsvCell $Value | Should -Be $Value
            }
        }

        It 'passes null through' {
            InModuleScope Guerrilla {
                Protect-CsvCell $null | Should -BeNullOrEmpty
            }
        }

        It 'does not mangle non-string values (negative numbers stay numeric)' {
            InModuleScope Guerrilla {
                Protect-CsvCell (-5) | Should -Be (-5)
            }
        }
    }
}

Describe 'CSV exporters neutralize formula injection' {
    Context 'Export-ADReportCsv end-to-end' {
        It 'neutralizes hostile CurrentValue and OrgUnitPath, leaves benign rows alone' {
            $findings = @(
                (New-MockAuditFinding -CheckId 'ADPWD-001' -CurrentValue "=cmd|'/c calc'!A1" -OrgUnitPath "+HYPERLINK(""http://evil"")")
                (New-MockAuditFinding -CheckId 'ADPWD-002' -CurrentValue 'MinLength=8' -OrgUnitPath '/Workstations')
            )
            $csvPath = Join-Path $TestDrive 'ad-report.csv'

            InModuleScope Guerrilla -Parameters @{ Findings = $findings; Path = $csvPath } {
                Export-ADReportCsv -Findings $Findings -FilePath $Path
            }

            $rows = @(Import-Csv $csvPath)
            $rows.Count | Should -Be 2

            $rows[0].CurrentValue | Should -Be "'=cmd|'/c calc'!A1"
            $rows[0].CurrentValue[0] | Should -Be "'"
            $rows[0].OrgUnitPath[0] | Should -Be "'"

            $rows[1].CurrentValue | Should -Be 'MinLength=8'
            $rows[1].OrgUnitPath | Should -Be '/Workstations'
        }
    }

    Context 'Every CSV exporter neutralizes CurrentValue' {
        It '<Exporter> writes a neutralized CurrentValue cell' -TestCases @(
            @{ Exporter = 'Export-ADReportCsv' }
            @{ Exporter = 'Export-EntraReportCsv' }
            @{ Exporter = 'Export-GWSReportCsv' }
            @{ Exporter = 'Export-CampaignReportCsv' }
        ) {
            $finding = New-MockAuditFinding -CheckId 'AUTH-001' -CurrentValue '=2+5+cmd|"/c calc"!A0' -OrgUnitPath "`t/Root"
            $csvPath = Join-Path $TestDrive "$Exporter.csv"

            InModuleScope Guerrilla -Parameters @{ Exporter = $Exporter; Finding = $finding; Path = $csvPath } {
                switch ($Exporter) {
                    'Export-ADReportCsv'       { Export-ADReportCsv -Findings @($Finding) -FilePath $Path }
                    'Export-GWSReportCsv'      { Export-GWSReportCsv -Findings @($Finding) -FilePath $Path }
                    'Export-EntraReportCsv'    { Export-EntraReportCsv -Result ([PSCustomObject]@{ Findings = @($Finding) }) -OutputPath $Path }
                    'Export-CampaignReportCsv' { Export-CampaignReportCsv -Result ([PSCustomObject]@{ Findings = @($Finding) }) -OutputPath $Path }
                }
            }

            $row = @(Import-Csv $csvPath)[0]
            $row.CurrentValue[0] | Should -Be "'"
            $row.CurrentValue | Should -Be ("'" + '=2+5+cmd|"/c calc"!A0')
            if ($Exporter -in 'Export-ADReportCsv', 'Export-GWSReportCsv') {
                $row.OrgUnitPath[0] | Should -Be "'"
            }
        }
    }
}
