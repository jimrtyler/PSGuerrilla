<#
*******************************************************************************
*  PSGuerrilla — Jim Tyler, Microsoft MVP                            *
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
    Import-PSGuerrilla
}

Describe 'New-AuditFinding' {
    BeforeEach {
        $checkDef = New-MockCheckDefinition
    }

    Context 'Creates finding with correct structure' {
        It 'Returns a PSGuerrilla.AuditFinding object' {
            $finding = New-AuditFinding -CheckDefinition $checkDef -Status 'FAIL' -CurrentValue 'Not enforced'
            $finding.PSObject.TypeNames | Should -Contain 'PSGuerrilla.AuditFinding'
        }

        It 'Populates all fields from check definition' {
            $finding = New-AuditFinding -CheckDefinition $checkDef -Status 'FAIL' -CurrentValue 'Not enforced'
            $finding.CheckId | Should -Be 'AUTH-001'
            $finding.CheckName | Should -Be '2SV Enforcement'
            $finding.Category | Should -Be 'Authentication'
            $finding.Severity | Should -Be 'Critical'
            $finding.Description | Should -Be 'Two-step verification should be enforced'
            $finding.RecommendedValue | Should -Be 'Enforced'
            $finding.RemediationUrl | Should -Be 'https://admin.google.com/ac/security/2sv'
        }

        It 'Sets Status and CurrentValue from parameters' {
            $finding = New-AuditFinding -CheckDefinition $checkDef -Status 'PASS' -CurrentValue 'Enforced'
            $finding.Status | Should -Be 'PASS'
            $finding.CurrentValue | Should -Be 'Enforced'
        }

        It 'Defaults OrgUnitPath to /' {
            $finding = New-AuditFinding -CheckDefinition $checkDef -Status 'FAIL'
            $finding.OrgUnitPath | Should -Be '/'
        }

        It 'Accepts custom OrgUnitPath' {
            $finding = New-AuditFinding -CheckDefinition $checkDef -Status 'FAIL' -OrgUnitPath '/Engineering'
            $finding.OrgUnitPath | Should -Be '/Engineering'
        }

        It 'Includes compliance mappings' {
            $finding = New-AuditFinding -CheckDefinition $checkDef -Status 'FAIL'
            $finding.Compliance.NistSp80053 | Should -Contain 'IA-2(1)'
            $finding.Compliance.MitreAttack | Should -Contain 'T1078'
            $finding.Compliance.CisBenchmark | Should -Contain '1.1'
        }

        It 'Includes Details hashtable' {
            $details = @{ EnrolledCount = 40; TotalActive = 50 }
            $finding = New-AuditFinding -CheckDefinition $checkDef -Status 'FAIL' -Details $details
            $finding.Details.EnrolledCount | Should -Be 40
            $finding.Details.TotalActive | Should -Be 50
        }

        It 'Sets Timestamp to current UTC time' {
            $before = [datetime]::UtcNow
            $finding = New-AuditFinding -CheckDefinition $checkDef -Status 'PASS'
            $after = [datetime]::UtcNow
            $finding.Timestamp | Should -BeGreaterOrEqual $before
            $finding.Timestamp | Should -BeLessOrEqual $after
        }
    }

    Context 'Validates Status parameter' {
        It 'Accepts PASS' {
            { New-AuditFinding -CheckDefinition $checkDef -Status 'PASS' } | Should -Not -Throw
        }
        It 'Accepts FAIL' {
            { New-AuditFinding -CheckDefinition $checkDef -Status 'FAIL' } | Should -Not -Throw
        }
        It 'Accepts WARN' {
            { New-AuditFinding -CheckDefinition $checkDef -Status 'WARN' } | Should -Not -Throw
        }
        It 'Accepts ERROR' {
            { New-AuditFinding -CheckDefinition $checkDef -Status 'ERROR' } | Should -Not -Throw
        }
        It 'Accepts SKIP' {
            { New-AuditFinding -CheckDefinition $checkDef -Status 'SKIP' } | Should -Not -Throw
        }
        It 'Rejects invalid status' {
            { New-AuditFinding -CheckDefinition $checkDef -Status 'INVALID' } | Should -Throw
        }
    }
}
