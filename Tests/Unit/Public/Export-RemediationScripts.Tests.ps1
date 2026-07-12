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
    Import-Module (Join-Path $PSScriptRoot '../../Helpers/TestHelpers.psm1') -Force
    Import-Guerrilla

    function Test-ScriptParses {
        param([string]$Path)
        $tokens = $null
        $parseErrors = $null
        [void][System.Management.Automation.Language.Parser]::ParseInput(
            (Get-Content $Path -Raw), [ref]$tokens, [ref]$parseErrors)
        return @($parseErrors)
    }
}

Describe 'Export-RemediationScripts' {
    Context 'Injection resistance' {
        It 'neutralizes quote and CRLF payloads so the generated script parses cleanly' {
            $finding = New-MockAuditFinding -CheckId 'AUTH-001' -Status 'FAIL' `
                -CheckName "O'Brien policy`r`nInvoke-Expression 'pwned'" `
                -RemediationSteps "x`r`nRemove-Item -Recurse /" `
                -RecommendedValue "val`nStart-Process calc"

            $outDir = Join-Path $TestDrive 'remediation-injection'
            $result = Export-RemediationScripts -Findings @($finding) -OutputDirectory $outDir -Force
            $result.Success | Should -BeTrue
            $result.ScriptCount | Should -Be 1

            $scriptPath = $result.Scripts[0]
            $parseErrors = Test-ScriptParses -Path $scriptPath
            $parseErrors.Count | Should -Be 0

            # None of the injected commands may survive at the start of a line.
            $lines = Get-Content $scriptPath
            @($lines | Where-Object { $_.TrimStart() -like 'Remove-Item*' }).Count | Should -Be 0
            @($lines | Where-Object { $_.TrimStart() -like 'Invoke-Expression*' }).Count | Should -Be 0
            @($lines | Where-Object { $_.TrimStart() -like 'Start-Process*' }).Count | Should -Be 0
        }

        It 'neutralizes a hostile CheckId interpolated into single-quoted strings' {
            $finding = New-MockAuditFinding -Status 'FAIL'
            # CheckId lands in a single-quoted Write-Host string; an unescaped quote
            # would break out of it.
            $finding.CheckId = "AUTH-001' ; Remove-Item -Recurse / ; '"

            $outDir = Join-Path $TestDrive 'remediation-checkid'
            $result = Export-RemediationScripts -Findings @($finding) -OutputDirectory $outDir -Force
            $result.ScriptCount | Should -Be 1

            $parseErrors = Test-ScriptParses -Path $result.Scripts[0]
            $parseErrors.Count | Should -Be 0

            $lines = Get-Content $result.Scripts[0]
            @($lines | Where-Object { $_.TrimStart() -like 'Remove-Item*' }).Count | Should -Be 0
        }
    }

    Context 'Catalog-wide syntax validation' {
        It 'generates parseable scripts from the real check catalog' {
            $catalogDir = Join-Path $PSScriptRoot '../../../source/Data/AuditChecks'
            $findings = foreach ($file in (Get-ChildItem $catalogDir -Filter '*.json')) {
                $category = Get-Content $file.FullName -Raw | ConvertFrom-Json
                foreach ($check in $category.checks) {
                    [PSCustomObject]@{
                        CheckId          = $check.id
                        CheckName        = $check.name
                        Severity         = $check.severity
                        Status           = 'FAIL'
                        RemediationSteps = $check.remediationSteps
                        RecommendedValue = $check.recommendedValue
                    }
                }
            }
            $findings.Count | Should -BeGreaterThan 0

            $outDir = Join-Path $TestDrive 'remediation-catalog'
            $result = Export-RemediationScripts -Findings @($findings) -OutputDirectory $outDir -Force
            $result.Success | Should -BeTrue
            $result.ScriptCount | Should -BeGreaterThan 0

            foreach ($scriptPath in $result.Scripts) {
                $parseErrors = Test-ScriptParses -Path $scriptPath
                if ($parseErrors.Count -gt 0) {
                    # Surface which generated file failed and why.
                    $parseErrors | Should -BeNullOrEmpty -Because "generated script $scriptPath must parse cleanly ($($parseErrors[0].Message))"
                }
                $parseErrors.Count | Should -Be 0
            }
        }
    }
}
