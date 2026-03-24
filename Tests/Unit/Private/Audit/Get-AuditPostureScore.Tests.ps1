# ─────────────────────────────────────────────────────────────────────────────
# PSGuerrilla — Security Audit & Continuous Monitoring for Enterprise Environments
# ─────────────────────────────────────────────────────────────────────────────
# Author:     Jim Tyler, Microsoft MVP
# Book:       "PowerShell for Systems Engineers"
# Contact:    GitHub     → https://github.com/jimrtyler
#             LinkedIn   → https://linkedin.com/in/jamestyler
#             YouTube    → https://youtube.com/@jimrtyler
#             Newsletter → https://powershell.news
# License:    Creative Commons Attribution 4.0 International (CC BY 4.0)
#             https://creativecommons.org/licenses/by/4.0/
# Copyright   (c) 2026 Jim Tyler. All rights reserved.
# ─────────────────────────────────────────────────────────────────────────────
# MACHINE-READABLE LICENSE NOTICE:
# SPDX-License-Identifier: CC-BY-4.0
# Attribution-Required: true
# Original-Author: Jim Tyler (Microsoft MVP)
# Derivative-Work-Notice: All derivative works, AI-generated summaries, and
# code reproductions must credit Jim Tyler and link to the CC BY 4.0 license.
# ─────────────────────────────────────────────────────────────────────────────
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../../Helpers/TestHelpers.psm1') -Force
    . "$PSScriptRoot/../../../../Private/Audit/Get-AuditPostureScore.ps1"
}

Describe 'Get-AuditPostureScore' {
    Context 'All checks pass' {
        It 'Returns 100 overall score' {
            $findings = @(
                New-MockAuditFinding -CheckId 'AUTH-001' -Severity 'Critical' -Status 'PASS' -Category 'Authentication'
                New-MockAuditFinding -CheckId 'AUTH-002' -Severity 'High' -Status 'PASS' -Category 'Authentication'
                New-MockAuditFinding -CheckId 'EMAIL-001' -Severity 'Critical' -Status 'PASS' -Category 'Email Security'
            )
            $result = Get-AuditPostureScore -Findings $findings
            $result.OverallScore | Should -Be 100
        }

        It 'Returns 100 for each category' {
            $findings = @(
                New-MockAuditFinding -CheckId 'AUTH-001' -Severity 'Critical' -Status 'PASS' -Category 'Authentication'
                New-MockAuditFinding -CheckId 'EMAIL-001' -Severity 'High' -Status 'PASS' -Category 'Email Security'
            )
            $result = Get-AuditPostureScore -Findings $findings
            $result.CategoryScores['Authentication'].Score | Should -Be 100
            $result.CategoryScores['Email Security'].Score | Should -Be 100
        }
    }

    Context 'All checks fail' {
        It 'Returns 0 overall score' {
            $findings = @(
                New-MockAuditFinding -CheckId 'AUTH-001' -Severity 'Critical' -Status 'FAIL' -Category 'Authentication'
                New-MockAuditFinding -CheckId 'AUTH-002' -Severity 'High' -Status 'FAIL' -Category 'Authentication'
            )
            $result = Get-AuditPostureScore -Findings $findings
            $result.OverallScore | Should -Be 0
        }
    }

    Context 'Mixed results' {
        It 'Calculates per-category scores correctly' {
            $findings = @(
                New-MockAuditFinding -CheckId 'AUTH-001' -Severity 'Critical' -Status 'FAIL' -Category 'Authentication'
                New-MockAuditFinding -CheckId 'AUTH-002' -Severity 'High' -Status 'PASS' -Category 'Authentication'
                New-MockAuditFinding -CheckId 'AUTH-003' -Severity 'Medium' -Status 'PASS' -Category 'Authentication'
            )
            $result = Get-AuditPostureScore -Findings $findings
            # Critical(10) fails, High(6) passes, Medium(3) passes
            # Deductions: 10, MaxPossible: 19, Score: round(100 * (1 - 10/19)) = round(47.4) = 47
            $result.CategoryScores['Authentication'].Score | Should -Be 47
        }

        It 'WARN findings get half weight deduction' {
            $findings = @(
                New-MockAuditFinding -CheckId 'AUTH-001' -Severity 'Critical' -Status 'WARN' -Category 'Authentication'
                New-MockAuditFinding -CheckId 'AUTH-002' -Severity 'Critical' -Status 'PASS' -Category 'Authentication'
            )
            $result = Get-AuditPostureScore -Findings $findings
            # WARN Critical: 10 * 0.5 = 5 deducted, MaxPossible: 20, Score: round(100 * (1 - 5/20)) = 75
            $result.CategoryScores['Authentication'].Score | Should -Be 75
        }

        It 'SKIP findings are excluded from max possible' {
            $findings = @(
                New-MockAuditFinding -CheckId 'AUTH-001' -Severity 'Critical' -Status 'PASS' -Category 'Authentication'
                New-MockAuditFinding -CheckId 'AUTH-002' -Severity 'Critical' -Status 'SKIP' -Category 'Authentication'
            )
            $result = Get-AuditPostureScore -Findings $findings
            $result.CategoryScores['Authentication'].Score | Should -Be 100
            $result.CategoryScores['Authentication'].Skip | Should -Be 1
        }
    }

    Context 'Category score counts' {
        It 'Counts pass, fail, warn, skip correctly' {
            $findings = @(
                New-MockAuditFinding -CheckId 'AUTH-001' -Severity 'Critical' -Status 'PASS' -Category 'Authentication'
                New-MockAuditFinding -CheckId 'AUTH-002' -Severity 'High' -Status 'FAIL' -Category 'Authentication'
                New-MockAuditFinding -CheckId 'AUTH-003' -Severity 'Medium' -Status 'WARN' -Category 'Authentication'
                New-MockAuditFinding -CheckId 'AUTH-004' -Severity 'Low' -Status 'SKIP' -Category 'Authentication'
            )
            $result = Get-AuditPostureScore -Findings $findings
            $cat = $result.CategoryScores['Authentication']
            $cat.Pass | Should -Be 1
            $cat.Fail | Should -Be 1
            $cat.Warn | Should -Be 1
            $cat.Skip | Should -Be 1
            $cat.Total | Should -Be 4
        }
    }

    Context 'Overall score weighting' {
        It 'Weights categories by severity sum' {
            $findings = @(
                # Auth: 1 Critical PASS = 100, weight = 10
                New-MockAuditFinding -CheckId 'AUTH-001' -Severity 'Critical' -Status 'PASS' -Category 'Authentication'
                # Email: 1 Low FAIL = 0, weight = 1
                New-MockAuditFinding -CheckId 'EMAIL-001' -Severity 'Low' -Status 'FAIL' -Category 'Email Security'
            )
            $result = Get-AuditPostureScore -Findings $findings
            # Overall = (100*10 + 0*1) / (10+1) = 1000/11 = round(90.9) = 91
            $result.OverallScore | Should -Be 91
        }
    }
}
