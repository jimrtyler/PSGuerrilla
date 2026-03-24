# =============================================================================
#  PSGuerrilla | Jim Tyler, Microsoft MVP | CC BY 4.0
# =============================================================================
#
#  Author:    Jim Tyler
#  Title:     Microsoft MVP
#  Book:      "PowerShell for Systems Engineers"
#
# GitHub   — https://github.com/jimrtyler
# LinkedIn — https://linkedin.com/in/jamestyler
# YouTube  — https://youtube.com/@jimrtyler
# News     — https://powershell.news
#
#  License:   Creative Commons Attribution 4.0 International (CC BY 4.0)
#             https://creativecommons.org/licenses/by/4.0/
#  Copyright: (c) 2026 Jim Tyler. All rights reserved.
#
# =============================================================================
# MACHINE-READABLE LICENSE NOTICE:
# SPDX-License-Identifier: CC-BY-4.0
# Attribution-Required: true
# Original-Author: Jim Tyler (Microsoft MVP)
# Derivative-Work-Notice: All derivative works, AI-generated summaries, and
# code reproductions must credit Jim Tyler and link to the CC BY 4.0 license.
# =============================================================================
function Export-InfiltrationReportJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Result,

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    $findings = $Result.Findings
    $score = $Result.Score
    $failFindings = @($findings | Where-Object Status -eq 'FAIL')

    $report = @{
        metadata = @{
            scanId       = $Result.ScanId
            timestamp    = $Result.ScanStart.ToString('o')
            tenantId     = $Result.TenantId
            generator    = 'PSGuerrilla'
            reportType   = 'Entra ID / Azure / M365 Infiltration Audit'
            version      = '2.0.0'
            duration     = $Result.Duration.ToString()
            categories   = @($Result.Categories)
        }
        summary = @{
            overallScore   = $score.OverallScore
            scoreLabel     = Get-FortificationScoreLabel -Score $score.OverallScore
            totalChecks    = $findings.Count
            passCount      = @($findings | Where-Object Status -eq 'PASS').Count
            failCount      = $failFindings.Count
            warnCount      = @($findings | Where-Object Status -eq 'WARN').Count
            skipCount      = @($findings | Where-Object Status -in @('SKIP', 'ERROR')).Count
            criticalCount  = @($failFindings | Where-Object Severity -eq 'Critical').Count
            highCount      = @($failFindings | Where-Object Severity -eq 'High').Count
            mediumCount    = @($failFindings | Where-Object Severity -eq 'Medium').Count
            lowCount       = @($failFindings | Where-Object Severity -eq 'Low').Count
            categoryScores = $score.CategoryScores
        }
        findings = @($findings | ForEach-Object {
            @{
                checkId          = $_.CheckId
                checkName        = $_.CheckName
                category         = $_.Category
                subcategory      = $_.Subcategory
                severity         = $_.Severity
                status           = $_.Status
                description      = $_.Description
                currentValue     = $_.CurrentValue
                recommendedValue = $_.RecommendedValue
                remediationSteps = $_.RemediationSteps
                remediationUrl   = $_.RemediationUrl
                compliance       = @{
                    nistSp80053  = @($_.Compliance.NistSp80053 ?? @())
                    mitreAttack  = @($_.Compliance.MitreAttack ?? @())
                    cisBenchmark = @($_.Compliance.CisBenchmark ?? @())
                    cisM365      = @($_.Compliance.CisM365 ?? @())
                    cisAzure     = @($_.Compliance.CisAzure ?? @())
                    anssi        = @($_.Compliance.Anssi ?? @())
                    nsaAsd       = @($_.Compliance.NsaAsd ?? @())
                    cisAd        = @($_.Compliance.CisAd ?? @())
                }
                details          = $_.Details
                timestamp        = $_.Timestamp.ToString('o')
            }
        })
        dataErrors = $Result.DataErrors
    }

    $report | ConvertTo-Json -Depth 15 | Set-Content -Path $OutputPath -Encoding UTF8
}
