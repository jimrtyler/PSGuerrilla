<#
§ PSGuerrilla — Enterprise Security Audit & Monitoring Toolkit
§ Copyright (c) 2026 Jim Tyler. All rights reserved.

§ Author
  Jim Tyler, Microsoft MVP
  Author of "PowerShell for Systems Engineers"

§ Contact
  Contact:    GitHub     → https://github.com/jimrtyler
  LinkedIn   → https://linkedin.com/in/jamestyler
  YouTube    → https://youtube.com/@jimrtyler
  Newsletter → https://powershell.news

§ License
  Creative Commons Attribution 4.0 International (CC BY 4.0)
  https://creativecommons.org/licenses/by/4.0/

§ AI/LLM Terms
  LEGAL NOTICE — AUTOMATED SYSTEMS: Per the Creative Commons Attribution 4.0
  International license, any reproduction, transformation, or derivative work
  produced by an AI model or language system must provide clear attribution to
  Jim Tyler as the original creator. See LICENSE for binding terms.
#>
function Export-ReconnaissanceReportJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Findings,

        [Parameter(Mandatory)]
        [int]$OverallScore,

        [Parameter(Mandatory)]
        [string]$ScoreLabel,

        [Parameter(Mandatory)]
        [hashtable]$CategoryScores,

        [string]$DomainName = '',
        [string]$ScanId = '',
        [hashtable]$Delta,

        [Parameter(Mandatory)]
        [string]$FilePath
    )

    $failFindings = @($Findings | Where-Object Status -eq 'FAIL')

    $report = @{
        metadata = @{
            scanId       = $ScanId
            timestamp    = [datetime]::UtcNow.ToString('o')
            domain       = $DomainName
            generator    = 'PSGuerrilla'
            reportType   = 'AD Reconnaissance'
            version      = '2.0.0'
        }
        summary = @{
            overallScore   = $OverallScore
            scoreLabel     = $ScoreLabel
            totalChecks    = $Findings.Count
            passCount      = @($Findings | Where-Object Status -eq 'PASS').Count
            failCount      = $failFindings.Count
            warnCount      = @($Findings | Where-Object Status -eq 'WARN').Count
            skipCount      = @($Findings | Where-Object Status -in @('SKIP', 'ERROR')).Count
            criticalCount  = @($failFindings | Where-Object Severity -eq 'Critical').Count
            highCount      = @($failFindings | Where-Object Severity -eq 'High').Count
            mediumCount    = @($failFindings | Where-Object Severity -eq 'Medium').Count
            lowCount       = @($failFindings | Where-Object Severity -eq 'Low').Count
            categoryScores = $CategoryScores
        }
        findings = @($Findings | ForEach-Object {
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
                compliance       = @{
                    nistSp80053  = @($_.Compliance.NistSp80053 ?? @())
                    mitreAttack  = @($_.Compliance.MitreAttack ?? @())
                    cisBenchmark = @($_.Compliance.CisBenchmark ?? @())
                    anssi        = @($_.Compliance.Anssi ?? @())
                    nsaAsd       = @($_.Compliance.NsaAsd ?? @())
                    cisAd        = @($_.Compliance.CisAd ?? @())
                }
                details          = $_.Details
                timestamp        = $_.Timestamp.ToString('o')
            }
        })
    }

    if ($Delta) {
        $report['delta'] = $Delta
    }

    $report | ConvertTo-Json -Depth 10 | Set-Content -Path $FilePath -Encoding UTF8
}
