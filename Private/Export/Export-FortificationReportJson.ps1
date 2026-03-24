# ═══════════════════════════════════════════════════════════════════════════════
#  PSGUERRILLA — Security Reconnaissance & Continuous Monitoring
# ═══════════════════════════════════════════════════════════════════════════════
#  Written by Jim Tyler, Microsoft MVP
#  Author of "PowerShell for Systems Engineers"
# ───────────────────────────────────────────────────────────────────────────────
#  • GitHub     https://github.com/jimrtyler
#  • LinkedIn   https://linkedin.com/in/jamestyler
#  • YouTube    https://youtube.com/@jimrtyler
#  • Newsletter https://powershell.news
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
function Export-FortificationReportJson {
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

        [string]$TenantDomain = '',
        [string]$ScanId = '',
        [hashtable]$Delta,
        [string]$FilePath
    )

    $report = @{
        scanId         = $ScanId
        timestamp      = [datetime]::UtcNow.ToString('o')
        tenantDomain   = $TenantDomain
        overallScore   = $OverallScore
        scoreLabel     = $ScoreLabel
        categoryScores = $CategoryScores
        summary        = @{
            totalChecks   = $Findings.Count
            passCount     = @($Findings | Where-Object Status -eq 'PASS').Count
            failCount     = @($Findings | Where-Object Status -eq 'FAIL').Count
            warnCount     = @($Findings | Where-Object Status -eq 'WARN').Count
            skipCount     = @($Findings | Where-Object Status -in @('SKIP', 'ERROR')).Count
            criticalCount = @($Findings | Where-Object { $_.Status -eq 'FAIL' -and $_.Severity -eq 'Critical' }).Count
            highCount     = @($Findings | Where-Object { $_.Status -eq 'FAIL' -and $_.Severity -eq 'High' }).Count
            mediumCount   = @($Findings | Where-Object { $_.Status -eq 'FAIL' -and $_.Severity -eq 'Medium' }).Count
            lowCount      = @($Findings | Where-Object { $_.Status -eq 'FAIL' -and $_.Severity -eq 'Low' }).Count
        }
        findings       = @($Findings | ForEach-Object {
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
                orgUnitPath      = $_.OrgUnitPath
                remediationUrl   = $_.RemediationUrl
                remediationSteps = $_.RemediationSteps
                compliance       = $_.Compliance
                details          = $_.Details
            }
        })
        delta          = $Delta
    }

    $json = $report | ConvertTo-Json -Depth 10

    if ($FilePath) {
        $json | Set-Content -Path $FilePath -Encoding UTF8
    }

    return $json
}
