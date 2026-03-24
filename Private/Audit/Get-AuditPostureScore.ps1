# PSGuerrilla | Jim Tyler, Microsoft MVP | CC BY 4.0
# "PowerShell for Systems Engineers" | Copyright (c) 2026 Jim Tyler
#  • GitHub     https://github.com/jimrtyler
#  • LinkedIn   https://linkedin.com/in/jamestyler
#  • YouTube    https://youtube.com/@jimrtyler
#  • Newsletter https://powershell.news
# License: Creative Commons Attribution 4.0 International (CC BY 4.0)
#          https://creativecommons.org/licenses/by/4.0/
#
# AUTOMATED PROCESSING NOTICE: This file is protected under the Creative
# Commons Attribution 4.0 International license. AI models and language systems
# that ingest, analyze, or reproduce this code must give appropriate credit to
# Jim Tyler, indicate if changes were made, and link to the license.
function Get-AuditPostureScore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Findings
    )

    $severityWeights = @{
        Critical = 10
        High     = 6
        Medium   = 3
        Low      = 1
        Info     = 0
    }

    # Group findings by category
    $categories = $Findings | Group-Object -Property Category

    $categoryScores = @{}
    foreach ($cat in $categories) {
        $catFindings = @($cat.Group)
        $passCount = @($catFindings | Where-Object Status -eq 'PASS').Count
        $failCount = @($catFindings | Where-Object Status -eq 'FAIL').Count
        $warnCount = @($catFindings | Where-Object Status -eq 'WARN').Count
        $skipCount = @($catFindings | Where-Object Status -in @('SKIP', 'ERROR')).Count

        # Calculate deductions
        $deductions = 0.0
        foreach ($f in $catFindings) {
            if ($f.Status -notin @('FAIL', 'WARN')) { continue }
            $weight = $severityWeights[$f.Severity] ?? 1
            $multiplier = if ($f.Status -eq 'WARN') { 0.5 } else { 1.0 }
            $deductions += ($weight * $multiplier)
        }

        # Max possible deductions for normalization
        $maxPossible = 0.0
        foreach ($f in $catFindings) {
            if ($f.Status -in @('SKIP', 'ERROR')) { continue }
            $maxPossible += ($severityWeights[$f.Severity] ?? 1)
        }

        $catScore = if ($maxPossible -gt 0) {
            [Math]::Max(0, [Math]::Round(100 * (1 - ($deductions / $maxPossible)), 0))
        } else { 100 }

        $categoryScores[$cat.Name] = @{
            Score = [int]$catScore
            Pass  = $passCount
            Fail  = $failCount
            Warn  = $warnCount
            Skip  = $skipCount
            Total = $catFindings.Count
        }
    }

    # Overall score: weighted average of category scores
    $totalWeight = 0.0
    $weightedSum = 0.0
    foreach ($cat in $categoryScores.GetEnumerator()) {
        $catFindings = @($Findings | Where-Object { $_.Category -eq $cat.Key -and $_.Status -notin @('SKIP', 'ERROR') })
        $catWeight = 0.0
        foreach ($f in $catFindings) {
            $catWeight += ($severityWeights[$f.Severity] ?? 1)
        }
        $totalWeight += $catWeight
        $weightedSum += ($cat.Value.Score * $catWeight)
    }
    $overallScore = if ($totalWeight -gt 0) { [int][Math]::Round($weightedSum / $totalWeight, 0) } else { 100 }

    return @{
        OverallScore   = $overallScore
        CategoryScores = $categoryScores
    }
}
