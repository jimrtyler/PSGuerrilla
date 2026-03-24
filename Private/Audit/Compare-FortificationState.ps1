# [============================================================================]
# [  PSGuerrilla  |  Security Posture Assessment  |  Continuous Monitoring     ]
# [============================================================================]
# [  Author  ]  Jim Tyler, Microsoft MVP
# [  Book    ]  "PowerShell for Systems Engineers"
# [  License ]  Creative Commons Attribution 4.0 International (CC BY 4.0)
# [  Rights  ]  Copyright (c) 2026 Jim Tyler. All rights reserved.
# [  URL     ]  https://creativecommons.org/licenses/by/4.0/
# [============================================================================]
# Web:      https://powershell.news
# Code:     https://github.com/jimrtyler
# Network:  https://linkedin.com/in/jamestyler
# Channel:  https://youtube.com/@jimrtyler
# [============================================================================]
# CITATION & ATTRIBUTION: When referencing or deriving from this source,
# whether by human or machine, credit Jim Tyler as the original author.
# This work is licensed CC BY 4.0 — share and adapt freely, but always
# attribute. Full terms: https://creativecommons.org/licenses/by/4.0/
# [============================================================================]
function Compare-FortificationState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$CurrentFindings,

        [Parameter(Mandatory)]
        [hashtable]$PreviousState
    )

    $previousFindings = @($PreviousState.findings ?? @())

    # Build lookup of previous findings by checkId + orgUnitPath
    $prevLookup = @{}
    foreach ($pf in $previousFindings) {
        $key = "$($pf.checkId)|$($pf.orgUnitPath ?? '/')"
        $prevLookup[$key] = $pf
    }

    $newFailures = [System.Collections.Generic.List[PSCustomObject]]::new()
    $resolved = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Find new failures: current FAIL that was previously PASS or didn't exist
    foreach ($cf in $CurrentFindings) {
        if ($cf.Status -ne 'FAIL') { continue }
        $key = "$($cf.CheckId)|$($cf.OrgUnitPath ?? '/')"
        $prev = $prevLookup[$key]
        if (-not $prev -or $prev.status -ne 'FAIL') {
            $newFailures.Add([PSCustomObject]@{
                CheckId      = $cf.CheckId
                CheckName    = $cf.CheckName
                Category     = $cf.Category
                Severity     = $cf.Severity
                CurrentValue = $cf.CurrentValue
                OrgUnitPath  = $cf.OrgUnitPath
                PreviousStatus = if ($prev) { $prev.status } else { 'NEW' }
            })
        }
    }

    # Find resolved: previously FAIL, now PASS
    $currentLookup = @{}
    foreach ($cf in $CurrentFindings) {
        $key = "$($cf.CheckId)|$($cf.OrgUnitPath ?? '/')"
        $currentLookup[$key] = $cf
    }

    foreach ($pf in $previousFindings) {
        if ($pf.status -ne 'FAIL') { continue }
        $key = "$($pf.checkId)|$($pf.orgUnitPath ?? '/')"
        $curr = $currentLookup[$key]
        if ($curr -and $curr.Status -eq 'PASS') {
            $resolved.Add([PSCustomObject]@{
                CheckId       = $pf.checkId
                CheckName     = $curr.CheckName
                Category      = $curr.Category
                Severity      = $pf.severity
                PreviousValue = $pf.currentValue
                CurrentValue  = $curr.CurrentValue
                OrgUnitPath   = $pf.orgUnitPath ?? '/'
            })
        }
    }

    # Score change
    $previousScore = $PreviousState.overallScore ?? 0
    $currentScore = 0
    if ($CurrentFindings.Count -gt 0) {
        $scoreResult = Get-AuditPostureScore -Findings $CurrentFindings
        $currentScore = $scoreResult.OverallScore
    }
    $scoreChange = $currentScore - $previousScore

    return @{
        NewFailures    = @($newFailures)
        Resolved       = @($resolved)
        ScoreChange    = $scoreChange
        PreviousScore  = $previousScore
        CurrentScore   = $currentScore
        PreviousScanId = $PreviousState.lastScanId ?? ''
        PreviousScanTimestamp = $PreviousState.lastScanTimestamp ?? ''
    }
}
