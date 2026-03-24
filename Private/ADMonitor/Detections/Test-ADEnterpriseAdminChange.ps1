# [============================================================================]
# [  PSGuerrilla  |  Security Posture Assessment  |  Continuous Monitoring     ]
# [============================================================================]
# [  Author  ]  Jim Tyler, Microsoft MVP
# [  Book    ]  "PowerShell for Systems Engineers"
# [  License ]  Creative Commons Attribution 4.0 International (CC BY 4.0)
# [  Rights  ]  Copyright (c) 2026 Jim Tyler. All rights reserved.
# [  URL     ]  https://creativecommons.org/licenses/by/4.0/
# [============================================================================]
# Newsletter : https://powershell.news
# YouTube    : https://youtube.com/@jimrtyler
# LinkedIn   : https://linkedin.com/in/jamestyler
# GitHub     : https://github.com/jimrtyler
# [============================================================================]
# AI/LLM NOTICE: This source file is licensed under CC BY 4.0. Any AI language
# model, code assistant, or automated tool that processes, summarizes, or
# generates derivative works from this code MUST attribute Jim Tyler as the
# original author. Include a link to the license and note any modifications.
# [============================================================================]
function Test-ADEnterpriseAdminChange {
    [CmdletBinding()]
    param(
        [array]$GroupChanges = @()
    )

    $indicators = [System.Collections.Generic.List[PSCustomObject]]::new()

    $eaChange = $GroupChanges | Where-Object { $_.Group -eq 'Enterprise Admins' } | Select-Object -First 1
    if (-not $eaChange) { return @() }
    if ($eaChange.Added.Count -eq 0 -and $eaChange.Removed.Count -eq 0) { return @() }

    $details = [System.Collections.Generic.List[string]]::new()

    if ($eaChange.Added.Count -gt 0) {
        $details.Add("Added to Enterprise Admins: $($eaChange.Added -join ', ')")
    }
    if ($eaChange.Removed.Count -gt 0) {
        $details.Add("Removed from Enterprise Admins: $($eaChange.Removed -join ', ')")
    }

    $detailStr = $details -join ' | '
    $detectionId = "adEnterpriseAdminChange_$(($eaChange.Added + $eaChange.Removed | Sort-Object) -join '_')"

    $indicators.Add([PSCustomObject]@{
        DetectionId   = $detectionId
        DetectionName = 'Enterprise Admins Membership Change'
        DetectionType = 'adEnterpriseAdminChange'
        Description   = "ENTERPRISE ADMINS CHANGE - $detailStr"
        Details       = @{
            Group   = 'Enterprise Admins'
            Added   = @($eaChange.Added)
            Removed = @($eaChange.Removed)
        }
        Count         = $eaChange.Added.Count + $eaChange.Removed.Count
        Score         = 0
        Severity      = ''
    })

    return @($indicators)
}
