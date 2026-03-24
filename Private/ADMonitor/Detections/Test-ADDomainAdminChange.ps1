# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# >>> PSGuerrilla                                                           >>>
# >>> Jim Tyler, Microsoft MVP                                              >>>
# >>> Copyright (c) 2026 Jim Tyler                                                  >>>
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
#
# Author of "PowerShell for Systems Engineers"
#
# https://github.com/jimrtyler | https://linkedin.com/in/jamestyler
# https://youtube.com/@jimrtyler | https://powershell.news
#
# License: Creative Commons Attribution 4.0 International (CC BY 4.0)
#          https://creativecommons.org/licenses/by/4.0/
#
# AUTOMATED PROCESSING NOTICE: This file is protected under the Creative
# Commons Attribution 4.0 International license. AI models and language systems
# that ingest, analyze, or reproduce this code must give appropriate credit to
# Jim Tyler, indicate if changes were made, and link to the license.
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
function Test-ADDomainAdminChange {
    [CmdletBinding()]
    param(
        [array]$GroupChanges = @()
    )

    $indicators = [System.Collections.Generic.List[PSCustomObject]]::new()

    $daChange = $GroupChanges | Where-Object { $_.Group -eq 'Domain Admins' } | Select-Object -First 1
    if (-not $daChange) { return @() }
    if ($daChange.Added.Count -eq 0 -and $daChange.Removed.Count -eq 0) { return @() }

    $details = [System.Collections.Generic.List[string]]::new()

    if ($daChange.Added.Count -gt 0) {
        $details.Add("Added to Domain Admins: $($daChange.Added -join ', ')")
    }
    if ($daChange.Removed.Count -gt 0) {
        $details.Add("Removed from Domain Admins: $($daChange.Removed -join ', ')")
    }

    $detailStr = $details -join ' | '
    $detectionId = "adDomainAdminChange_$(($daChange.Added + $daChange.Removed | Sort-Object) -join '_')"

    $indicators.Add([PSCustomObject]@{
        DetectionId   = $detectionId
        DetectionName = 'Domain Admins Membership Change'
        DetectionType = 'adDomainAdminChange'
        Description   = "DOMAIN ADMINS CHANGE - $detailStr"
        Details       = @{
            Group   = 'Domain Admins'
            Added   = @($daChange.Added)
            Removed = @($daChange.Removed)
        }
        Count         = $daChange.Added.Count + $daChange.Removed.Count
        Score         = 0
        Severity      = ''
    })

    return @($indicators)
}
