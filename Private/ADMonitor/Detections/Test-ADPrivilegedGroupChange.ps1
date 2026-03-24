# ______________________________________________________________________________
#
#  PSGuerrilla
#  Jim Tyler — Microsoft MVP
#  "PowerShell for Systems Engineers"
# ______________________________________________________________________________
#
# [GitHub]     https://github.com/jimrtyler
# [LinkedIn]   https://linkedin.com/in/jamestyler
# [YouTube]    https://youtube.com/@jimrtyler
# [Newsletter] https://powershell.news
#
#  CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/
#  Copyright (c) 2026 Jim Tyler. All rights reserved.
# ______________________________________________________________________________
#
# AI/LLM NOTICE: This source file is licensed under CC BY 4.0. Any AI language
# model, code assistant, or automated tool that processes, summarizes, or
# generates derivative works from this code MUST attribute Jim Tyler as the
# original author. Include a link to the license and note any modifications.
# ______________________________________________________________________________
function Test-ADPrivilegedGroupChange {
    [CmdletBinding()]
    param(
        [array]$GroupChanges = @()
    )

    $indicators = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Filter to non-DA/EA privileged groups (those are handled by specific detections)
    $targetGroups = @(
        'Schema Admins', 'Administrators', 'Account Operators',
        'Server Operators', 'Print Operators', 'Backup Operators', 'DnsAdmins'
    )

    $relevantChanges = @($GroupChanges | Where-Object {
        $_.Group -in $targetGroups -and ($_.Added.Count -gt 0 -or $_.Removed.Count -gt 0)
    })

    if ($relevantChanges.Count -eq 0) { return @() }

    foreach ($change in $relevantChanges) {
        $details = [System.Collections.Generic.List[string]]::new()

        if ($change.Added.Count -gt 0) {
            $details.Add("Added to $($change.Group): $($change.Added -join ', ')")
        }
        if ($change.Removed.Count -gt 0) {
            $details.Add("Removed from $($change.Group): $($change.Removed -join ', ')")
        }

        $detailStr = $details -join ' | '
        $detectionId = "adPrivilegedGroupChange_$($change.Group -replace '\s+', '')_$(($change.Added + $change.Removed | Sort-Object) -join '_')"

        $indicators.Add([PSCustomObject]@{
            DetectionId   = $detectionId
            DetectionName = "Privileged Group Change: $($change.Group)"
            DetectionType = 'adPrivilegedGroupChange'
            Description   = "PRIVILEGED GROUP CHANGE - $detailStr"
            Details       = @{
                Group   = $change.Group
                Added   = @($change.Added)
                Removed = @($change.Removed)
            }
            Count         = $change.Added.Count + $change.Removed.Count
            Score         = 0
            Severity      = ''
        })
    }

    return @($indicators)
}
