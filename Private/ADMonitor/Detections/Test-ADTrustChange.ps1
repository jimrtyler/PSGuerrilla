# =============================================================================
#  PSGuerrilla | Jim Tyler, Microsoft MVP | CC BY 4.0
# =============================================================================
#
#  Author:    Jim Tyler
#  Title:     Microsoft MVP
#  Book:      "PowerShell for Systems Engineers"
#
# Contact:    GitHub     → https://github.com/jimrtyler
#             LinkedIn   → https://linkedin.com/in/jamestyler
#             YouTube    → https://youtube.com/@jimrtyler
#             Newsletter → https://powershell.news
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
function Test-ADTrustChange {
    [CmdletBinding()]
    param(
        [array]$TrustChanges = @()
    )

    $indicators = [System.Collections.Generic.List[PSCustomObject]]::new()

    if ($TrustChanges.Count -eq 0) { return @() }

    foreach ($change in $TrustChanges) {
        $description = switch ($change.ChangeType) {
            'Added'    { "New trust relationship: $($change.Name) ($($change.Direction), $($change.Type))" }
            'Modified' { "Trust modified: $($change.Details)" }
            'Removed'  { "Trust removed: $($change.Name)" }
            default    { $change.Details }
        }

        # New trusts are especially concerning
        $detectionType = if ($change.ChangeType -eq 'Added') { 'adNewTrust' } else { 'adTrustModified' }

        $detectionId = "adTrustChange_$($change.Name -replace '\.', '_')_$($change.ChangeType)"

        $indicators.Add([PSCustomObject]@{
            DetectionId   = $detectionId
            DetectionName = "Trust $($change.ChangeType): $($change.Name)"
            DetectionType = $detectionType
            Description   = "TRUST CHANGE - $description"
            Details       = @{
                Name       = $change.Name
                ChangeType = $change.ChangeType
                Direction  = $change.Direction
                Type       = $change.Type
            }
            Count         = 1
            Score         = 0
            Severity      = ''
        })
    }

    return @($indicators)
}
