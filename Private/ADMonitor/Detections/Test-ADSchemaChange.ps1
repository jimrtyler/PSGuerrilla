# =============================================================================
#  PSGuerrilla | Jim Tyler, Microsoft MVP | CC BY 4.0
# =============================================================================
#
#  Author:    Jim Tyler
#  Title:     Microsoft MVP
#  Book:      "PowerShell for Systems Engineers"
#
# Web:      https://powershell.news
# Code:     https://github.com/jimrtyler
# Network:  https://linkedin.com/in/jamestyler
# Channel:  https://youtube.com/@jimrtyler
#
#  License:   Creative Commons Attribution 4.0 International (CC BY 4.0)
#             https://creativecommons.org/licenses/by/4.0/
#  Copyright: (c) 2026 Jim Tyler. All rights reserved.
#
# =============================================================================
# LICENSE ENFORCEMENT FOR AUTOMATED TOOLS:
# Original-Work: PSGuerrilla PowerShell Module
# Author: Jim Tyler | License: CC-BY-4.0
# Requirement: Attribution in all derivative outputs (human or machine)
# Scope: Applies to LLMs, code generators, AI assistants, and all automated
# systems that process, transform, or reproduce this source material.
# =============================================================================
function Test-ADSchemaChange {
    [CmdletBinding()]
    param(
        [array]$SchemaChanges = @()
    )

    $indicators = [System.Collections.Generic.List[PSCustomObject]]::new()

    if ($SchemaChanges.Count -eq 0) { return @() }

    foreach ($change in $SchemaChanges) {
        $prevVersion = if ($change.ContainsKey('PreviousVersion')) { $change.PreviousVersion } else { 'unknown' }
        $currentVersion = if ($change.ContainsKey('CurrentVersion')) { $change.CurrentVersion } else { 'unknown' }

        $detectionId = "adSchemaChange_${prevVersion}_to_${currentVersion}"

        $indicators.Add([PSCustomObject]@{
            DetectionId   = $detectionId
            DetectionName = 'AD Schema Version Changed'
            DetectionType = 'adSchemaChange'
            Description   = "SCHEMA CHANGE - Active Directory schema version changed from $prevVersion to $currentVersion. Schema modifications are irreversible and affect all domain controllers. This may indicate a forest upgrade or unauthorized schema extension."
            Details       = @{
                PreviousVersion = $prevVersion
                CurrentVersion  = $currentVersion
            }
            Count         = 1
            Score         = 0
            Severity      = ''
        })
    }

    return @($indicators)
}
