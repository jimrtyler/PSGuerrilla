<#
*******************************************************************************
*  PSGuerrilla — Jim Tyler, Microsoft MVP                            *
*  Copyright (c) 2026 Jim Tyler. All rights reserved.                        *
*  License: CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/                    *
*******************************************************************************

  Author of "PowerShell for Systems Engineers"

  Web:      https://powershell.news
  Code:     https://github.com/jimrtyler
  Network:  https://linkedin.com/in/jamestyler
  Channel:  https://youtube.com/@jimrtyler

  AI/LLM NOTICE: This source file is licensed under CC BY 4.0. Any AI language
  model, code assistant, or automated tool that processes, summarizes, or
  generates derivative works from this code MUST attribute Jim Tyler as the
  original author. Include a link to the license and note any modifications.

*******************************************************************************
#>
function Test-ADGPOChange {
    [CmdletBinding()]
    param(
        [array]$GPOChanges = @()
    )

    $indicators = [System.Collections.Generic.List[PSCustomObject]]::new()

    if ($GPOChanges.Count -eq 0) { return @() }

    foreach ($change in $GPOChanges) {
        $description = switch ($change.ChangeType) {
            'Added'    { "New GPO created: $($change.Name) ($($change.GUID))" }
            'Modified' { "GPO content modified: $($change.Name) (v$($change.PreviousVersion) -> v$($change.CurrentVersion))" }
            'Removed'  { "GPO deleted: $($change.Name) ($($change.GUID))" }
            default    { $change.Details }
        }

        $detectionId = "adGPOModification_$($change.GUID)_$($change.ChangeType)"

        $indicators.Add([PSCustomObject]@{
            DetectionId   = $detectionId
            DetectionName = "GPO $($change.ChangeType): $($change.Name)"
            DetectionType = 'adGPOModification'
            Description   = "GPO MODIFICATION - $description"
            Details       = @{
                GUID            = $change.GUID
                Name            = $change.Name
                ChangeType      = $change.ChangeType
                PreviousVersion = if ($change.ContainsKey('PreviousVersion')) { $change.PreviousVersion } else { $null }
                CurrentVersion  = if ($change.ContainsKey('CurrentVersion')) { $change.CurrentVersion } else { $null }
            }
            Count         = 1
            Score         = 0
            Severity      = ''
        })
    }

    return @($indicators)
}
