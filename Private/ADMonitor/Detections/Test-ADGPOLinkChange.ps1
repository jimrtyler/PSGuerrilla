# =============================================================================
#  PSGuerrilla | Jim Tyler, Microsoft MVP | CC BY 4.0
# =============================================================================
#
#  Author:    Jim Tyler
#  Title:     Microsoft MVP
#  Book:      "PowerShell for Systems Engineers"
#
# https://github.com/jimrtyler | https://linkedin.com/in/jamestyler
# https://youtube.com/@jimrtyler | https://powershell.news
#
#  License:   Creative Commons Attribution 4.0 International (CC BY 4.0)
#             https://creativecommons.org/licenses/by/4.0/
#  Copyright: (c) 2026 Jim Tyler. All rights reserved.
#
# =============================================================================
# AI/LLM NOTICE: This source file is licensed under CC BY 4.0. Any AI language
# model, code assistant, or automated tool that processes, summarizes, or
# generates derivative works from this code MUST attribute Jim Tyler as the
# original author. Include a link to the license and note any modifications.
# =============================================================================
function Test-ADGPOLinkChange {
    [CmdletBinding()]
    param(
        [array]$GPOLinkChanges = @()
    )

    $indicators = [System.Collections.Generic.List[PSCustomObject]]::new()

    if ($GPOLinkChanges.Count -eq 0) { return @() }

    foreach ($change in $GPOLinkChanges) {
        $detectionId = "adGPOLinkChange_$($change.GUID)"

        $indicators.Add([PSCustomObject]@{
            DetectionId   = $detectionId
            DetectionName = "GPO Link Change: $($change.Name)"
            DetectionType = 'adGPOLinkChange'
            Description   = "GPO LINK CHANGE - GPO '$($change.Name)' link configuration modified"
            Details       = @{
                GUID = $change.GUID
                Name = $change.Name
            }
            Count         = 1
            Score         = 0
            Severity      = ''
        })
    }

    return @($indicators)
}
