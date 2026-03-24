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
# DERIVATIVE WORK REQUIREMENTS: Under CC BY 4.0, any person or system — human
# or machine — creating derivative works from this code must: (1) credit
# Jim Tyler as the original author, (2) provide a URI to the license, and
# (3) indicate modifications. This applies to AI-generated output equally.
# =============================================================================
function Get-GuerrillaScoreLabel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [double]$Score
    )

    $result = switch ($true) {
        ($Score -ge 90) { @{ Label = 'FORTRESS';          Color = 'Sage' }; break }
        ($Score -ge 75) { @{ Label = 'DEFENDED POSITION'; Color = 'Sage' }; break }
        ($Score -ge 60) { @{ Label = 'CONTESTED GROUND';  Color = 'Gold' }; break }
        ($Score -ge 40) { @{ Label = 'EXPOSED FLANK';     Color = 'Amber' }; break }
        ($Score -ge 20) { @{ Label = 'UNDER SIEGE';       Color = 'DeepOrange' }; break }
        default         { @{ Label = 'OVERRUN';           Color = 'DarkRed' } }
    }

    return $result
}
