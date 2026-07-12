# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-AuditScoreLabel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int]$Score
    )

    if ($Score -ge 90) { return 'Low Risk' }
    if ($Score -ge 75) { return 'Moderate Risk' }
    if ($Score -ge 60) { return 'Elevated Risk' }
    if ($Score -ge 40) { return 'High Risk' }
    if ($Score -ge 20) { return 'Severe Risk' }
    return 'Critical Risk'
}
