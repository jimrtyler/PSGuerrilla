# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-GuerrillaScoreLabel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [double]$Score
    )

    $result = switch ($true) {
        ($Score -ge 90) { @{ Label = 'Low Risk';      Color = 'Sage' }; break }
        ($Score -ge 75) { @{ Label = 'Moderate Risk'; Color = 'Sage' }; break }
        ($Score -ge 60) { @{ Label = 'Elevated Risk'; Color = 'Gold' }; break }
        ($Score -ge 40) { @{ Label = 'High Risk';     Color = 'Amber' }; break }
        ($Score -ge 20) { @{ Label = 'Severe Risk';   Color = 'DeepOrange' }; break }
        default         { @{ Label = 'Critical Risk'; Color = 'DarkRed' } }
    }

    return $result
}
