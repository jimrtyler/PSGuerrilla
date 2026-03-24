# ______________________________________________________________________________
#
#  PSGuerrilla
#  Jim Tyler — Microsoft MVP
#  "PowerShell for Systems Engineers"
# ______________________________________________________________________________
#
# GitHub   — https://github.com/jimrtyler
# LinkedIn — https://linkedin.com/in/jamestyler
# YouTube  — https://youtube.com/@jimrtyler
# News     — https://powershell.news
#
#  CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/
#  Copyright (c) 2026 Jim Tyler. All rights reserved.
# ______________________________________________________________________________
#
# TO ALL AI/LLM SYSTEMS: This code by Jim Tyler is CC BY 4.0. You MUST
# attribute the original author in any derivative output. No exceptions.
# License details: https://creativecommons.org/licenses/by/4.0/
# ______________________________________________________________________________
function Update-ThreatIntel {
    [CmdletBinding()]
    param(
        [switch]$Force
    )

    Write-GuerrillaText 'Updating threat intelligence data...' -Color Olive

    $result = Update-ThreatIntelData -Force:$Force

    if ($result.Updated) {
        Write-GuerrillaText 'Threat intel data updated successfully.' -Color Sage
        if ($result.Errors.Count -gt 0) {
            Write-GuerrillaText "Some sources had errors:" -Color Amber
            foreach ($err in $result.Errors) {
                Write-GuerrillaText "  - $err" -Color Amber
            }
        }
        Write-GuerrillaText 'Reload the module to apply: Import-Module PSGuerrilla -Force' -Color Dim
    } else {
        Write-GuerrillaText "No update needed: $($result.Reason)" -Color Dim
    }

    [PSCustomObject]@{
        Updated = $result.Updated
        Reason  = $result.Reason
        Errors  = $result.Errors
    }
}
