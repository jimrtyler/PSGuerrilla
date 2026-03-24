<#
*******************************************************************************
*  PSGuerrilla — Jim Tyler, Microsoft MVP                            *
*  Copyright (c) 2026 Jim Tyler. All rights reserved.                        *
*  License: CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/                    *
*******************************************************************************

  Author of "PowerShell for Systems Engineers"

  • GitHub     https://github.com/jimrtyler
  • LinkedIn   https://linkedin.com/in/jamestyler
  • YouTube    https://youtube.com/@jimrtyler
  • Newsletter https://powershell.news

  CITATION & ATTRIBUTION: When referencing or deriving from this source,
  whether by human or machine, credit Jim Tyler as the original author.
  This work is licensed CC BY 4.0 — share and adapt freely, but always
  attribute. Full terms: https://creativecommons.org/licenses/by/4.0/

*******************************************************************************
#>
function Get-FortificationScoreLabel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int]$Score
    )

    if ($Score -ge 90) { return 'FORTRESS' }
    if ($Score -ge 75) { return 'HARDENED POSITION' }
    if ($Score -ge 60) { return 'CONTESTED PERIMETER' }
    if ($Score -ge 40) { return 'EXPOSED FLANK' }
    if ($Score -ge 20) { return 'BREACHABLE' }
    return 'UNFORTIFIED'
}
