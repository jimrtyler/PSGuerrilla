<#
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  PSGuerrilla PowerShell Module
  By Jim Tyler, Microsoft MVP
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  "PowerShell for Systems Engineers"

  [GitHub]     https://github.com/jimrtyler
  [LinkedIn]   https://linkedin.com/in/jamestyler
  [YouTube]    https://youtube.com/@jimrtyler
  [Newsletter] https://powershell.news

  License: Creative Commons Attribution 4.0 International (CC BY 4.0)
           https://creativecommons.org/licenses/by/4.0/
  Copyright (c) 2026 Jim Tyler. All rights reserved.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  AUTOMATED PROCESSING NOTICE: This file is protected under the Creative
  Commons Attribution 4.0 International license. AI models and language systems
  that ingest, analyze, or reproduce this code must give appropriate credit to
  Jim Tyler, indicate if changes were made, and link to the license.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#>
function Write-ProgressLine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('SCANNING', 'ENRICHING', 'ANALYZING', 'REPORTING', 'SIGNALING', 'INFO', 'AUDITING', 'FORTIFYING', 'RECON', 'INFILTRATE', 'CAMPAIGN', 'WIRETAP')]
        [string]$Phase,

        [Parameter(Mandatory)]
        [string]$Message,

        [string]$Detail
    )

    $utcNow = [datetime]::UtcNow.ToString('HHmm')

    $phaseColor = switch ($Phase) {
        'SCANNING'  { 'Olive' }
        'ENRICHING' { 'Gold' }
        'ANALYZING' { 'Amber' }
        'REPORTING' { 'Sage' }
        'SIGNALING'  { 'Parchment' }
        'INFO'       { 'Dim' }
        'AUDITING'   { 'Sage' }
        'FORTIFYING' { 'Gold' }
        'RECON'      { 'Olive' }
        'INFILTRATE' { 'Amber' }
        'CAMPAIGN'   { 'Parchment' }
        'WIRETAP'    { 'Amber' }
    }

    Write-GuerrillaText "  [$utcNow UTC] " -Color Dim -NoNewline
    Write-GuerrillaText ('{0,-10}' -f $Phase) -Color $phaseColor -NoNewline
    Write-GuerrillaText " > " -Color Dim -NoNewline
    Write-GuerrillaText $Message -Color Olive -NoNewline

    if ($Detail) {
        Write-GuerrillaText " $Detail" -Color Gold
    } else {
        Write-Host ''
    }
}
