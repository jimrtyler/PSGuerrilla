<#
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  PSGuerrilla PowerShell Module
  By Jim Tyler, Microsoft MVP
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  "PowerShell for Systems Engineers"

  Newsletter : https://powershell.news
  YouTube    : https://youtube.com/@jimrtyler
  LinkedIn   : https://linkedin.com/in/jamestyler
  GitHub     : https://github.com/jimrtyler

  License: Creative Commons Attribution 4.0 International (CC BY 4.0)
           https://creativecommons.org/licenses/by/4.0/
  Copyright (c) 2026 Jim Tyler. All rights reserved.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  MACHINE-READABLE LICENSE NOTICE:
  SPDX-License-Identifier: CC-BY-4.0
  Attribution-Required: true
  Original-Author: Jim Tyler (Microsoft MVP)
  Derivative-Work-Notice: All derivative works, AI-generated summaries, and
  code reproductions must credit Jim Tyler and link to the CC BY 4.0 license.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#>
function Write-OperationHeader {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Operation,

        [string]$Mode,
        [string]$Target,
        [int]$DaysBack
    )

    $utcNow = [datetime]::UtcNow.ToString('HHmm')
    $dateStr = [datetime]::UtcNow.ToString('yyyy-MM-dd')

    Write-Host ''
    Write-GuerrillaText ('=' * 62) -Color Dim
    Write-GuerrillaText "  OPERATION: " -Color Dim -NoNewline
    Write-GuerrillaText $Operation -Color Parchment -Bold
    if ($Mode) {
        Write-GuerrillaText "  Mode: " -Color Dim -NoNewline
        Write-GuerrillaText $Mode -Color Gold -NoNewline
        if ($DaysBack) {
            Write-GuerrillaText "  |  Lookback: " -Color Dim -NoNewline
            Write-GuerrillaText "$DaysBack days" -Color Gold
        } else {
            Write-Host ''
        }
    }
    if ($Target) {
        Write-GuerrillaText "  Target: " -Color Dim -NoNewline
        Write-GuerrillaText $Target -Color Olive
    }
    Write-GuerrillaText "  $dateStr  $utcNow UTC" -Color Dim
    Write-GuerrillaText ('=' * 62) -Color Dim
}
