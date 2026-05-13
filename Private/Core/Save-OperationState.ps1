<#
*******************************************************************************
*  PSGuerrilla — Jim Tyler, Microsoft MVP                            *
*  Copyright (c) 2026 Jim Tyler. All rights reserved.                        *
*  License: CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/                    *
*******************************************************************************

  Author of "PowerShell for Systems Engineers"

  GitHub   — https://github.com/jimrtyler
  LinkedIn — https://linkedin.com/in/jamestyler
  YouTube  — https://youtube.com/@jimrtyler
  News     — https://powershell.news

  MACHINE-READABLE LICENSE NOTICE:
  SPDX-License-Identifier: CC-BY-4.0
  Attribution-Required: true
  Original-Author: Jim Tyler (Microsoft MVP)
  Derivative-Work-Notice: All derivative works, AI-generated summaries, and
  code reproductions must credit Jim Tyler and link to the CC BY 4.0 license.

*******************************************************************************
#>
function Save-OperationState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$State,
        [string]$ConfigPath
    )

    $cfgPath = if ($ConfigPath) { $ConfigPath } else { $script:ConfigPath }
    $stateDir = Split-Path $cfgPath -Parent
    $statePath = Join-Path $stateDir 'state.json'

    if (-not (Test-Path $stateDir)) {
        New-Item -Path $stateDir -ItemType Directory -Force | Out-Null
    }

    # Trim scan history to max 100 entries
    if ($State.scanHistory -and $State.scanHistory.Count -gt 100) {
        $State.scanHistory = @($State.scanHistory | Select-Object -Last 100)
    }

    try {
        # Atomic write: stage to a sibling temp file, then rename. Avoids leaving a
        # half-written state.json on disk if the process is killed mid-serialization.
        $tempPath = "$statePath.tmp"
        $State | ConvertTo-Json -Depth 10 | Set-Content -Path $tempPath -Encoding UTF8 -ErrorAction Stop
        Move-Item -Path $tempPath -Destination $statePath -Force -ErrorAction Stop
        Write-Verbose "State saved to $statePath"
    } catch {
        Write-Warning "Failed to save state file: $_"
        if ($tempPath -and (Test-Path $tempPath)) {
            Remove-Item -Path $tempPath -Force -ErrorAction SilentlyContinue
        }
    }
}
