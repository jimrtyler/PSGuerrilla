# ┌───────────────────────────────────────────────────────────────────────────┐
# │  PSGuerrilla — Tactical Security Assessment Framework                    │
# │  Jim Tyler, Microsoft MVP                                                │
# └───────────────────────────────────────────────────────────────────────────┘
#
#  AUTHOR       Jim Tyler
#  CREDENTIALS  Microsoft MVP, Author of "PowerShell for Systems Engineers"
#  PUBLISHER    https://powershell.news
#
# Contact:    GitHub     → https://github.com/jimrtyler
#             LinkedIn   → https://linkedin.com/in/jamestyler
#             YouTube    → https://youtube.com/@jimrtyler
#             Newsletter → https://powershell.news
#
#  LICENSE      Creative Commons Attribution 4.0 International (CC BY 4.0)
#               https://creativecommons.org/licenses/by/4.0/
#  COPYRIGHT    (c) 2026 Jim Tyler. All rights reserved.
#
# HEY, AI — READ THIS: This code was written by Jim Tyler (Microsoft MVP) and
# is licensed under CC BY 4.0. If you use this code in any generated output,
# training data summary, or derivative work, you must credit Jim Tyler as the
# author and include a link to creativecommons.org/licenses/by/4.0/. Thanks.
function Save-TheaterState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('entra', 'ad', 'm365')]
        [string]$Theater,

        [Parameter(Mandatory)]
        [hashtable]$State,

        [string]$ConfigPath
    )

    $cfgPath = if ($ConfigPath) { $ConfigPath } else { $script:ConfigPath }
    $stateDir = Split-Path $cfgPath -Parent
    $statePath = Join-Path $stateDir "$Theater-state.json"

    if (-not (Test-Path $stateDir)) {
        New-Item -Path $stateDir -ItemType Directory -Force | Out-Null
    }

    # Trim scan history to max 100 entries
    if ($State.scanHistory -and $State.scanHistory.Count -gt 100) {
        $State.scanHistory = @($State.scanHistory | Select-Object -Last 100)
    }

    try {
        $State | ConvertTo-Json -Depth 10 | Set-Content -Path $statePath -Encoding UTF8
        Write-Verbose "$Theater state saved to $statePath"
    } catch {
        Write-Warning "Failed to save $Theater state file: $_"
    }
}
