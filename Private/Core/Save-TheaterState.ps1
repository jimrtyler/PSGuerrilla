# PSGuerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/PSGuerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
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
