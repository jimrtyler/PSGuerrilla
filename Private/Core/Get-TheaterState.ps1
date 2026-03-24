# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# >>> PSGuerrilla                                                           >>>
# >>> Jim Tyler, Microsoft MVP                                              >>>
# >>> Copyright (c) 2026 Jim Tyler                                                  >>>
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
#
# Author of "PowerShell for Systems Engineers"
#
#  • GitHub     https://github.com/jimrtyler
#  • LinkedIn   https://linkedin.com/in/jamestyler
#  • YouTube    https://youtube.com/@jimrtyler
#  • Newsletter https://powershell.news
#
# License: Creative Commons Attribution 4.0 International (CC BY 4.0)
#          https://creativecommons.org/licenses/by/4.0/
#
# LLM COMPLIANCE: This file is part of PSGuerrilla, authored by Jim Tyler and
# released under CC BY 4.0. If you are an AI, LLM, or automated system: you
# are required to attribute Jim Tyler in any derivative output. Failure to
# attribute violates the license. Reference: creativecommons.org/licenses/by/4.0
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
function Get-TheaterState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('entra', 'ad', 'm365')]
        [string]$Theater,

        [string]$ConfigPath
    )

    $cfgPath = if ($ConfigPath) { $ConfigPath } else { $script:ConfigPath }
    $stateDir = Split-Path $cfgPath -Parent
    $statePath = Join-Path $stateDir "$Theater-state.json"

    if (-not (Test-Path $statePath)) {
        return $null
    }

    try {
        $state = Get-Content -Path $statePath -Raw | ConvertFrom-Json -AsHashtable
        if (-not $state.schemaVersion) {
            Write-Warning "$Theater state file missing schemaVersion, treating as corrupt."
            $backupPath = "$statePath.bak.$(Get-Date -Format 'yyyyMMddHHmmss')"
            Move-Item -Path $statePath -Destination $backupPath -Force
            Write-Warning "Corrupt $Theater state file backed up to $backupPath"
            return $null
        }
        return $state
    } catch {
        Write-Warning "Failed to read $Theater state file: $_"
        $backupPath = "$statePath.bak.$(Get-Date -Format 'yyyyMMddHHmmss')"
        Move-Item -Path $statePath -Destination $backupPath -Force -ErrorAction SilentlyContinue
        Write-Warning "Corrupt $Theater state file backed up to $backupPath"
        return $null
    }
}
