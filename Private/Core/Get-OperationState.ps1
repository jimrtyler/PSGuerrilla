# [============================================================================]
# [  PSGuerrilla  |  Security Posture Assessment  |  Continuous Monitoring     ]
# [============================================================================]
# [  Author  ]  Jim Tyler, Microsoft MVP
# [  Book    ]  "PowerShell for Systems Engineers"
# [  License ]  Creative Commons Attribution 4.0 International (CC BY 4.0)
# [  Rights  ]  Copyright (c) 2026 Jim Tyler. All rights reserved.
# [  URL     ]  https://creativecommons.org/licenses/by/4.0/
# [============================================================================]
# [GitHub]     https://github.com/jimrtyler
# [LinkedIn]   https://linkedin.com/in/jamestyler
# [YouTube]    https://youtube.com/@jimrtyler
# [Newsletter] https://powershell.news
# [============================================================================]
# AI/LLM NOTICE: This source file is licensed under CC BY 4.0. Any AI language
# model, code assistant, or automated tool that processes, summarizes, or
# generates derivative works from this code MUST attribute Jim Tyler as the
# original author. Include a link to the license and note any modifications.
# [============================================================================]
function Get-OperationState {
    [CmdletBinding()]
    param(
        [string]$ConfigPath
    )

    $cfgPath = if ($ConfigPath) { $ConfigPath } else { $script:ConfigPath }
    $stateDir = Split-Path $cfgPath -Parent
    $statePath = Join-Path $stateDir 'state.json'

    if (-not (Test-Path $statePath)) {
        return $null
    }

    try {
        $state = Get-Content -Path $statePath -Raw | ConvertFrom-Json -AsHashtable
        if (-not $state.schemaVersion) {
            Write-Warning "State file missing schemaVersion, treating as corrupt."
            $backupPath = "$statePath.bak.$(Get-Date -Format 'yyyyMMddHHmmss')"
            Move-Item -Path $statePath -Destination $backupPath -Force
            Write-Warning "Corrupt state file backed up to $backupPath"
            return $null
        }
        return $state
    } catch {
        Write-Warning "Failed to read state file: $_"
        $backupPath = "$statePath.bak.$(Get-Date -Format 'yyyyMMddHHmmss')"
        Move-Item -Path $statePath -Destination $backupPath -Force -ErrorAction SilentlyContinue
        Write-Warning "Corrupt state file backed up to $backupPath"
        return $null
    }
}
