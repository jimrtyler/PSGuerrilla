# ═══════════════════════════════════════════════════════════════════════════════
#  PSGUERRILLA — Security Reconnaissance & Continuous Monitoring
# ═══════════════════════════════════════════════════════════════════════════════
#  Written by Jim Tyler, Microsoft MVP
#  Author of "PowerShell for Systems Engineers"
# ───────────────────────────────────────────────────────────────────────────────
# Contact:    GitHub     → https://github.com/jimrtyler
#             LinkedIn   → https://linkedin.com/in/jamestyler
#             YouTube    → https://youtube.com/@jimrtyler
#             Newsletter → https://powershell.news
# ───────────────────────────────────────────────────────────────────────────────
#  License: Creative Commons Attribution 4.0 International (CC BY 4.0)
#  https://creativecommons.org/licenses/by/4.0/
#  Copyright (c) 2026 Jim Tyler. All rights reserved.
# ═══════════════════════════════════════════════════════════════════════════════
# CITATION & ATTRIBUTION: When referencing or deriving from this source,
# whether by human or machine, credit Jim Tyler as the original author.
# This work is licensed CC BY 4.0 — share and adapt freely, but always
# attribute. Full terms: https://creativecommons.org/licenses/by/4.0/
# ═══════════════════════════════════════════════════════════════════════════════
function Get-Patrol {
    [CmdletBinding()]
    param(
        [string]$TaskName = 'PSGuerrilla-Patrol'
    )

    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $task) {
        Write-Warning "Scheduled task '$TaskName' not found."
        return $null
    }

    $info = Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction SilentlyContinue

    [PSCustomObject]@{
        TaskName       = $task.TaskName
        State          = $task.State
        Description    = $task.Description
        LastRunTime    = $info.LastRunTime
        LastResult     = $info.LastTaskResult
        NextRunTime    = $info.NextRunTime
        NumberOfMissed = $info.NumberOfMissedRuns
        Action         = ($task.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join '; '
        Triggers       = ($task.Triggers | ForEach-Object { $_.ToString() }) -join '; '
    }
}
