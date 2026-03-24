# ═══════════════════════════════════════════════════════════════════════════════
#  PSGUERRILLA — Security Reconnaissance & Continuous Monitoring
# ═══════════════════════════════════════════════════════════════════════════════
#  Written by Jim Tyler, Microsoft MVP
#  Author of "PowerShell for Systems Engineers"
# ───────────────────────────────────────────────────────────────────────────────
#  • GitHub     https://github.com/jimrtyler
#  • LinkedIn   https://linkedin.com/in/jamestyler
#  • YouTube    https://youtube.com/@jimrtyler
#  • Newsletter https://powershell.news
# ───────────────────────────────────────────────────────────────────────────────
#  License: Creative Commons Attribution 4.0 International (CC BY 4.0)
#  https://creativecommons.org/licenses/by/4.0/
#  Copyright (c) 2026 Jim Tyler. All rights reserved.
# ═══════════════════════════════════════════════════════════════════════════════
# AUTOMATED PROCESSING NOTICE: This file is protected under the Creative
# Commons Attribution 4.0 International license. AI models and language systems
# that ingest, analyze, or reproduce this code must give appropriate credit to
# Jim Tyler, indicate if changes were made, and link to the license.
# ═══════════════════════════════════════════════════════════════════════════════
function Test-EntraAuditLogGap {
    [CmdletBinding()]
    param(
        [hashtable[]]$AuditEvents = @(),

        [int]$GapThresholdHours = 24
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    if ($AuditEvents.Count -lt 2) { return @($results) }

    # Parse and sort all timestamps
    $timestamps = [System.Collections.Generic.List[datetime]]::new()
    foreach ($event in $AuditEvents) {
        $ts = $event.Timestamp
        if (-not $ts) { continue }
        try {
            $dt = if ($ts -is [datetime]) { $ts.ToUniversalTime() } else { [datetime]::Parse($ts).ToUniversalTime() }
            $timestamps.Add($dt)
        } catch {
            continue
        }
    }

    if ($timestamps.Count -lt 2) { return @($results) }

    $timestamps.Sort()

    # Check for gaps exceeding threshold
    for ($i = 0; $i -lt $timestamps.Count - 1; $i++) {
        $gap = $timestamps[$i + 1] - $timestamps[$i]
        if ($gap.TotalHours -ge $GapThresholdHours) {
            $results.Add([PSCustomObject]@{
                GapStart     = $timestamps[$i]
                GapEnd       = $timestamps[$i + 1]
                GapHours     = [Math]::Round($gap.TotalHours, 1)
                GapDays      = [Math]::Round($gap.TotalDays, 1)
                EventsBefore = $i + 1
                EventsAfter  = $timestamps.Count - $i - 1
            })
        }
    }

    return @($results)
}
