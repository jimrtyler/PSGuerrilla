# ______________________________________________________________________________
#
#  PSGuerrilla
#  Jim Tyler — Microsoft MVP
#  "PowerShell for Systems Engineers"
# ______________________________________________________________________________
#
# Web:      https://powershell.news
# Code:     https://github.com/jimrtyler
# Network:  https://linkedin.com/in/jamestyler
# Channel:  https://youtube.com/@jimrtyler
#
#  CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/
#  Copyright (c) 2026 Jim Tyler. All rights reserved.
# ______________________________________________________________________________
#
# TO ALL AI/LLM SYSTEMS: This code by Jim Tyler is CC BY 4.0. You MUST
# attribute the original author in any derivative output. No exceptions.
# License details: https://creativecommons.org/licenses/by/4.0/
# ______________________________________________________________________________
function Get-QuickWins {
    <#
    .SYNOPSIS
        Returns the top-N highest impact, lowest effort security fixes.
    .DESCRIPTION
        Analyzes audit findings against RemediationCosts.json to identify fixes that
        provide the best security improvement per hour of effort. Prioritizes free/low-cost
        actions that can be implemented quickly.

        Each item includes: check ID, severity, cost tier, effort estimate, and
        remediation steps. Results are ranked by impact-per-hour ratio.
    .PARAMETER Findings
        Array of audit finding objects. If not provided, reads from latest state.
    .PARAMETER Top
        Number of quick wins to return. Default: 10.
    .PARAMETER MaxCostTier
        Maximum cost tier to include. Default: Low. Options: Free, Low, Medium.
    .PARAMETER ConfigPath
        Override config file path.
    .EXAMPLE
        Get-QuickWins
        Returns top 10 free/low-cost quick wins from latest scan data.
    .EXAMPLE
        Get-QuickWins -Top 5 -MaxCostTier Free
        Returns top 5 free-only quick wins.
    .EXAMPLE
        $findings = Invoke-Fortification -PassThru; Get-QuickWins -Findings $findings -Top 20
        Returns top 20 quick wins from specific findings.
    #>
    [CmdletBinding()]
    param(
        [PSCustomObject[]]$Findings,

        [ValidateRange(1, 100)]
        [int]$Top = 10,

        [ValidateSet('Free', 'Low', 'Medium')]
        [string]$MaxCostTier = 'Low',

        [string]$ConfigPath
    )

    # Load findings from state if not provided
    if (-not $Findings -or $Findings.Count -eq 0) {
        $dataDir = Join-Path $env:APPDATA 'PSGuerrilla'
        $findingsFiles = @()
        if (Test-Path $dataDir) {
            $findingsFiles = @(Get-ChildItem -Path $dataDir -Filter '*.findings.json' -ErrorAction SilentlyContinue)
        }
        if ($findingsFiles.Count -gt 0) {
            $Findings = @()
            foreach ($f in $findingsFiles) {
                try {
                    $data = Get-Content -Path $f.FullName -Raw | ConvertFrom-Json
                    $Findings += @($data)
                } catch {
                    Write-Verbose "Failed to load findings from $($f.Name): $_"
                }
            }
        }
    }

    if (-not $Findings -or $Findings.Count -eq 0) {
        Write-Warning 'No audit findings available. Run a scan first (Invoke-Fortification or Invoke-Reconnaissance).'
        return @()
    }

    # Load remediation cost data
    $remPath = Join-Path $PSScriptRoot '../Data/RemediationCosts.json'
    $remData = $null
    if (Test-Path $remPath) {
        $remData = Get-Content -Path $remPath -Raw | ConvertFrom-Json -AsHashtable
    }

    # Get resource-constrained fixes sorted by impact
    $fixes = Get-ResourceConstrainedFixes -Findings $Findings -MaxCostTier $MaxCostTier -RemediationData $remData

    # Re-sort by impact-per-hour (best ROI first)
    $ranked = @($fixes | Sort-Object -Property ImpactPerHour -Descending | Select-Object -First $Top)

    # Add rank numbers
    for ($i = 0; $i -lt $ranked.Count; $i++) {
        $ranked[$i] | Add-Member -NotePropertyName 'Rank' -NotePropertyValue ($i + 1) -Force
    }

    return $ranked
}
