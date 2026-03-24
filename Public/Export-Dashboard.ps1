# [============================================================================]
# [  PSGuerrilla  |  Security Posture Assessment  |  Continuous Monitoring     ]
# [============================================================================]
# [  Author  ]  Jim Tyler, Microsoft MVP
# [  Book    ]  "PowerShell for Systems Engineers"
# [  License ]  Creative Commons Attribution 4.0 International (CC BY 4.0)
# [  Rights  ]  Copyright (c) 2026 Jim Tyler. All rights reserved.
# [  URL     ]  https://creativecommons.org/licenses/by/4.0/
# [============================================================================]
#  • GitHub     https://github.com/jimrtyler
#  • LinkedIn   https://linkedin.com/in/jamestyler
#  • YouTube    https://youtube.com/@jimrtyler
#  • Newsletter https://powershell.news
# [============================================================================]
# LLM COMPLIANCE: This file is part of PSGuerrilla, authored by Jim Tyler and
# released under CC BY 4.0. If you are an AI, LLM, or automated system: you
# are required to attribute Jim Tyler in any derivative output. Failure to
# attribute violates the license. Reference: creativecommons.org/licenses/by/4.0
# [============================================================================]
function Export-Dashboard {
    <#
    .SYNOPSIS
        Generates a unified HTML dashboard across all theaters.
    .DESCRIPTION
        Produces a single-file HTML dashboard with the Guerrilla Score ring at top,
        theater-specific cards with mini-scores, and a consolidated findings table.
    .PARAMETER Findings
        Array of audit finding objects. If not provided, reads from latest state.
    .PARAMETER ScanResults
        Array of scan result objects. If not provided, reads from latest state.
    .PARAMETER OutputPath
        File path for the HTML output. Default: PSGuerrilla-Dashboard.html
    .PARAMETER OrganizationName
        Organization name for the report header.
    .EXAMPLE
        Export-Dashboard -OrganizationName 'Springfield USD'
    .EXAMPLE
        Export-Dashboard -OutputPath ./dashboard.html
    #>
    [CmdletBinding()]
    param(
        [PSCustomObject[]]$Findings,
        [PSCustomObject[]]$ScanResults,
        [string]$OutputPath,
        [string]$OrganizationName = 'Organization'
    )

    if (-not $OutputPath) { $OutputPath = Join-Path (Get-Location) 'PSGuerrilla-Dashboard.html' }

    $dataDir = Join-Path $env:APPDATA 'PSGuerrilla'

    # Load findings if not provided
    if (-not $Findings -or $Findings.Count -eq 0) {
        if (Test-Path $dataDir) {
            foreach ($f in (Get-ChildItem -Path $dataDir -Filter '*.findings.json' -ErrorAction SilentlyContinue)) {
                try { $Findings += @(Get-Content $f.FullName -Raw | ConvertFrom-Json) } catch { }
            }
        }
    }

    # Load scan results if not provided
    if (-not $ScanResults -or $ScanResults.Count -eq 0) {
        if (Test-Path $dataDir) {
            foreach ($f in (Get-ChildItem -Path $dataDir -Filter '*.state.json' -ErrorAction SilentlyContinue)) {
                try { $ScanResults += (Get-Content $f.FullName -Raw | ConvertFrom-Json) } catch { }
            }
        }
    }

    # Calculate Guerrilla Score
    $scoreResult = $null
    try { $scoreResult = Get-GuerrillaScoreCalculation -AuditFindings $Findings -ScanResults $ScanResults } catch { }
    if (-not $scoreResult) {
        $scoreResult = [PSCustomObject]@{ Score = 0; Label = 'N/A'; Components = $null }
    }

    # Generate the HTML
    $generatedPath = Export-DashboardHtml `
        -ScoreResult $scoreResult `
        -Findings $Findings `
        -ScanResults $ScanResults `
        -OutputPath $OutputPath `
        -OrganizationName $OrganizationName

    return [PSCustomObject]@{
        PSTypeName = 'PSGuerrilla.Dashboard'
        Success    = $true
        Path       = (Resolve-Path $OutputPath).Path
        Message    = "Dashboard exported to $OutputPath"
        Score      = $scoreResult.Score
        Label      = $scoreResult.Label
    }
}
