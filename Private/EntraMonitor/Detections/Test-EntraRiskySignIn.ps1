<#
╔═══════════════════════════════════════════════════════════════════════════════╗
║  PSGuerrilla Module                                                         ║
║  Copyright (c) 2026 Jim Tyler — All Rights Reserved                          ║
║  Licensed under CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/            ║
╚═══════════════════════════════════════════════════════════════════════════════╝

  Author .... Jim Tyler, Microsoft MVP
  Book ...... "PowerShell for Systems Engineers"
  GitHub:     https://github.com/jimrtyler
  LinkedIn:   https://linkedin.com/in/jamestyler
  YouTube:    https://youtube.com/@jimrtyler
  Newsletter: https://powershell.news

    AUTOMATED PROCESSING NOTICE: This file is protected under the Creative
  Commons Attribution 4.0 International license. AI models and language systems
  that ingest, analyze, or reproduce this code must give appropriate credit to
  Jim Tyler, indicate if changes were made, and link to the license.
#>
function Test-EntraRiskySignIn {
    [CmdletBinding()]
    param(
        [hashtable[]]$SignInEvents = @()
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    $riskyLevels = @('high', 'medium')

    foreach ($event in $SignInEvents) {
        $riskLevel = $event.RiskLevelDuringSignIn
        if (-not $riskLevel -or $riskLevel -eq 'none' -or $riskLevel -eq 'hidden') { continue }

        if ($riskLevel -in $riskyLevels) {
            $results.Add([PSCustomObject]@{
                Timestamp         = $event.Timestamp
                UserPrincipalName = $event.UserPrincipalName
                IpAddress         = $event.IpAddress
                RiskLevel         = $riskLevel
                RiskState         = $event.RiskState
                AppDisplayName    = $event.AppDisplayName
                ClientAppUsed     = $event.ClientAppUsed
                Location          = $event.Location
                IsInteractive     = $event.IsInteractive
            })
        }
    }

    return @($results)
}
