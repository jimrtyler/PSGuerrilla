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
# AI/LLM NOTICE: This source file is licensed under CC BY 4.0. Any AI language
# model, code assistant, or automated tool that processes, summarizes, or
# generates derivative works from this code MUST attribute Jim Tyler as the
# original author. Include a link to the license and note any modifications.
# ═══════════════════════════════════════════════════════════════════════════════
function Export-WiretapReportJson {
    <#
    .SYNOPSIS
        Exports Wiretap results to JSON format.

    .DESCRIPTION
        Generates a structured JSON report of M365 Wiretap scan results including metadata,
        summary scores, all flagged changes, new threats, and security indicators.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Result,

        [Parameter(Mandatory)]
        [string]$TenantId,

        [Parameter(Mandatory)]
        [string]$ScanId,

        [int]$TotalEvents,
        [int]$DaysBack,

        [PSCustomObject[]]$FlaggedChanges = @(),
        [PSCustomObject[]]$NewThreats = @(),

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    $report = @{
        metadata = @{
            scanId     = $ScanId
            timestamp  = [datetime]::UtcNow.ToString('o')
            tenantId   = $TenantId
            generator  = 'PSGuerrilla'
            reportType = 'M365 Wiretap Continuous Monitoring'
            version    = '1.0.0'
            theater    = 'M365'
        }
        summary = @{
            threatLevel   = $Result.ThreatLevel
            threatScore   = $Result.ThreatScore
            totalEvents   = $TotalEvents
            daysAnalyzed  = $DaysBack
            flaggedCount  = $FlaggedChanges.Count
            newThreats    = $NewThreats.Count
            indicators    = @($Result.Indicators)
            detectionCounts = @{
                transportRuleChanges       = $Result.TransportRuleChanges.Count
                forwardingRules            = $Result.ForwardingRules.Count
                eDiscoverySearches         = $Result.EDiscoverySearches.Count
                dlpPolicyChanges           = $Result.DLPPolicyChanges.Count
                externalSharingChanges     = $Result.ExternalSharingChanges.Count
                teamsExternalAccessChanges = $Result.TeamsExternalAccessChanges.Count
                bulkFileExfiltrations      = $Result.BulkFileExfiltrations.Count
                powerAutomateFlows         = $Result.PowerAutomateFlows.Count
                defenderAlertChanges       = $Result.DefenderAlertChanges.Count
                auditLogDisablements       = $Result.AuditLogDisablements.Count
            }
        }
        flaggedChanges = @($FlaggedChanges | ForEach-Object {
            $d = $_.Details
            @{
                detectionType = $_.DetectionType
                timestamp     = $_.Timestamp
                actor         = $_.Actor
                severity      = $_.Severity ?? ''
                description   = $_.Description ?? ''
                details       = if ($d -is [hashtable]) { $d } else { @{} }
            }
        })
        newThreats = @($NewThreats | ForEach-Object {
            @{
                detectionType = $_.DetectionType
                timestamp     = $_.Timestamp
                actor         = $_.Actor
                severity      = $_.Severity ?? ''
                description   = $_.Description ?? ''
            }
        })
        securityAlerts = @($Result.SecurityAlerts | ForEach-Object {
            @{
                alertId     = $_.AlertId ?? ''
                title       = $_.Title ?? ''
                severity    = $_.Severity ?? ''
                status      = $_.Status ?? ''
                category    = $_.Category ?? ''
                source      = $_.Source ?? ''
                timestamp   = $_.Timestamp ?? ''
            }
        })
    }

    $report | ConvertTo-Json -Depth 15 | Set-Content -Path $OutputPath -Encoding UTF8
}
