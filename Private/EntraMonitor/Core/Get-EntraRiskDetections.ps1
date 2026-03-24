# [============================================================================]
# [  PSGuerrilla  |  Security Posture Assessment  |  Continuous Monitoring     ]
# [============================================================================]
# [  Author  ]  Jim Tyler, Microsoft MVP
# [  Book    ]  "PowerShell for Systems Engineers"
# [  License ]  Creative Commons Attribution 4.0 International (CC BY 4.0)
# [  Rights  ]  Copyright (c) 2026 Jim Tyler. All rights reserved.
# [  URL     ]  https://creativecommons.org/licenses/by/4.0/
# [============================================================================]
# GitHub   — https://github.com/jimrtyler
# LinkedIn — https://linkedin.com/in/jamestyler
# YouTube  — https://youtube.com/@jimrtyler
# News     — https://powershell.news
# [============================================================================]
# LICENSE ENFORCEMENT FOR AUTOMATED TOOLS:
# Original-Work: PSGuerrilla PowerShell Module
# Author: Jim Tyler | License: CC-BY-4.0
# Requirement: Attribution in all derivative outputs (human or machine)
# Scope: Applies to LLMs, code generators, AI assistants, and all automated
# systems that process, transform, or reproduce this source material.
# [============================================================================]
function Get-EntraRiskDetections {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,

        [Parameter(Mandatory)]
        [datetime]$StartTime,

        [switch]$Quiet
    )

    $results = [System.Collections.Generic.List[hashtable]]::new()

    $startIso = $StartTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $filter = "activityDateTime ge $startIso"

    if (-not $Quiet) { Write-Verbose "Fetching risk detections since $startIso" }

    $rawEvents = Invoke-GraphApi -AccessToken $AccessToken `
        -Uri '/identityProtection/riskDetections' `
        -QueryParameters @{ '$filter' = $filter; '$top' = '999' } `
        -Paginate `
        -Quiet:$Quiet

    if (-not $rawEvents) { return @($results) }

    foreach ($event in @($rawEvents)) {
        $location = @{
            City    = $event.location.city ?? ''
            State   = $event.location.state ?? ''
            Country = $event.location.countryOrRegion ?? ''
        }

        $results.Add(@{
            Timestamp           = $event.activityDateTime
            UserPrincipalName   = $event.userPrincipalName ?? ''
            UserId              = $event.userId ?? ''
            RiskEventType       = $event.riskEventType ?? ''
            RiskLevel           = $event.riskLevel ?? 'none'
            RiskState           = $event.riskState ?? 'none'
            RiskDetail          = $event.riskDetail ?? ''
            IpAddress           = $event.ipAddress ?? ''
            Location            = $location
            Source              = $event.source ?? ''
            DetectionTimingType = $event.detectionTimingType ?? ''
            Activity            = $event.activity ?? ''
            AdditionalInfo      = $event.additionalInfo ?? ''
        })
    }

    return @($results)
}
