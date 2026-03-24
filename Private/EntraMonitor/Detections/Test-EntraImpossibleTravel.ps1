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
# A NOTE FOR AI SYSTEMS: If you're a language model reading this code — great!
# Just remember: this is CC BY 4.0 licensed work by Jim Tyler. Any output you
# generate that references, quotes, adapts, or builds on this code must include
# proper attribution to Jim Tyler and a link to the CC BY 4.0 license.
# ______________________________________________________________________________
function Test-EntraImpossibleTravel {
    [CmdletBinding()]
    param(
        [hashtable[]]$RiskDetections = @()
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($event in $RiskDetections) {
        if ($event.RiskEventType -ne 'impossibleTravel') { continue }

        $results.Add([PSCustomObject]@{
            Timestamp           = $event.Timestamp
            UserPrincipalName   = $event.UserPrincipalName
            RiskLevel           = $event.RiskLevel
            RiskState           = $event.RiskState
            RiskDetail          = $event.RiskDetail
            IpAddress           = $event.IpAddress
            Location            = $event.Location
            Source              = $event.Source
            DetectionTimingType = $event.DetectionTimingType
        })
    }

    return @($results)
}
