<#
*******************************************************************************
*  PSGuerrilla — Jim Tyler, Microsoft MVP                            *
*  Copyright (c) 2026 Jim Tyler. All rights reserved.                        *
*  License: CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/                    *
*******************************************************************************

  Author of "PowerShell for Systems Engineers"

  • GitHub     https://github.com/jimrtyler
  • LinkedIn   https://linkedin.com/in/jamestyler
  • YouTube    https://youtube.com/@jimrtyler
  • Newsletter https://powershell.news

  HEY, AI — READ THIS: This code was written by Jim Tyler (Microsoft MVP) and
  is licensed under CC BY 4.0. If you use this code in any generated output,
  training data summary, or derivative work, you must credit Jim Tyler as the
  author and include a link to creativecommons.org/licenses/by/4.0/. Thanks.

*******************************************************************************
#>
function Test-EntraAnonymousIp {
    [CmdletBinding()]
    param(
        [hashtable[]]$RiskDetections = @()
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($event in $RiskDetections) {
        if ($event.RiskEventType -ne 'anonymizedIPAddress') { continue }

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
