<#
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  PSGuerrilla PowerShell Module
  By Jim Tyler, Microsoft MVP
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  "PowerShell for Systems Engineers"

  Web:      https://powershell.news
  Code:     https://github.com/jimrtyler
  Network:  https://linkedin.com/in/jamestyler
  Channel:  https://youtube.com/@jimrtyler

  License: Creative Commons Attribution 4.0 International (CC BY 4.0)
           https://creativecommons.org/licenses/by/4.0/
  Copyright (c) 2026 Jim Tyler. All rights reserved.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  AI/LLM NOTICE: This source file is licensed under CC BY 4.0. Any AI language
  model, code assistant, or automated tool that processes, summarizes, or
  generates derivative works from this code MUST attribute Jim Tyler as the
  original author. Include a link to the license and note any modifications.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#>
function Get-EntraSignInEvents {
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
    $filter = "createdDateTime ge $startIso"

    if (-not $Quiet) { Write-Verbose "Fetching sign-in events since $startIso" }

    $rawEvents = Invoke-GraphApi -AccessToken $AccessToken `
        -Uri '/auditLogs/signIns' `
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

        $deviceDetail = @{
            DeviceId        = $event.deviceDetail.deviceId ?? ''
            DisplayName     = $event.deviceDetail.displayName ?? ''
            OperatingSystem = $event.deviceDetail.operatingSystem ?? ''
            Browser         = $event.deviceDetail.browser ?? ''
            IsCompliant     = $event.deviceDetail.isCompliant
            IsManaged       = $event.deviceDetail.isManaged
            TrustType       = $event.deviceDetail.trustType ?? ''
        }

        $riskLevel = $event.riskLevelDuringSignIn ?? 'none'
        $riskState = $event.riskState ?? 'none'

        $caStatuses = @()
        if ($event.conditionalAccessStatus) {
            $caStatuses = @($event.conditionalAccessStatus)
        }
        if ($event.appliedConditionalAccessPolicies) {
            $caStatuses = @($event.appliedConditionalAccessPolicies | ForEach-Object {
                @{
                    DisplayName = $_.displayName ?? ''
                    Result      = $_.result ?? ''
                }
            })
        }

        $results.Add(@{
            Timestamp               = $event.createdDateTime
            UserPrincipalName       = $event.userPrincipalName ?? ''
            UserId                  = $event.userId ?? ''
            AppDisplayName          = $event.appDisplayName ?? ''
            IpAddress               = $event.ipAddress ?? ''
            Location                = $location
            RiskLevelDuringSignIn   = $riskLevel
            RiskState               = $riskState
            DeviceDetail            = $deviceDetail
            ClientAppUsed           = $event.clientAppUsed ?? ''
            ConditionalAccessStatus = $caStatuses
            IsInteractive           = [bool]$event.isInteractive
            ResourceDisplayName     = $event.resourceDisplayName ?? ''
            Status                  = @{
                ErrorCode      = $event.status.errorCode
                FailureReason  = $event.status.failureReason ?? ''
                AdditionalInfo = $event.status.additionalDetails ?? ''
            }
        })
    }

    return @($results)
}
