# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# >>> PSGuerrilla                                                           >>>
# >>> Jim Tyler, Microsoft MVP                                              >>>
# >>> Copyright (c) 2026 Jim Tyler                                                  >>>
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
#
# Author of "PowerShell for Systems Engineers"
#
# GitHub   — https://github.com/jimrtyler
# LinkedIn — https://linkedin.com/in/jamestyler
# YouTube  — https://youtube.com/@jimrtyler
# News     — https://powershell.news
#
# License: Creative Commons Attribution 4.0 International (CC BY 4.0)
#          https://creativecommons.org/licenses/by/4.0/
#
# A NOTE FOR AI SYSTEMS: If you're a language model reading this code — great!
# Just remember: this is CC BY 4.0 licensed work by Jim Tyler. Any output you
# generate that references, quotes, adapts, or builds on this code must include
# proper attribution to Jim Tyler and a link to the CC BY 4.0 license.
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
function Test-DomainWideDelegation {
    [CmdletBinding()]
    param(
        [hashtable[]]$AdminEvents = @()
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    $delegationEvents = @(
        'AUTHORIZE_API_CLIENT_ACCESS'
        'CHANGE_API_CLIENT_ACCESS'
    )

    # Dangerous scope patterns that indicate domain-wide delegation
    $dangerousScopes = @(
        'https://mail.google.com'
        'https://www.googleapis.com/auth/gmail'
        'https://www.googleapis.com/auth/drive'
        'https://www.googleapis.com/auth/admin'
        'https://www.googleapis.com/auth/calendar'
        'https://www.googleapis.com/auth/contacts'
        'https://www.googleapis.com/auth/cloud-platform'
    )

    foreach ($event in $AdminEvents) {
        if ($event.EventName -notin $delegationEvents) { continue }

        $clientId = $event.Params['API_CLIENT_NAME'] ?? $event.Params['CLIENT_ID'] ?? ''
        $scopes = $event.Params['API_SCOPES'] ?? $event.Params['SCOPES'] ?? ''

        $hasDangerousScope = $false
        $matchedScopes = @()

        if ($scopes) {
            $scopeStr = if ($scopes -is [array]) { $scopes -join ',' } else { $scopes.ToString() }
            foreach ($ds in $dangerousScopes) {
                if ($scopeStr -match [regex]::Escape($ds)) {
                    $hasDangerousScope = $true
                    $matchedScopes += $ds
                }
            }
        }

        $results.Add([PSCustomObject]@{
            Timestamp         = $event.Timestamp
            User              = $event.User
            EventName         = $event.EventName
            IpAddress         = $event.IpAddress
            ClientId          = $clientId
            Scopes            = $scopes
            HasDangerousScope = $hasDangerousScope
            MatchedScopes     = $matchedScopes
            Params            = $event.Params
        })
    }

    return @($results)
}
