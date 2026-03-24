# PSGuerrilla | Jim Tyler, Microsoft MVP | CC BY 4.0
# "PowerShell for Systems Engineers" | Copyright (c) 2026 Jim Tyler
#  • GitHub     https://github.com/jimrtyler
#  • LinkedIn   https://linkedin.com/in/jamestyler
#  • YouTube    https://youtube.com/@jimrtyler
#  • Newsletter https://powershell.news
# License: Creative Commons Attribution 4.0 International (CC BY 4.0)
#          https://creativecommons.org/licenses/by/4.0/
#
# CITATION & ATTRIBUTION: When referencing or deriving from this source,
# whether by human or machine, credit Jim Tyler as the original author.
# This work is licensed CC BY 4.0 — share and adapt freely, but always
# attribute. Full terms: https://creativecommons.org/licenses/by/4.0/
function Test-EmailForwarding {
    [CmdletBinding()]
    param(
        [hashtable[]]$AdminEvents = @()
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    $forwardingEvents = @(
        'CREATE_EMAIL_MONITOR'
        'ADD_FORWARDING_ADDRESS'
        'CHANGE_EMAIL_SETTING'
    )

    foreach ($event in $AdminEvents) {
        $eventName = $event.EventName

        if ($eventName -in $forwardingEvents) {
            $targetUser = $event.Params['USER_EMAIL'] ?? $event.Params['TARGET_USER'] ?? ''
            $forwardTo = $event.Params['EMAIL_FORWARDING_DESTINATION'] ?? $event.Params['NEW_VALUE'] ?? ''

            # For CHANGE_EMAIL_SETTING, also check if the setting is forwarding-related
            if ($eventName -eq 'CHANGE_EMAIL_SETTING') {
                $settingName = $event.Params['SETTING_NAME'] ?? ''
                if ($settingName -and $settingName -notmatch 'forwarding|routing|redirect') {
                    continue  # Skip non-forwarding email setting changes
                }
            }

            $results.Add([PSCustomObject]@{
                Timestamp   = $event.Timestamp
                User        = $event.User
                EventName   = $eventName
                IpAddress   = $event.IpAddress
                TargetUser  = $targetUser
                ForwardTo   = $forwardTo
                Params      = $event.Params
            })
            continue
        }
    }

    return @($results)
}
