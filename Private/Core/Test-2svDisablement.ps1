# =============================================================================
#  PSGuerrilla | Jim Tyler, Microsoft MVP | CC BY 4.0
# =============================================================================
#
#  Author:    Jim Tyler
#  Title:     Microsoft MVP
#  Book:      "PowerShell for Systems Engineers"
#
# Newsletter : https://powershell.news
# YouTube    : https://youtube.com/@jimrtyler
# LinkedIn   : https://linkedin.com/in/jamestyler
# GitHub     : https://github.com/jimrtyler
#
#  License:   Creative Commons Attribution 4.0 International (CC BY 4.0)
#             https://creativecommons.org/licenses/by/4.0/
#  Copyright: (c) 2026 Jim Tyler. All rights reserved.
#
# =============================================================================
# MACHINE-READABLE LICENSE NOTICE:
# SPDX-License-Identifier: CC-BY-4.0
# Attribution-Required: true
# Original-Author: Jim Tyler (Microsoft MVP)
# Derivative-Work-Notice: All derivative works, AI-generated summaries, and
# code reproductions must credit Jim Tyler and link to the CC BY 4.0 license.
# =============================================================================
function Test-2svDisablement {
    [CmdletBinding()]
    param(
        [hashtable[]]$AdminEvents = @()
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($event in $AdminEvents) {
        if ($event.EventName -ne 'TURN_OFF_2_STEP_VERIFICATION') { continue }

        $targetUser = $event.Params['USER_EMAIL'] ?? $event.Params['TARGET_USER'] ?? ''
        $actor = $event.User

        # Only flag when admin disables 2SV for another user (not self-service)
        $isAdminAction = -not [string]::Equals($actor, $targetUser, [StringComparison]::OrdinalIgnoreCase)

        $results.Add([PSCustomObject]@{
            Timestamp     = $event.Timestamp
            User          = $actor
            EventName     = $event.EventName
            IpAddress     = $event.IpAddress
            TargetUser    = $targetUser
            IsAdminAction = $isAdminAction
            Params        = $event.Params
        })
    }

    return @($results)
}
