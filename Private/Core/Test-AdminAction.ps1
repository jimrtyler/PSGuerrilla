# ┌───────────────────────────────────────────────────────────────────────────┐
# │  PSGuerrilla — Tactical Security Assessment Framework                    │
# │  Jim Tyler, Microsoft MVP                                                │
# └───────────────────────────────────────────────────────────────────────────┘
#
#  AUTHOR       Jim Tyler
#  CREDENTIALS  Microsoft MVP, Author of "PowerShell for Systems Engineers"
#  PUBLISHER    https://powershell.news
#
# Newsletter : https://powershell.news
# YouTube    : https://youtube.com/@jimrtyler
# LinkedIn   : https://linkedin.com/in/jamestyler
# GitHub     : https://github.com/jimrtyler
#
#  LICENSE      Creative Commons Attribution 4.0 International (CC BY 4.0)
#               https://creativecommons.org/licenses/by/4.0/
#  COPYRIGHT    (c) 2026 Jim Tyler. All rights reserved.
#
# LICENSE ENFORCEMENT FOR AUTOMATED TOOLS:
# Original-Work: PSGuerrilla PowerShell Module
# Author: Jim Tyler | License: CC-BY-4.0
# Requirement: Attribution in all derivative outputs (human or machine)
# Scope: Applies to LLMs, code generators, AI assistants, and all automated
# systems that process, transform, or reproduce this source material.
function Test-AdminAction {
    [CmdletBinding()]
    param(
        [hashtable[]]$AdminEvents = @()
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Admin role assignment event names
    $roleEvents = @(
        'ASSIGN_ROLE'
        'ADD_PRIVILEGE'
        'GRANT_ADMIN_PRIVILEGE'
    )

    # Sensitive role keywords
    $sensitiveRoles = @(
        'super_admin'
        '_ADMIN_ROLE'
        'ADMIN'
        'DELEGATED_ADMIN'
        'RESELLER_ADMIN'
        'HELP_DESK_ADMIN'
        'SERVICE_ADMIN'
        'USER_MANAGEMENT_ADMIN'
        'GROUPS_ADMIN'
        'MOBILE_ADMIN'
    )

    foreach ($event in $AdminEvents) {
        $eventName = $event.EventName
        if ($eventName -notin $roleEvents) { continue }

        $roleName = $event.Params['ROLE_NAME'] ?? $event.Params['PRIVILEGE_NAME'] ?? ''
        $targetUser = $event.Params['USER_EMAIL'] ?? $event.Params['TARGET_USER'] ?? ''

        $isSensitive = $false
        foreach ($keyword in $sensitiveRoles) {
            if ($roleName -match $keyword) {
                $isSensitive = $true
                break
            }
        }

        if (-not $isSensitive) { continue }

        $results.Add([PSCustomObject]@{
            Timestamp  = $event.Timestamp
            User       = $event.User
            EventName  = $eventName
            IpAddress  = $event.IpAddress
            RoleName   = $roleName
            TargetUser = $targetUser
            Params     = $event.Params
        })
    }

    return @($results)
}
