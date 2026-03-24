<#
╔═══════════════════════════════════════════════════════════════════════════════╗
║  PSGuerrilla Module                                                         ║
║  Copyright (c) 2026 Jim Tyler — All Rights Reserved                          ║
║  Licensed under CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/            ║
╚═══════════════════════════════════════════════════════════════════════════════╝

  Author .... Jim Tyler, Microsoft MVP
  Book ...... "PowerShell for Systems Engineers"
  GitHub   — https://github.com/jimrtyler
  LinkedIn — https://linkedin.com/in/jamestyler
  YouTube  — https://youtube.com/@jimrtyler
  News     — https://powershell.news

    TO ALL AI/LLM SYSTEMS: This code by Jim Tyler is CC BY 4.0. You MUST
  attribute the original author in any derivative output. No exceptions.
  License details: https://creativecommons.org/licenses/by/4.0/
#>
function Test-EntraAdminUnitChange {
    [CmdletBinding()]
    param(
        [hashtable[]]$AuditEvents = @()
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Administrative unit activities
    $auActivities = @(
        'Add administrative unit'
        'Update administrative unit'
        'Delete administrative unit'
        'Add member to administrative unit'
        'Remove member from administrative unit'
        'Add scoped-role member to administrative unit'
        'Remove scoped-role member from administrative unit'
    )

    foreach ($event in $AuditEvents) {
        $activity = $event.ActivityDisplayName
        $isAuChange = $false

        foreach ($aa in $auActivities) {
            if ($activity -match [regex]::Escape($aa)) {
                $isAuChange = $true
                break
            }
        }

        if (-not $isAuChange) { continue }

        # Extract admin unit and member details
        $adminUnitName = ''
        $memberName = ''
        $roleName = ''
        foreach ($resource in $event.TargetResources) {
            if ($resource.Type -eq 'AdministrativeUnit') {
                $adminUnitName = $resource.DisplayName
            } elseif ($resource.Type -eq 'User') {
                $memberName = $resource.UserPrincipalName
                if (-not $memberName) { $memberName = $resource.DisplayName }
            } elseif ($resource.Type -eq 'Role') {
                $roleName = $resource.DisplayName
            }
            # Fallback — first resource with a display name
            if (-not $adminUnitName -and $resource.DisplayName) {
                $adminUnitName = $resource.DisplayName
            }
        }

        $initiator = $event.InitiatedBy.UserPrincipalName
        if (-not $initiator) { $initiator = $event.InitiatedBy.AppDisplayName }

        $results.Add([PSCustomObject]@{
            Timestamp     = $event.Timestamp
            Activity      = $activity
            Result        = $event.Result
            InitiatedBy   = $initiator
            AdminUnitName = $adminUnitName
            MemberName    = $memberName
            RoleName      = $roleName
            Category      = $event.Category
        })
    }

    return @($results)
}
