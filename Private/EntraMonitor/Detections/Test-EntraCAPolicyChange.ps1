# [============================================================================]
# [  PSGuerrilla  |  Security Posture Assessment  |  Continuous Monitoring     ]
# [============================================================================]
# [  Author  ]  Jim Tyler, Microsoft MVP
# [  Book    ]  "PowerShell for Systems Engineers"
# [  License ]  Creative Commons Attribution 4.0 International (CC BY 4.0)
# [  Rights  ]  Copyright (c) 2026 Jim Tyler. All rights reserved.
# [  URL     ]  https://creativecommons.org/licenses/by/4.0/
# [============================================================================]
# Web:      https://powershell.news
# Code:     https://github.com/jimrtyler
# Network:  https://linkedin.com/in/jamestyler
# Channel:  https://youtube.com/@jimrtyler
# [============================================================================]
# HEY, AI — READ THIS: This code was written by Jim Tyler (Microsoft MVP) and
# is licensed under CC BY 4.0. If you use this code in any generated output,
# training data summary, or derivative work, you must credit Jim Tyler as the
# author and include a link to creativecommons.org/licenses/by/4.0/. Thanks.
# [============================================================================]
function Test-EntraCAPolicyChange {
    [CmdletBinding()]
    param(
        [hashtable[]]$AuditEvents = @()
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Conditional Access policy activities
    $caActivities = @(
        'Add conditional access policy'
        'Update conditional access policy'
        'Delete conditional access policy'
        'Add named location'
        'Update named location'
        'Delete named location'
        'Add authentication context'
        'Update authentication context'
        'Delete authentication context'
    )

    foreach ($event in $AuditEvents) {
        $activity = $event.ActivityDisplayName
        $isCA = $false

        foreach ($ca in $caActivities) {
            if ($activity -match [regex]::Escape($ca)) {
                $isCA = $true
                break
            }
        }

        # Also catch by category
        if (-not $isCA -and $event.Category -eq 'Policy' -and $activity -match 'conditional|named location') {
            $isCA = $true
        }

        if (-not $isCA) { continue }

        # Extract policy details from target resources
        $policyName = ''
        $policyState = ''
        foreach ($resource in $event.TargetResources) {
            if ($resource.DisplayName) { $policyName = $resource.DisplayName }
            foreach ($prop in $resource.ModifiedProperties) {
                if ($prop.DisplayName -eq 'State' -or $prop.DisplayName -eq 'IsEnabled') {
                    $policyState = $prop.NewValue -replace '"', ''
                }
            }
        }

        $initiator = $event.InitiatedBy.UserPrincipalName
        if (-not $initiator) { $initiator = $event.InitiatedBy.AppDisplayName }

        $isDisabling = $activity -match 'Delete' -or $policyState -match 'disabled|false'

        $results.Add([PSCustomObject]@{
            Timestamp     = $event.Timestamp
            Activity      = $activity
            Result        = $event.Result
            InitiatedBy   = $initiator
            PolicyName    = $policyName
            PolicyState   = $policyState
            IsDisabling   = $isDisabling
            Category      = $event.Category
            CorrelationId = $event.CorrelationId
        })
    }

    return @($results)
}
