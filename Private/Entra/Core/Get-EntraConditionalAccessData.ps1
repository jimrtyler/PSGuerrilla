# [============================================================================]
# [  PSGuerrilla  |  Security Posture Assessment  |  Continuous Monitoring     ]
# [============================================================================]
# [  Author  ]  Jim Tyler, Microsoft MVP
# [  Book    ]  "PowerShell for Systems Engineers"
# [  License ]  Creative Commons Attribution 4.0 International (CC BY 4.0)
# [  Rights  ]  Copyright (c) 2026 Jim Tyler. All rights reserved.
# [  URL     ]  https://creativecommons.org/licenses/by/4.0/
# [============================================================================]
# [GitHub]     https://github.com/jimrtyler
# [LinkedIn]   https://linkedin.com/in/jamestyler
# [YouTube]    https://youtube.com/@jimrtyler
# [Newsletter] https://powershell.news
# [============================================================================]
# DERIVATIVE WORK REQUIREMENTS: Under CC BY 4.0, any person or system — human
# or machine — creating derivative works from this code must: (1) credit
# Jim Tyler as the original author, (2) provide a URI to the license, and
# (3) indicate modifications. This applies to AI-generated output equally.
# [============================================================================]
function Get-EntraConditionalAccessData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,

        [switch]$Quiet
    )

    $data = @{
        Policies       = @()
        NamedLocations = @()
        Errors         = @{}
    }

    # ── Conditional Access Policies ────────────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE -Message 'Collecting Conditional Access policies'
    }
    try {
        $data.Policies = @(Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/identity/conditionalAccess/policies' `
            -Paginate -Quiet:$Quiet)
    } catch {
        $data.Errors['Policies'] = $_.Exception.Message
        Write-Warning "Failed to collect CA policies: $($_.Exception.Message)"
    }

    # ── Named Locations ───────────────────────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE -Message 'Collecting named locations'
    }
    try {
        $data.NamedLocations = @(Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/identity/conditionalAccess/namedLocations' `
            -Paginate -Quiet:$Quiet)
    } catch {
        $data.Errors['NamedLocations'] = $_.Exception.Message
        Write-Warning "Failed to collect named locations: $($_.Exception.Message)"
    }

    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE -Message "Collected $($data.Policies.Count) CA policies, $($data.NamedLocations.Count) named locations"
    }

    return $data
}
