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
# CITATION & ATTRIBUTION: When referencing or deriving from this source,
# whether by human or machine, credit Jim Tyler as the original author.
# This work is licensed CC BY 4.0 — share and adapt freely, but always
# attribute. Full terms: https://creativecommons.org/licenses/by/4.0/
# [============================================================================]
function Get-EntraTenantData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,

        [switch]$Quiet
    )

    $data = @{
        Organization            = $null
        AuthorizationPolicy     = $null
        SecurityDefaults        = $null
        CrossTenantAccess       = $null
        CrossTenantPartners     = @()
        SubscribedSkus          = @()
        AdminUnits              = @()
        Domains                 = @()
        AdminConsentRequestPolicy = $null
        Errors                  = @{}
    }

    # ── Organization Settings ─────────────────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE -Message 'Collecting organization settings'
    }
    try {
        $orgResponse = Invoke-GraphApi -AccessToken $AccessToken -Uri '/organization'
        $data.Organization = if ($orgResponse.value) { $orgResponse.value[0] } else { $orgResponse }
    } catch {
        $data.Errors['Organization'] = $_.Exception.Message
    }

    # ── Authorization Policy ──────────────────────────────────────────────
    try {
        $data.AuthorizationPolicy = Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/policies/authorizationPolicy'
    } catch {
        $data.Errors['AuthorizationPolicy'] = $_.Exception.Message
    }

    # ── Security Defaults ─────────────────────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE -Message 'Checking security defaults'
    }
    try {
        $data.SecurityDefaults = Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/policies/identitySecurityDefaultsEnforcementPolicy'
    } catch {
        $data.Errors['SecurityDefaults'] = $_.Exception.Message
    }

    # ── Cross-Tenant Access Policy ────────────────────────────────────────
    try {
        $data.CrossTenantAccess = Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/policies/crossTenantAccessPolicy'
    } catch {
        $data.Errors['CrossTenantAccess'] = $_.Exception.Message
    }

    # ── Cross-Tenant Partners ─────────────────────────────────────────────
    try {
        $data.CrossTenantPartners = @(Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/policies/crossTenantAccessPolicy/partners' `
            -Paginate -Quiet:$Quiet)
    } catch {
        $data.Errors['CrossTenantPartners'] = $_.Exception.Message
    }

    # ── Subscribed SKUs (Licenses) ────────────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE -Message 'Collecting license inventory'
    }
    try {
        $data.SubscribedSkus = @(Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/subscribedSkus' -Paginate -Quiet:$Quiet)
    } catch {
        $data.Errors['SubscribedSkus'] = $_.Exception.Message
    }

    # ── Administrative Units ──────────────────────────────────────────────
    try {
        $data.AdminUnits = @(Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/directory/administrativeUnits' -Paginate -Quiet:$Quiet)
    } catch {
        $data.Errors['AdminUnits'] = $_.Exception.Message
    }

    # ── Domains ───────────────────────────────────────────────────────────
    try {
        $data.Domains = @(Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/domains' -Paginate -Quiet:$Quiet)
    } catch {
        $data.Errors['Domains'] = $_.Exception.Message
    }

    # ── Admin Consent Request Policy ──────────────────────────────────────
    try {
        $data.AdminConsentRequestPolicy = Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/policies/adminConsentRequestPolicy'
    } catch {
        $data.Errors['AdminConsentRequestPolicy'] = $_.Exception.Message
    }

    if (-not $Quiet) {
        $tenantName = $data.Organization.displayName ?? 'Unknown'
        Write-ProgressLine -Phase INFILTRATE -Message "Tenant: $tenantName, $($data.SubscribedSkus.Count) licenses, $($data.AdminUnits.Count) admin units"
    }

    return $data
}
