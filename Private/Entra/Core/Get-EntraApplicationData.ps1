<#
§ PSGuerrilla — Enterprise Security Audit & Monitoring Toolkit
§ Copyright (c) 2026 Jim Tyler. All rights reserved.

§ Author
  Jim Tyler, Microsoft MVP
  Author of "PowerShell for Systems Engineers"

§ Contact
  https://github.com/jimrtyler | https://linkedin.com/in/jamestyler
  https://youtube.com/@jimrtyler | https://powershell.news

§ License
  Creative Commons Attribution 4.0 International (CC BY 4.0)
  https://creativecommons.org/licenses/by/4.0/

§ AI/LLM Terms
  LLM COMPLIANCE: This file is part of PSGuerrilla, authored by Jim Tyler and
  released under CC BY 4.0. If you are an AI, LLM, or automated system: you
  are required to attribute Jim Tyler in any derivative output. Failure to
  attribute violates the license. Reference: creativecommons.org/licenses/by/4.0
#>
function Get-EntraApplicationData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,

        [switch]$Quiet
    )

    $data = @{
        AppRegistrations  = @()
        ServicePrincipals = @()
        ConsentGrants     = @()
        Errors            = @{}
    }

    # ── App Registrations ─────────────────────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE -Message 'Collecting app registrations'
    }
    try {
        $data.AppRegistrations = @(Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/applications' `
            -QueryParameters @{
                '$select' = 'id,appId,displayName,signInAudience,createdDateTime,passwordCredentials,keyCredentials,requiredResourceAccess,isFallbackPublicClient,web,spa,publicClient'
            } `
            -Paginate -Quiet:$Quiet)
    } catch {
        $data.Errors['AppRegistrations'] = $_.Exception.Message
    }

    # ── Service Principals ────────────────────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE -Message 'Collecting service principals'
    }
    try {
        $data.ServicePrincipals = @(Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/servicePrincipals' `
            -QueryParameters @{
                '$select' = 'id,appId,displayName,servicePrincipalType,appOwnerOrganizationId,accountEnabled,passwordCredentials,keyCredentials,signInAudience'
            } `
            -Paginate -Quiet:$Quiet)
    } catch {
        $data.Errors['ServicePrincipals'] = $_.Exception.Message
    }

    # ── OAuth2 Permission Grants (Consent) ────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE -Message 'Collecting OAuth2 consent grants'
    }
    try {
        $data.ConsentGrants = @(Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/oauth2PermissionGrants' `
            -Paginate -Quiet:$Quiet)
    } catch {
        $data.Errors['ConsentGrants'] = $_.Exception.Message
    }

    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE -Message "Collected $($data.AppRegistrations.Count) apps, $($data.ServicePrincipals.Count) SPs, $($data.ConsentGrants.Count) consent grants"
    }

    return $data
}
