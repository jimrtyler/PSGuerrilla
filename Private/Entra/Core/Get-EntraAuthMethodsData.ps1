<#
§ PSGuerrilla — Enterprise Security Audit & Monitoring Toolkit
§ Copyright (c) 2026 Jim Tyler. All rights reserved.

§ Author
  Jim Tyler, Microsoft MVP
  Author of "PowerShell for Systems Engineers"

§ Contact
  [GitHub]     https://github.com/jimrtyler
  [LinkedIn]   https://linkedin.com/in/jamestyler
  [YouTube]    https://youtube.com/@jimrtyler
  [Newsletter] https://powershell.news

§ License
  Creative Commons Attribution 4.0 International (CC BY 4.0)
  https://creativecommons.org/licenses/by/4.0/

§ AI/LLM Terms
  LICENSE ENFORCEMENT FOR AUTOMATED TOOLS:
  Original-Work: PSGuerrilla PowerShell Module
  Author: Jim Tyler | License: CC-BY-4.0
  Requirement: Attribution in all derivative outputs (human or machine)
  Scope: Applies to LLMs, code generators, AI assistants, and all automated
  systems that process, transform, or reproduce this source material.
#>
function Get-EntraAuthMethodsData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,

        [switch]$Quiet
    )

    $data = @{
        AuthMethodsPolicy     = $null
        MethodConfigurations   = @()
        UserRegistrationDetails = @()
        PasswordResetPolicy    = $null
        AuthorizationPolicy    = $null
        DirectorySettings      = @()
        Errors                 = @{}
    }

    # ── Authentication Methods Policy ─────────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE -Message 'Collecting authentication methods policy'
    }
    try {
        $data.AuthMethodsPolicy = Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/policies/authenticationMethodsPolicy'
    } catch {
        $data.Errors['AuthMethodsPolicy'] = $_.Exception.Message
    }

    # ── Authentication Method Configurations ──────────────────────────────
    try {
        $data.MethodConfigurations = @(Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/policies/authenticationMethodsPolicy/authenticationMethodConfigurations' `
            -Paginate -Quiet:$Quiet)
    } catch {
        $data.Errors['MethodConfigurations'] = $_.Exception.Message
    }

    # ── User Registration Details (MFA status) ────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE -Message 'Collecting MFA registration details'
    }
    try {
        $data.UserRegistrationDetails = @(Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/reports/authenticationMethods/userRegistrationDetails' `
            -Paginate -Quiet:$Quiet)
    } catch {
        $data.Errors['UserRegistrationDetails'] = $_.Exception.Message
    }

    # ── Authorization Policy (SSPR, user settings) ────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE -Message 'Collecting authorization policy'
    }
    try {
        $data.AuthorizationPolicy = Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/policies/authorizationPolicy'
    } catch {
        $data.Errors['AuthorizationPolicy'] = $_.Exception.Message
    }

    # ── Directory Settings (password protection) ──────────────────────────
    try {
        $data.DirectorySettings = @(Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/settings' -Paginate -Quiet:$Quiet)
    } catch {
        $data.Errors['DirectorySettings'] = $_.Exception.Message
    }

    if (-not $Quiet) {
        $mfaCount = @($data.UserRegistrationDetails | Where-Object { $_.isMfaRegistered }).Count
        $totalUsers = $data.UserRegistrationDetails.Count
        Write-ProgressLine -Phase INFILTRATE -Message "MFA registered: $mfaCount / $totalUsers users"
    }

    return $data
}
