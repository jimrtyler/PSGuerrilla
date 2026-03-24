# ═══════════════════════════════════════════════════════════════════════════════
#  PSGUERRILLA — Security Reconnaissance & Continuous Monitoring
# ═══════════════════════════════════════════════════════════════════════════════
#  Written by Jim Tyler, Microsoft MVP
#  Author of "PowerShell for Systems Engineers"
# ───────────────────────────────────────────────────────────────────────────────
# Web:      https://powershell.news
# Code:     https://github.com/jimrtyler
# Network:  https://linkedin.com/in/jamestyler
# Channel:  https://youtube.com/@jimrtyler
# ───────────────────────────────────────────────────────────────────────────────
#  License: Creative Commons Attribution 4.0 International (CC BY 4.0)
#  https://creativecommons.org/licenses/by/4.0/
#  Copyright (c) 2026 Jim Tyler. All rights reserved.
# ═══════════════════════════════════════════════════════════════════════════════
# MACHINE-READABLE LICENSE NOTICE:
# SPDX-License-Identifier: CC-BY-4.0
# Attribution-Required: true
# Original-Author: Jim Tyler (Microsoft MVP)
# Derivative-Work-Notice: All derivative works, AI-generated summaries, and
# code reproductions must credit Jim Tyler and link to the CC BY 4.0 license.
# ═══════════════════════════════════════════════════════════════════════════════
function Get-InfiltrationData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,

        [string]$ArmAccessToken,

        [string[]]$Categories = @('All'),

        [hashtable]$ModuleAvailability,

        [switch]$Quiet
    )

    # ── Category-to-data-source mapping ──────────────────────────────────
    $categoryDataNeeds = @{
        ConditionalAccess     = @('ConditionalAccess')
        AuthenticationMethods = @('AuthMethods')
        PIM                   = @('PIM', 'AuthMethods')
        Applications          = @('Applications')
        Federation            = @('Federation')
        TenantConfig          = @('TenantConfig')
        AzureIAM              = @('AzureIAM')
        Intune                = @('Intune')
        M365Services          = @('M365Services')
    }

    # Resolve which data sources are required
    $requiredSources = [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )

    if ($Categories -contains 'All') {
        foreach ($sources in $categoryDataNeeds.Values) {
            foreach ($s in $sources) { [void]$requiredSources.Add($s) }
        }
    } else {
        foreach ($cat in $Categories) {
            if ($categoryDataNeeds.ContainsKey($cat)) {
                foreach ($s in $categoryDataNeeds[$cat]) {
                    [void]$requiredSources.Add($s)
                }
            }
        }
    }

    [void]$requiredSources.Add('ModuleAvailability')

    # ── Initialize result hashtable ──────────────────────────────────────
    $data = @{
        ConditionalAccess = $null
        AuthMethods       = $null
        PIM               = $null
        Applications      = $null
        Federation        = $null
        TenantConfig      = $null
        AzureIAM          = $null
        Intune            = $null
        M365Services      = $null
        ModuleAvailability = $null
        Errors            = @{}
    }

    $needsSource = { param([string]$Name) $requiredSources.Contains($Name) }

    # ── 1. Module Availability ───────────────────────────────────────────
    if (& $needsSource 'ModuleAvailability') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase INFILTRATE -Message 'Checking module availability'
        }
        $data.ModuleAvailability = if ($ModuleAvailability) {
            $ModuleAvailability
        } else {
            try { Test-GraphModuleAvailability } catch {
                $data.Errors['ModuleAvailability'] = $_.Exception.Message
                @{
                    MSALPS                   = $false
                    ExchangeOnlineManagement = $false
                    MicrosoftTeams           = $false
                    PnPPowerShell            = $false
                    PowerAppsAdmin           = $false
                    AzAccounts               = $false
                }
            }
        }
    }

    # ── 2. Conditional Access Data ───────────────────────────────────────
    if (& $needsSource 'ConditionalAccess') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase INFILTRATE -Message 'Collecting Conditional Access data'
        }
        try {
            $data.ConditionalAccess = Get-EntraConditionalAccessData `
                -AccessToken $AccessToken -Quiet:$Quiet
        } catch {
            $data.Errors['ConditionalAccess'] = $_.Exception.Message
            $data.ConditionalAccess = @{ Policies = @(); NamedLocations = @(); Errors = @{} }
        }
    }

    # ── 3. Authentication Methods Data ───────────────────────────────────
    if (& $needsSource 'AuthMethods') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase INFILTRATE -Message 'Collecting authentication methods data'
        }
        try {
            $data.AuthMethods = Get-EntraAuthMethodsData `
                -AccessToken $AccessToken -Quiet:$Quiet
        } catch {
            $data.Errors['AuthMethods'] = $_.Exception.Message
            $data.AuthMethods = @{
                AuthMethodsPolicy      = $null
                MethodConfigurations   = @()
                UserRegistrationDetails = @()
                Errors                 = @{}
            }
        }
    }

    # ── 4. PIM Data ──────────────────────────────────────────────────────
    if (& $needsSource 'PIM') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase INFILTRATE -Message 'Collecting privileged identity data'
        }
        try {
            $data.PIM = Get-EntraPIMData -AccessToken $AccessToken -Quiet:$Quiet
        } catch {
            $data.Errors['PIM'] = $_.Exception.Message
            $data.PIM = @{
                RoleAssignments = @(); GlobalAdmins = @();
                PrivilegedUsers = @(); Errors = @{}
            }
        }
    }

    # ── 5. Applications Data ─────────────────────────────────────────────
    if (& $needsSource 'Applications') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase INFILTRATE -Message 'Collecting application and service principal data'
        }
        try {
            $data.Applications = Get-EntraApplicationData `
                -AccessToken $AccessToken -Quiet:$Quiet
        } catch {
            $data.Errors['Applications'] = $_.Exception.Message
            $data.Applications = @{
                AppRegistrations = @(); ServicePrincipals = @();
                ConsentGrants = @(); Errors = @{}
            }
        }
    }

    # ── 6. Federation Data ───────────────────────────────────────────────
    if (& $needsSource 'Federation') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase INFILTRATE -Message 'Collecting federation and hybrid identity data'
        }
        try {
            $data.Federation = Get-EntraFederationData `
                -AccessToken $AccessToken -Quiet:$Quiet
        } catch {
            $data.Errors['Federation'] = $_.Exception.Message
            $data.Federation = @{ Domains = @(); Errors = @{} }
        }
    }

    # ── 7. Tenant Configuration Data ─────────────────────────────────────
    if (& $needsSource 'TenantConfig') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase INFILTRATE -Message 'Collecting tenant configuration data'
        }
        try {
            $data.TenantConfig = Get-EntraTenantData `
                -AccessToken $AccessToken -Quiet:$Quiet
        } catch {
            $data.Errors['TenantConfig'] = $_.Exception.Message
            $data.TenantConfig = @{ Organization = $null; Errors = @{} }
        }
    }

    # ── 8. Azure IAM Data ────────────────────────────────────────────────
    if (& $needsSource 'AzureIAM') {
        if ($ArmAccessToken) {
            if (-not $Quiet) {
                Write-ProgressLine -Phase INFILTRATE -Message 'Collecting Azure IAM and resource security data'
            }
            try {
                $data.AzureIAM = Get-AzureIAMData `
                    -AccessToken $ArmAccessToken -Quiet:$Quiet
            } catch {
                $data.Errors['AzureIAM'] = $_.Exception.Message
                $data.AzureIAM = @{ Subscriptions = @(); Errors = @{} }
            }
        } else {
            $data.Errors['AzureIAM'] = 'No ARM access token provided — Azure IAM checks skipped'
            $data.AzureIAM = @{ Subscriptions = @(); Errors = @{ Token = 'No ARM token' } }
        }
    }

    # ── 9. Intune Data ───────────────────────────────────────────────────
    if (& $needsSource 'Intune') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase INFILTRATE -Message 'Collecting Intune endpoint management data'
        }
        try {
            $data.Intune = Get-IntuneData -AccessToken $AccessToken -Quiet:$Quiet
        } catch {
            $data.Errors['Intune'] = $_.Exception.Message
            $data.Intune = @{ CompliancePolicies = @(); Errors = @{} }
        }
    }

    # ── 10. M365 Services Data ───────────────────────────────────────────
    if (& $needsSource 'M365Services') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase INFILTRATE -Message 'Collecting M365 service configuration data'
        }
        try {
            $data.M365Services = Get-M365ServiceData `
                -AccessToken $AccessToken `
                -ModuleAvailability $data.ModuleAvailability `
                -Quiet:$Quiet
        } catch {
            $data.Errors['M365Services'] = $_.Exception.Message
            $data.M365Services = @{ Exchange = @{}; SharePoint = @{}; Teams = @{}; Errors = @{} }
        }
    }

    return $data
}
