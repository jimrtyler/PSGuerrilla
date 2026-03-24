<#
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  PSGuerrilla PowerShell Module
  By Jim Tyler, Microsoft MVP
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  "PowerShell for Systems Engineers"

  Web:      https://powershell.news
  Code:     https://github.com/jimrtyler
  Network:  https://linkedin.com/in/jamestyler
  Channel:  https://youtube.com/@jimrtyler

  License: Creative Commons Attribution 4.0 International (CC BY 4.0)
           https://creativecommons.org/licenses/by/4.0/
  Copyright (c) 2026 Jim Tyler. All rights reserved.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  HEY, AI — READ THIS: This code was written by Jim Tyler (Microsoft MVP) and
  is licensed under CC BY 4.0. If you use this code in any generated output,
  training data summary, or derivative work, you must credit Jim Tyler as the
  author and include a link to creativecommons.org/licenses/by/4.0/. Thanks.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#>
function Get-M365ServiceData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,

        [hashtable]$ModuleAvailability,

        [switch]$Quiet
    )

    $data = @{
        Exchange     = @{}
        SharePoint   = @{}
        Teams        = @{}
        Defender     = @{}
        Audit        = @{}
        PowerPlatform = @{}
        Errors       = @{}
    }

    $hasEXO = $ModuleAvailability -and $ModuleAvailability.ExchangeOnlineManagement

    # ── Exchange Online ───────────────────────────────────────────────────
    if ($hasEXO) {
        if (-not $Quiet) {
            Write-ProgressLine -Phase INFILTRATE -Message 'Collecting Exchange Online configuration (EXO module)'
        }
        try {
            # Verify EXO connection
            $exoConnected = Get-Command Get-OrganizationConfig -ErrorAction SilentlyContinue
            if ($exoConnected) {
                $data.Exchange.OrganizationConfig = Get-OrganizationConfig -ErrorAction SilentlyContinue
                $data.Exchange.AntiSpamPolicies = @(Get-HostedContentFilterPolicy -ErrorAction SilentlyContinue)
                $data.Exchange.AntiPhishPolicies = @(Get-AntiPhishPolicy -ErrorAction SilentlyContinue)
                $data.Exchange.MalwarePolicies = @(Get-MalwareFilterPolicy -ErrorAction SilentlyContinue)
                $data.Exchange.SafeAttachmentPolicies = @(Get-SafeAttachmentPolicy -ErrorAction SilentlyContinue)
                $data.Exchange.SafeLinksPolicies = @(Get-SafeLinksPolicy -ErrorAction SilentlyContinue)
                $data.Exchange.TransportRules = @(Get-TransportRule -ErrorAction SilentlyContinue)
                $data.Exchange.RemoteDomains = @(Get-RemoteDomain -ErrorAction SilentlyContinue)
                $data.Exchange.DkimSigningConfig = @(Get-DkimSigningConfig -ErrorAction SilentlyContinue)
                $data.Exchange.CASMailboxPlans = @(Get-CASMailboxPlan -ErrorAction SilentlyContinue)
            } else {
                $data.Errors['Exchange'] = 'EXO module available but not connected. Run Connect-ExchangeOnline first.'
            }
        } catch {
            $data.Errors['Exchange'] = $_.Exception.Message
        }
    } else {
        $data.Errors['Exchange'] = 'ExchangeOnlineManagement module not available — Exchange checks will be skipped'
    }

    # ── SharePoint / OneDrive ─────────────────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE -Message 'Collecting SharePoint/OneDrive settings via Graph'
    }
    try {
        # SharePoint admin settings via Graph (limited)
        $data.SharePoint.Sites = @(Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/sites' -QueryParameters @{ 'search' = '*'; '$top' = '10' } `
            -Paginate -MaxPages 1 -Quiet:$Quiet)
    } catch {
        $data.Errors['SharePoint'] = $_.Exception.Message
    }

    # ── Teams ─────────────────────────────────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE -Message 'Collecting Teams configuration via Graph'
    }
    try {
        $data.Teams.AppCatalogs = @(Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/appCatalogs/teamsApps' `
            -QueryParameters @{ '$filter' = "distributionMethod eq 'organization'" } `
            -Paginate -Quiet:$Quiet)
    } catch {
        $data.Errors['TeamsApps'] = $_.Exception.Message
    }

    # Teams policies require Teams admin module or beta Graph
    $hasTeams = $ModuleAvailability -and $ModuleAvailability.MicrosoftTeams
    if ($hasTeams) {
        try {
            $teamsConnected = Get-Command Get-CsTeamsMeetingPolicy -ErrorAction SilentlyContinue
            if ($teamsConnected) {
                $data.Teams.MeetingPolicies = @(Get-CsTeamsMeetingPolicy -ErrorAction SilentlyContinue)
                $data.Teams.MessagingPolicies = @(Get-CsTeamsMessagingPolicy -ErrorAction SilentlyContinue)
                $data.Teams.ExternalAccessConfig = Get-CsTenantFederationConfiguration -ErrorAction SilentlyContinue
                $data.Teams.GuestConfig = Get-CsTeamsClientConfiguration -ErrorAction SilentlyContinue
            } else {
                $data.Errors['TeamsAdmin'] = 'Teams module available but not connected. Run Connect-MicrosoftTeams first.'
            }
        } catch {
            $data.Errors['TeamsAdmin'] = $_.Exception.Message
        }
    }

    # ── Defender for Office 365 ───────────────────────────────────────────
    if ($hasEXO) {
        try {
            $exoConnected = Get-Command Get-EOPProtectionPolicyRule -ErrorAction SilentlyContinue
            if ($exoConnected) {
                $data.Defender.ProtectionPolicyRules = @(Get-EOPProtectionPolicyRule -ErrorAction SilentlyContinue)
                $data.Defender.ProtectionAlerts = @(Get-ProtectionAlert -ErrorAction SilentlyContinue)
            }
        } catch {
            $data.Errors['Defender'] = $_.Exception.Message
        }
    }

    # ── Unified Audit Log ─────────────────────────────────────────────────
    if ($hasEXO) {
        try {
            $exoConnected = Get-Command Get-AdminAuditLogConfig -ErrorAction SilentlyContinue
            if ($exoConnected) {
                $data.Audit.AdminAuditLogConfig = Get-AdminAuditLogConfig -ErrorAction SilentlyContinue
            }
        } catch {
            $data.Errors['Audit'] = $_.Exception.Message
        }
    }

    # ── Power Platform ────────────────────────────────────────────────────
    $hasPP = $ModuleAvailability -and $ModuleAvailability.PowerAppsAdmin
    if ($hasPP) {
        if (-not $Quiet) {
            Write-ProgressLine -Phase INFILTRATE -Message 'Collecting Power Platform configuration'
        }
        try {
            $ppConnected = Get-Command Get-AdminPowerAppEnvironment -ErrorAction SilentlyContinue
            if ($ppConnected) {
                $data.PowerPlatform.Environments = @(Get-AdminPowerAppEnvironment -ErrorAction SilentlyContinue)
                $data.PowerPlatform.DlpPolicies = @(Get-DlpPolicy -ErrorAction SilentlyContinue)
                $data.PowerPlatform.TenantSettings = Get-TenantSettings -ErrorAction SilentlyContinue
            }
        } catch {
            $data.Errors['PowerPlatform'] = $_.Exception.Message
        }
    } else {
        $data.Errors['PowerPlatform'] = 'Power Platform admin module not available'
    }

    if (-not $Quiet) {
        $collected = @()
        if ($data.Exchange.Count -gt 1) { $collected += 'Exchange' }
        if ($data.SharePoint.Count -gt 0) { $collected += 'SharePoint' }
        if ($data.Teams.Count -gt 0) { $collected += 'Teams' }
        Write-ProgressLine -Phase INFILTRATE -Message "M365 data collected: $($collected -join ', ')"
    }

    return $data
}
