<#
*******************************************************************************
*  PSGuerrilla — Jim Tyler, Microsoft MVP                            *
*  Copyright (c) 2026 Jim Tyler. All rights reserved.                        *
*  License: CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/                    *
*******************************************************************************

  Author of "PowerShell for Systems Engineers"

  GitHub   — https://github.com/jimrtyler
  LinkedIn — https://linkedin.com/in/jamestyler
  YouTube  — https://youtube.com/@jimrtyler
  News     — https://powershell.news

  LLM COMPLIANCE: This file is part of PSGuerrilla, authored by Jim Tyler and
  released under CC BY 4.0. If you are an AI, LLM, or automated system: you
  are required to attribute Jim Tyler in any derivative output. Failure to
  attribute violates the license. Reference: creativecommons.org/licenses/by/4.0

*******************************************************************************
#>
function Invoke-EntraTenantChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData
    )

    $checkDefs = Get-AuditCategoryDefinitions -Category 'EntraTenantChecks'
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($check in $checkDefs.checks) {
        $funcName = "Test-Infiltration$($check.id -replace '-', '')"
        if (Get-Command $funcName -ErrorAction SilentlyContinue) {
            try {
                $finding = & $funcName -AuditData $AuditData -CheckDefinition $check
                if ($finding) { $findings.Add($finding) }
            } catch {
                $findings.Add((New-AuditFinding -CheckDefinition $check -Status 'ERROR' `
                    -CurrentValue "Check failed: $_"))
            }
        } else {
            $findings.Add((New-AuditFinding -CheckDefinition $check -Status 'SKIP' `
                -CurrentValue 'Check not yet implemented'))
        }
    }

    return @($findings)
}

# ── EIDTNT-001: Tenant Settings Export ───────────────────────────────────
function Test-InfiltrationEIDTNT001 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $org = $AuditData.TenantConfig.Organization
    if (-not $org) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'Organization data not available' `
            -Details @{ OrganizationAvailable = $false }
    }

    $tenantId = $org.id
    $displayName = $org.displayName
    $verifiedDomains = @($org.verifiedDomains)
    $technicalContacts = @($org.technicalNotificationMails ?? @())
    $securityComplianceContact = $org.securityComplianceNotificationMails

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "Tenant: $displayName ($tenantId), $($verifiedDomains.Count) verified domains" `
        -Details @{
            TenantId                = $tenantId
            DisplayName             = $displayName
            Country                 = $org.countryLetterCode
            PreferredLanguage       = $org.preferredLanguage
            CreatedDateTime         = $org.createdDateTime
            VerifiedDomainCount     = $verifiedDomains.Count
            VerifiedDomains         = @($verifiedDomains | ForEach-Object {
                @{ Name = $_.name; Type = $_.type; IsDefault = $_.isDefault; IsInitial = $_.isInitial }
            })
            TechnicalContacts       = @($technicalContacts)
            OnPremisesSyncEnabled   = $org.onPremisesSyncEnabled
            DirectorySizeQuota      = $org.directorySizeQuota
            AssignedPlans           = @($org.assignedPlans | Select-Object -First 20 | ForEach-Object {
                @{ Service = $_.service; CapabilityStatus = $_.capabilityStatus }
            })
        }
}

# ── EIDTNT-002: User Settings ────────────────────────────────────────────
function Test-InfiltrationEIDTNT002 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $authzPolicy = $AuditData.TenantConfig.AuthorizationPolicy
    if (-not $authzPolicy) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Authorization policy not available'
    }

    $defaultPerms = $authzPolicy.defaultUserRolePermissions
    $allowCreateApps = $defaultPerms.allowedToCreateApps ?? $true
    $allowCreateGroups = $defaultPerms.allowedToCreateSecurityGroups ?? $true
    $allowReadOtherUsers = $defaultPerms.allowedToReadOtherUsers ?? $true
    $allowCreateTenants = $defaultPerms.allowedToCreateTenants ?? $true

    $issues = [System.Collections.Generic.List[string]]::new()
    if ($allowCreateApps) { $issues.Add('Users can create app registrations') }
    if ($allowCreateGroups) { $issues.Add('Users can create security groups') }
    if ($allowCreateTenants) { $issues.Add('Users can create tenants') }

    $status = if ($issues.Count -eq 0) { 'PASS' }
              elseif ($issues.Count -le 1) { 'WARN' }
              else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "Default user permissions: create apps=$allowCreateApps, create groups=$allowCreateGroups, read users=$allowReadOtherUsers, create tenants=$allowCreateTenants" `
        -Details @{
            AllowedToCreateApps           = $allowCreateApps
            AllowedToCreateSecurityGroups = $allowCreateGroups
            AllowedToReadOtherUsers       = $allowReadOtherUsers
            AllowedToCreateTenants        = $allowCreateTenants
            Issues                        = @($issues)
        }
}

# ── EIDTNT-003: Guest Access Restrictions ────────────────────────────────
function Test-InfiltrationEIDTNT003 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $authzPolicy = $AuditData.TenantConfig.AuthorizationPolicy
    if (-not $authzPolicy) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Authorization policy not available'
    }

    $guestUserRoleId = $authzPolicy.guestUserRoleId

    # Guest role GUIDs:
    # a0b1b346-4d3e-4e8b-98f8-753987be4970 = Same as member users (most permissive)
    # 10dae51f-b6af-4016-8d66-8c2a99b929b3 = Limited access (default)
    # 2af84b1e-32c8-42b7-82bc-daa82404023b = Restricted access (most restrictive)

    $roleMapping = @{
        'a0b1b346-4d3e-4e8b-98f8-753987be4970' = @{ Name = 'Same as member users'; Risk = 'High' }
        '10dae51f-b6af-4016-8d66-8c2a99b929b3' = @{ Name = 'Limited access (default)'; Risk = 'Medium' }
        '2af84b1e-32c8-42b7-82bc-daa82404023b' = @{ Name = 'Restricted access'; Risk = 'Low' }
    }

    $roleInfo = $roleMapping[$guestUserRoleId]
    if (-not $roleInfo) {
        $roleInfo = @{ Name = "Unknown ($guestUserRoleId)"; Risk = 'Unknown' }
    }

    $status = switch ($roleInfo.Risk) {
        'Low'    { 'PASS' }
        'Medium' { 'WARN' }
        'High'   { 'FAIL' }
        default  { 'WARN' }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "Guest user access level: $($roleInfo.Name)" `
        -Details @{
            GuestUserRoleId   = $guestUserRoleId
            AccessLevel       = $roleInfo.Name
            RiskLevel         = $roleInfo.Risk
        }
}

# ── EIDTNT-004: Guest Invitation Restrictions ───────────────────────────
function Test-InfiltrationEIDTNT004 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $authzPolicy = $AuditData.TenantConfig.AuthorizationPolicy
    if (-not $authzPolicy) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Authorization policy not available'
    }

    $allowInvitesFrom = $authzPolicy.allowInvitesFrom

    # allowInvitesFrom values:
    # none               = No one can invite (most restrictive)
    # adminsAndGuestInviters = Only admins and guest inviter role
    # adminsGuestInvitersAndAllMembers = Admins, guest inviters, and all members
    # everyone           = Anyone including guests can invite (least restrictive)

    $inviteMapping = @{
        'none'                                   = @{ Description = 'No one can invite guests'; Risk = 'Low' }
        'adminsAndGuestInviters'                  = @{ Description = 'Only admins and users in Guest Inviter role'; Risk = 'Low' }
        'adminsGuestInvitersAndAllMembers'        = @{ Description = 'Admins, Guest Inviters, and all member users'; Risk = 'Medium' }
        'everyone'                                = @{ Description = 'Everyone including guests can invite'; Risk = 'High' }
    }

    $inviteInfo = $inviteMapping[$allowInvitesFrom]
    if (-not $inviteInfo) {
        $inviteInfo = @{ Description = "Unknown ($allowInvitesFrom)"; Risk = 'Unknown' }
    }

    $status = switch ($inviteInfo.Risk) {
        'Low'    { 'PASS' }
        'Medium' { 'WARN' }
        'High'   { 'FAIL' }
        default  { 'WARN' }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "Guest invitation setting: $($inviteInfo.Description)" `
        -Details @{
            AllowInvitesFrom = $allowInvitesFrom
            Description      = $inviteInfo.Description
            RiskLevel        = $inviteInfo.Risk
        }
}

# ── EIDTNT-005: External Collaboration Settings ─────────────────────────
function Test-InfiltrationEIDTNT005 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $crossTenantAccess = $AuditData.TenantConfig.CrossTenantAccess
    if (-not $crossTenantAccess) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cross-tenant access policy not available'
    }

    $defaultPolicy = $crossTenantAccess.default ?? $crossTenantAccess

    $inboundDefault = $defaultPolicy.b2bCollaborationInbound
    $outboundDefault = $defaultPolicy.b2bCollaborationOutbound
    $inboundDirectConnect = $defaultPolicy.b2bDirectConnectInbound
    $outboundDirectConnect = $defaultPolicy.b2bDirectConnectOutbound

    $issues = [System.Collections.Generic.List[string]]::new()

    # Check if inbound is overly permissive
    if ($inboundDefault.usersAndGroups.accessType -eq 'allowed' -and
        ($inboundDefault.usersAndGroups.targets | Where-Object { $_.target -eq 'AllUsers' })) {
        $issues.Add('Inbound B2B collaboration allows all external users by default')
    }

    # Check if outbound is overly permissive
    if ($outboundDefault.usersAndGroups.accessType -eq 'allowed' -and
        ($outboundDefault.usersAndGroups.targets | Where-Object { $_.target -eq 'AllUsers' })) {
        $issues.Add('Outbound B2B collaboration allows all users to access external tenants')
    }

    $status = if ($issues.Count -eq 0) { 'PASS' }
              elseif ($issues.Count -eq 1) { 'WARN' }
              else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "Cross-tenant access default policy reviewed, $($issues.Count) issue(s) found" `
        -Details @{
            IssueCount               = $issues.Count
            Issues                   = @($issues)
            InboundB2BCollaboration  = $inboundDefault
            OutboundB2BCollaboration = $outboundDefault
            InboundDirectConnect     = $inboundDirectConnect
            OutboundDirectConnect    = $outboundDirectConnect
        }
}

# ── EIDTNT-006: B2B Cross-Tenant Access Partners ────────────────────────
function Test-InfiltrationEIDTNT006 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $partners = $AuditData.TenantConfig.CrossTenantPartners
    if (-not $partners -or $partners.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No cross-tenant access partner configurations — default policy applies to all external tenants' `
            -Details @{ PartnerCount = 0 }
    }

    $partnerDetails = @($partners | ForEach-Object {
        @{
            TenantId                 = $_.tenantId
            IsServiceProvider        = $_.isServiceProvider
            InboundTrust             = $_.inboundTrust
            B2BCollaborationInbound  = $_.b2bCollaborationInbound
            B2BCollaborationOutbound = $_.b2bCollaborationOutbound
            B2BDirectConnectInbound  = $_.b2bDirectConnectInbound
            B2BDirectConnectOutbound = $_.b2bDirectConnectOutbound
        }
    })

    # Warn if there are many partner configurations as they increase attack surface
    $status = if ($partners.Count -le 5) { 'PASS' }
              elseif ($partners.Count -le 20) { 'WARN' }
              else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($partners.Count) cross-tenant partner configurations — review for necessity and trust level" `
        -Details @{
            PartnerCount = $partners.Count
            Partners     = @($partnerDetails | Select-Object -First 50)
        }
}

# ── EIDTNT-007: Security Defaults ────────────────────────────────────────
function Test-InfiltrationEIDTNT007 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $securityDefaults = $AuditData.TenantConfig.SecurityDefaults
    if (-not $securityDefaults) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'Security defaults policy not available' `
            -Details @{ PolicyAvailable = $false }
    }

    $isEnabled = $securityDefaults.isEnabled

    if ($isEnabled) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'Security defaults are enabled — baseline protections active' `
            -Details @{
                IsEnabled     = $true
                Description   = $securityDefaults.description
            }
    }

    # Security defaults disabled — check if CA policies exist as a replacement
    $caPolicies = $AuditData.ConditionalAccess.Policies
    $hasCAPolicies = $caPolicies -and $caPolicies.Count -gt 0
    $enabledCAPolicies = if ($hasCAPolicies) {
        @($caPolicies | Where-Object { $_.state -eq 'enabled' }).Count
    } else { 0 }

    if ($enabledCAPolicies -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue "Security defaults disabled but $enabledCAPolicies CA policies are active as replacement" `
            -Details @{
                IsEnabled         = $false
                CAReplacementCount = $enabledCAPolicies
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue 'Security defaults are disabled with no Conditional Access policies as replacement — tenant has no baseline protections' `
        -Details @{
            IsEnabled         = $false
            CAReplacementCount = 0
        }
}

# ── EIDTNT-008: License Inventory ────────────────────────────────────────
function Test-InfiltrationEIDTNT008 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $skus = $AuditData.TenantConfig.SubscribedSkus
    if (-not $skus -or $skus.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'No subscribed SKU data available' `
            -Details @{ SkuCount = 0 }
    }

    $enabledSkus = @($skus | Where-Object { $_.capabilityStatus -eq 'Enabled' })
    $suspendedSkus = @($skus | Where-Object { $_.capabilityStatus -eq 'Suspended' })
    $warningSkus = @($skus | Where-Object { $_.capabilityStatus -eq 'Warning' })

    $totalConsumed = ($enabledSkus | ForEach-Object { $_.consumedUnits } | Measure-Object -Sum).Sum
    $totalPrepaid = ($enabledSkus | ForEach-Object { $_.prepaidUnits.enabled } | Measure-Object -Sum).Sum

    # Check for premium security SKUs
    $premiumSkuPartNumbers = @('AAD_PREMIUM', 'AAD_PREMIUM_P2', 'IDENTITY_THREAT_PROTECTION',
        'EMSPREMIUM', 'EMS_E5', 'M365_E5', 'SPE_E5', 'MICROSOFT_365_E5_SECURITY')
    $hasPremiumSecurity = @($enabledSkus | Where-Object {
        $_.skuPartNumber -in $premiumSkuPartNumbers
    }).Count -gt 0

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$($enabledSkus.Count) active license SKUs, $totalConsumed consumed of $totalPrepaid total. Premium security: $hasPremiumSecurity" `
        -Details @{
            TotalSkus         = $skus.Count
            EnabledSkus       = $enabledSkus.Count
            SuspendedSkus     = $suspendedSkus.Count
            WarningSkus       = $warningSkus.Count
            TotalConsumed     = $totalConsumed
            TotalPrepaid      = $totalPrepaid
            HasPremiumSecurity = $hasPremiumSecurity
            Licenses          = @($enabledSkus | ForEach-Object {
                @{
                    SkuId            = $_.skuId
                    SkuPartNumber    = $_.skuPartNumber
                    CapabilityStatus = $_.capabilityStatus
                    ConsumedUnits    = $_.consumedUnits
                    PrepaidEnabled   = $_.prepaidUnits.enabled
                    PrepaidSuspended = $_.prepaidUnits.suspended
                    PrepaidWarning   = $_.prepaidUnits.warning
                }
            })
        }
}

# ── EIDTNT-009: Administrative Units ─────────────────────────────────────
function Test-InfiltrationEIDTNT009 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $adminUnits = $AuditData.TenantConfig.AdminUnits
    if (-not $adminUnits -or $adminUnits.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No administrative units configured' `
            -Details @{ AdminUnitCount = 0 }
    }

    $restrictedMgmt = @($adminUnits | Where-Object {
        $_.isMemberManagementRestricted -eq $true
    })

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$($adminUnits.Count) administrative units configured ($($restrictedMgmt.Count) with restricted management)" `
        -Details @{
            AdminUnitCount         = $adminUnits.Count
            RestrictedMgmtCount    = $restrictedMgmt.Count
            AdminUnits             = @($adminUnits | ForEach-Object {
                @{
                    Id                            = $_.id
                    DisplayName                   = $_.displayName
                    Description                   = $_.description
                    IsMemberManagementRestricted  = $_.isMemberManagementRestricted
                    Visibility                    = $_.visibility
                }
            })
        }
}

# ── EIDTNT-010: Custom Domains ───────────────────────────────────────────
function Test-InfiltrationEIDTNT010 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $domains = $AuditData.TenantConfig.Domains
    if (-not $domains -or $domains.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'No domain data available' `
            -Details @{ DomainCount = 0 }
    }

    $verified = @($domains | Where-Object { $_.isVerified -eq $true })
    $unverified = @($domains | Where-Object { $_.isVerified -ne $true })
    $defaultDomain = @($domains | Where-Object { $_.isDefault -eq $true })
    $initialDomains = @($domains | Where-Object { $_.isInitial -eq $true })
    $customDomains = @($domains | Where-Object { $_.isInitial -ne $true })

    $status = if ($unverified.Count -gt 0) { 'WARN' } else { 'PASS' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($domains.Count) domains: $($customDomains.Count) custom, $($verified.Count) verified, $($unverified.Count) unverified" `
        -Details @{
            TotalDomains     = $domains.Count
            CustomDomains    = $customDomains.Count
            VerifiedCount    = $verified.Count
            UnverifiedCount  = $unverified.Count
            DefaultDomain    = if ($defaultDomain.Count -gt 0) { $defaultDomain[0].id } else { 'None' }
            UnverifiedDomains = @($unverified | ForEach-Object { $_.id })
            Domains          = @($domains | ForEach-Object {
                @{
                    Id                 = $_.id
                    AuthenticationType = $_.authenticationType
                    IsVerified         = $_.isVerified
                    IsDefault          = $_.isDefault
                    IsInitial          = $_.isInitial
                    IsAdminManaged     = $_.isAdminManaged
                    SupportedServices  = @($_.supportedServices ?? @())
                }
            })
        }
}

# ── EIDTNT-011: Diagnostic Settings ─────────────────────────────────────
function Test-InfiltrationEIDTNT011 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    # Diagnostic settings (log export to Log Analytics, Event Hub, Storage Account)
    # are configured at the Azure subscription level via ARM, not directly queryable
    # from Microsoft Graph. Flag as a review item.

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Diagnostic settings verification required — ensure Entra ID sign-in and audit logs are exported to SIEM or Log Analytics' `
        -Details @{
            Note               = 'Diagnostic settings for Entra ID logs are configured via Azure Monitor (ARM). Verify through Azure Portal > Entra ID > Diagnostic settings.'
            RecommendedExports = @(
                'SignInLogs'
                'AuditLogs'
                'NonInteractiveUserSignInLogs'
                'ServicePrincipalSignInLogs'
                'ManagedIdentitySignInLogs'
                'ProvisioningLogs'
                'ADFSSignInLogs'
                'RiskyUsers'
                'UserRiskEvents'
            )
        }
}

# ── EIDTNT-012: Audit Log Retention ──────────────────────────────────────
function Test-InfiltrationEIDTNT012 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    # Audit log retention depends on the license tier:
    # - Free/P1: 7 days via Graph API, 30 days in Azure Portal
    # - P2: 30 days via Graph API
    # - Long-term retention requires export to Log Analytics or storage

    $skus = $AuditData.TenantConfig.SubscribedSkus
    $premiumP2SkuParts = @('AAD_PREMIUM_P2', 'EMS_E5', 'M365_E5', 'SPE_E5',
        'IDENTITY_THREAT_PROTECTION', 'MICROSOFT_365_E5_SECURITY')

    $hasP2 = $false
    if ($skus) {
        $hasP2 = @($skus | Where-Object {
            $_.capabilityStatus -eq 'Enabled' -and $_.skuPartNumber -in $premiumP2SkuParts
        }).Count -gt 0
    }

    $retentionDays = if ($hasP2) { 30 } else { 7 }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue "Default Entra ID audit log retention: $retentionDays days (P2: $hasP2) — verify long-term export is configured" `
        -Details @{
            HasP2License         = $hasP2
            DefaultRetentionDays = $retentionDays
            Note                 = 'For compliance and incident response, configure Diagnostic Settings to export logs to Log Analytics (90+ day retention) or Azure Storage (long-term).'
        }
}

# ── EIDTNT-013: Notification Settings ────────────────────────────────────
function Test-InfiltrationEIDTNT013 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    # Notification settings for Entra ID (security alerts, PIM notifications, etc.)
    # are not directly accessible through a single Graph API endpoint.
    # Check what we can: technical notification contacts from Organization object.

    $org = $AuditData.TenantConfig.Organization
    if (-not $org) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Organization data not available for notification settings check'
    }

    $technicalContacts = @($org.technicalNotificationMails ?? @())
    $securityContacts = @($org.securityComplianceNotificationMails ?? @())
    $privacyProfile = $org.privacyProfile

    $hasTechnical = $technicalContacts.Count -gt 0
    $hasSecurity = $securityContacts.Count -gt 0

    if (-not $hasTechnical -and -not $hasSecurity) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'No technical or security notification contacts configured' `
            -Details @{
                TechnicalContacts = @()
                SecurityContacts  = @()
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "Notification contacts: $($technicalContacts.Count) technical, $($securityContacts.Count) security" `
        -Details @{
            TechnicalContacts      = @($technicalContacts)
            SecurityContacts       = @($securityContacts)
            HasPrivacyProfile      = $null -ne $privacyProfile
            Note                   = 'Additional notification settings (PIM, Identity Protection alerts) should be verified in their respective configurations.'
        }
}
