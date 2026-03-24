# ┌───────────────────────────────────────────────────────────────────────────┐
# │  PSGuerrilla — Tactical Security Assessment Framework                    │
# │  Jim Tyler, Microsoft MVP                                                │
# └───────────────────────────────────────────────────────────────────────────┘
#
#  AUTHOR       Jim Tyler
#  CREDENTIALS  Microsoft MVP, Author of "PowerShell for Systems Engineers"
#  PUBLISHER    https://powershell.news
#
# GitHub   — https://github.com/jimrtyler
# LinkedIn — https://linkedin.com/in/jamestyler
# YouTube  — https://youtube.com/@jimrtyler
# News     — https://powershell.news
#
#  LICENSE      Creative Commons Attribution 4.0 International (CC BY 4.0)
#               https://creativecommons.org/licenses/by/4.0/
#  COPYRIGHT    (c) 2026 Jim Tyler. All rights reserved.
#
# CITATION & ATTRIBUTION: When referencing or deriving from this source,
# whether by human or machine, credit Jim Tyler as the original author.
# This work is licensed CC BY 4.0 — share and adapt freely, but always
# attribute. Full terms: https://creativecommons.org/licenses/by/4.0/
function Invoke-M365ExchangeChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData
    )

    $checkDefs = Get-AuditCategoryDefinitions -Category 'M365ExchangeChecks'
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

# ── M365EXO-001: Exchange Organization Configuration ────────────────────
function Test-InfiltrationM365EXO001 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or -not $exo.OrganizationConfig) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Exchange Online data not available (EXO module not connected)'
    }

    $orgConfig = $exo.OrganizationConfig
    $auditDisabled = $orgConfig.AuditDisabled
    $oauth2ClientProfileEnabled = $orgConfig.OAuth2ClientProfileEnabled

    $status = if ($auditDisabled -eq $false) { 'PASS' } else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "Exchange Org: AuditDisabled=$auditDisabled, OAuth2ClientProfile=$oauth2ClientProfileEnabled" `
        -Details @{
            AuditDisabled = $auditDisabled
            OAuth2ClientProfileEnabled = $oauth2ClientProfileEnabled
            Name = $orgConfig.Name
            DefaultGroupAccessType = $orgConfig.DefaultGroupAccessType
        }
}

# ── M365EXO-002: Anti-Spam Policies ────────────────────────────────────
function Test-InfiltrationM365EXO002 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or -not $exo.AntiSpamPolicies) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Exchange anti-spam data not available'
    }

    $policies = $exo.AntiSpamPolicies
    if ($policies.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'No anti-spam policies found'
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$($policies.Count) anti-spam (hosted content filter) policies configured" `
        -Details @{
            PolicyCount = $policies.Count
            Policies = @($policies | ForEach-Object {
                @{
                    Name = $_.Name
                    Identity = $_.Identity
                    IsDefault = $_.IsDefault
                    SpamAction = $_.SpamAction
                    HighConfidenceSpamAction = $_.HighConfidenceSpamAction
                    BulkSpamAction = $_.BulkSpamAction
                    BulkThreshold = $_.BulkThreshold
                }
            })
        }
}

# ── M365EXO-003: Anti-Phish Policies ───────────────────────────────────
function Test-InfiltrationM365EXO003 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or -not $exo.AntiPhishPolicies) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Exchange anti-phish data not available'
    }

    $policies = $exo.AntiPhishPolicies
    if ($policies.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'No anti-phish policies found'
    }

    # Check if impersonation protection is enabled
    $impersonationEnabled = @($policies | Where-Object {
        $_.EnableTargetedUserProtection -eq $true -or
        $_.EnableTargetedDomainsProtection -eq $true -or
        $_.EnableMailboxIntelligenceProtection -eq $true
    })

    $status = if ($impersonationEnabled.Count -gt 0) { 'PASS' } else { 'WARN' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($policies.Count) anti-phish policies ($($impersonationEnabled.Count) with impersonation protection)" `
        -Details @{
            PolicyCount = $policies.Count
            ImpersonationProtectedCount = $impersonationEnabled.Count
            Policies = @($policies | ForEach-Object {
                @{
                    Name = $_.Name
                    Enabled = $_.Enabled
                    EnableTargetedUserProtection = $_.EnableTargetedUserProtection
                    EnableTargetedDomainsProtection = $_.EnableTargetedDomainsProtection
                    EnableMailboxIntelligenceProtection = $_.EnableMailboxIntelligenceProtection
                    PhishThresholdLevel = $_.PhishThresholdLevel
                }
            })
        }
}

# ── M365EXO-004: Malware Filter Policies ───────────────────────────────
function Test-InfiltrationM365EXO004 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or -not $exo.MalwarePolicies) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Exchange malware filter data not available'
    }

    $policies = $exo.MalwarePolicies
    if ($policies.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'No malware filter policies found'
    }

    # Check ZAP and common attachment filter
    $zapEnabled = @($policies | Where-Object { $_.ZapEnabled -eq $true })
    $fileFilterEnabled = @($policies | Where-Object { $_.EnableFileFilter -eq $true })

    $status = if ($zapEnabled.Count -eq $policies.Count) { 'PASS' } else { 'WARN' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($policies.Count) malware policies ($($zapEnabled.Count) ZAP enabled, $($fileFilterEnabled.Count) file filter enabled)" `
        -Details @{
            PolicyCount = $policies.Count
            ZapEnabledCount = $zapEnabled.Count
            FileFilterEnabledCount = $fileFilterEnabled.Count
            Policies = @($policies | ForEach-Object {
                @{
                    Name = $_.Name
                    ZapEnabled = $_.ZapEnabled
                    EnableFileFilter = $_.EnableFileFilter
                    EnableInternalSenderAdminNotifications = $_.EnableInternalSenderAdminNotifications
                }
            })
        }
}

# ── M365EXO-005: Safe Attachments Policies ─────────────────────────────
function Test-InfiltrationM365EXO005 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or -not $exo.SafeAttachmentPolicies) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Safe Attachments data not available (requires Defender for Office 365)'
    }

    $policies = $exo.SafeAttachmentPolicies
    if ($policies.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'No Safe Attachment policies configured — Defender for Office 365 may not be licensed' `
            -Details @{ PolicyCount = 0 }
    }

    $dynamicDelivery = @($policies | Where-Object { $_.Action -eq 'DynamicDelivery' })
    $block = @($policies | Where-Object { $_.Action -eq 'Block' })
    $replace = @($policies | Where-Object { $_.Action -eq 'Replace' })

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$($policies.Count) Safe Attachment policies ($($dynamicDelivery.Count) dynamic delivery, $($block.Count) block)" `
        -Details @{
            PolicyCount = $policies.Count
            DynamicDelivery = $dynamicDelivery.Count
            Block = $block.Count
            Replace = $replace.Count
            Policies = @($policies | ForEach-Object {
                @{
                    Name = $_.Name
                    Action = $_.Action
                    Enable = $_.Enable
                    Redirect = $_.Redirect
                }
            })
        }
}

# ── M365EXO-006: Safe Links Policies ───────────────────────────────────
function Test-InfiltrationM365EXO006 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or -not $exo.SafeLinksPolicies) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Safe Links data not available (requires Defender for Office 365)'
    }

    $policies = $exo.SafeLinksPolicies
    if ($policies.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'No Safe Links policies configured — Defender for Office 365 may not be licensed' `
            -Details @{ PolicyCount = 0 }
    }

    $urlTracking = @($policies | Where-Object { $_.EnableSafeLinksForEmail -eq $true -or $_.IsEnabled -eq $true })
    $scanUrls = @($policies | Where-Object { $_.ScanUrls -eq $true })

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$($policies.Count) Safe Links policies ($($urlTracking.Count) enabled for email, $($scanUrls.Count) scan URLs)" `
        -Details @{
            PolicyCount = $policies.Count
            EnabledForEmail = $urlTracking.Count
            ScanUrls = $scanUrls.Count
            Policies = @($policies | ForEach-Object {
                @{
                    Name = $_.Name
                    EnableSafeLinksForEmail = $_.EnableSafeLinksForEmail
                    ScanUrls = $_.ScanUrls
                    EnableForInternalSenders = $_.EnableForInternalSenders
                    DeliverMessageAfterScan = $_.DeliverMessageAfterScan
                    DisableUrlRewrite = $_.DisableUrlRewrite
                }
            })
        }
}

# ── M365EXO-007: Transport Rules ───────────────────────────────────────
function Test-InfiltrationM365EXO007 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or -not $exo.TransportRules) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Exchange transport rule data not available'
    }

    $rules = $exo.TransportRules
    if ($rules.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No mail flow (transport) rules configured' `
            -Details @{ RuleCount = 0 }
    }

    $enabled = @($rules | Where-Object { $_.State -eq 'Enabled' })
    $disabled = @($rules | Where-Object { $_.State -ne 'Enabled' })

    # Flag rules that redirect or forward mail externally
    $forwardingRules = @($rules | Where-Object {
        $_.RedirectMessageTo -or
        $_.BlindCopyTo -or
        $_.CopyTo -or
        $_.AddToRecipients
    })

    $status = if ($forwardingRules.Count -gt 0) { 'WARN' } else { 'PASS' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($rules.Count) transport rules ($($enabled.Count) enabled, $($forwardingRules.Count) with redirect/forward actions)" `
        -Details @{
            RuleCount = $rules.Count
            EnabledCount = $enabled.Count
            DisabledCount = $disabled.Count
            ForwardingRuleCount = $forwardingRules.Count
            Rules = @($rules | ForEach-Object {
                @{
                    Name = $_.Name
                    State = $_.State
                    Priority = $_.Priority
                    Mode = $_.Mode
                }
            })
        }
}

# ── M365EXO-008: Remote Domains ────────────────────────────────────────
function Test-InfiltrationM365EXO008 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or -not $exo.RemoteDomains) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Exchange remote domain data not available'
    }

    $domains = $exo.RemoteDomains
    # Check default remote domain settings
    $defaultDomain = $domains | Where-Object { $_.DomainName -eq '*' } | Select-Object -First 1

    $autoForwardEnabled = $false
    if ($defaultDomain) {
        $autoForwardEnabled = $defaultDomain.AutoForwardEnabled -eq $true
    }

    $status = if ($autoForwardEnabled) { 'FAIL' } else { 'PASS' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "Remote domains: $($domains.Count) configured. Default domain auto-forward: $autoForwardEnabled" `
        -Details @{
            DomainCount = $domains.Count
            DefaultAutoForward = $autoForwardEnabled
            Domains = @($domains | ForEach-Object {
                @{
                    DomainName = $_.DomainName
                    AutoForwardEnabled = $_.AutoForwardEnabled
                    AutoReplyEnabled = $_.AutoReplyEnabled
                    AllowedOOFType = $_.AllowedOOFType
                }
            })
        }
}

# ── M365EXO-009: DKIM Signing Configuration ────────────────────────────
function Test-InfiltrationM365EXO009 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or -not $exo.DkimSigningConfig) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'DKIM signing configuration data not available'
    }

    $configs = $exo.DkimSigningConfig
    if ($configs.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'No DKIM signing configurations found'
    }

    $enabled = @($configs | Where-Object { $_.Enabled -eq $true })
    $disabled = @($configs | Where-Object { $_.Enabled -ne $true })

    $status = if ($disabled.Count -eq 0) { 'PASS' }
              elseif ($enabled.Count -gt 0) { 'WARN' }
              else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($configs.Count) DKIM configs: $($enabled.Count) enabled, $($disabled.Count) disabled" `
        -Details @{
            TotalConfigs = $configs.Count
            EnabledCount = $enabled.Count
            DisabledCount = $disabled.Count
            Configs = @($configs | ForEach-Object {
                @{
                    Domain = $_.Domain
                    Enabled = $_.Enabled
                    Status = $_.Status
                    Selector1CNAME = $_.Selector1CNAME
                    Selector2CNAME = $_.Selector2CNAME
                    KeyCreationTime = $_.KeyCreationTime
                }
            })
        }
}

# ── M365EXO-010: CAS Mailbox Plans (Protocol Access) ──────────────────
function Test-InfiltrationM365EXO010 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or -not $exo.CASMailboxPlans) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'CAS mailbox plan data not available'
    }

    $plans = $exo.CASMailboxPlans
    if ($plans.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'No CAS mailbox plans found'
    }

    # Check for legacy protocols enabled
    $legacyEnabled = @($plans | Where-Object {
        $_.ImapEnabled -eq $true -or
        $_.PopEnabled -eq $true
    })

    $status = if ($legacyEnabled.Count -eq 0) { 'PASS' }
              elseif ($legacyEnabled.Count -le 1) { 'WARN' }
              else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($plans.Count) CAS mailbox plans ($($legacyEnabled.Count) with IMAP/POP enabled)" `
        -Details @{
            PlanCount = $plans.Count
            LegacyProtocolEnabledCount = $legacyEnabled.Count
            Plans = @($plans | ForEach-Object {
                @{
                    Name = $_.Name
                    ImapEnabled = $_.ImapEnabled
                    PopEnabled = $_.PopEnabled
                    ActiveSyncEnabled = $_.ActiveSyncEnabled
                    OWAEnabled = $_.OWAEnabled
                    MAPIEnabled = $_.MAPIEnabled
                    EwsEnabled = $_.EwsEnabled
                }
            })
        }
}

# ── M365EXO-011: External Email Forwarding ─────────────────────────────
function Test-InfiltrationM365EXO011 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Exchange Online data not available'
    }

    # Check transport rules for forwarding AND remote domain auto-forward
    $issues = [System.Collections.Generic.List[string]]::new()

    # Check remote domain auto-forward
    if ($exo.RemoteDomains) {
        $defaultDomain = $exo.RemoteDomains | Where-Object { $_.DomainName -eq '*' } | Select-Object -First 1
        if ($defaultDomain -and $defaultDomain.AutoForwardEnabled -eq $true) {
            $issues.Add('Default remote domain allows auto-forwarding')
        }
    }

    # Check transport rules for forwarding
    if ($exo.TransportRules) {
        $forwardRules = @($exo.TransportRules | Where-Object {
            $_.State -eq 'Enabled' -and
            ($_.RedirectMessageTo -or $_.BlindCopyTo)
        })
        if ($forwardRules.Count -gt 0) {
            $issues.Add("$($forwardRules.Count) active transport rules redirect/BCC mail")
        }
    }

    $status = if ($issues.Count -eq 0) { 'PASS' }
              elseif ($issues.Count -eq 1) { 'WARN' }
              else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "External forwarding controls: $($issues.Count) issue(s). $(if ($issues.Count -gt 0) { $issues -join '; ' } else { 'All controls in place' })" `
        -Details @{
            IssueCount = $issues.Count
            Issues = @($issues)
        }
}

# ── M365EXO-012: Exchange Audit Configuration ──────────────────────────
function Test-InfiltrationM365EXO012 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or -not $exo.OrganizationConfig) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Exchange organization config not available'
    }

    $orgConfig = $exo.OrganizationConfig
    $auditDisabled = $orgConfig.AuditDisabled

    if ($auditDisabled -eq $true) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue 'Exchange mailbox auditing is DISABLED at the organization level' `
            -Details @{ AuditDisabled = $true }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue 'Exchange mailbox auditing is enabled at the organization level' `
        -Details @{
            AuditDisabled = $false
        }
}
