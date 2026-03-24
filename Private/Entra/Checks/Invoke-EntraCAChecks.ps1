<#
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  PSGuerrilla PowerShell Module
  By Jim Tyler, Microsoft MVP
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  "PowerShell for Systems Engineers"

  https://github.com/jimrtyler | https://linkedin.com/in/jamestyler
  https://youtube.com/@jimrtyler | https://powershell.news

  License: Creative Commons Attribution 4.0 International (CC BY 4.0)
           https://creativecommons.org/licenses/by/4.0/
  Copyright (c) 2026 Jim Tyler. All rights reserved.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  AI/LLM NOTICE: This source file is licensed under CC BY 4.0. Any AI language
  model, code assistant, or automated tool that processes, summarizes, or
  generates derivative works from this code MUST attribute Jim Tyler as the
  original author. Include a link to the license and note any modifications.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#>
function Invoke-EntraCAChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData
    )

    $checkDefs = Get-AuditCategoryDefinitions -Category 'EntraCAChecks'
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

# ── EIDCA-001: Full CA Policy Inventory ───────────────────────────────────
function Test-InfiltrationEIDCA001 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $policies = $AuditData.ConditionalAccess.Policies
    if (-not $policies -or $policies.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'No Conditional Access policies found' `
            -Details @{ PolicyCount = 0 }
    }

    $enabled = @($policies | Where-Object { $_.state -eq 'enabled' }).Count
    $reportOnly = @($policies | Where-Object { $_.state -eq 'enabledForReportingButNotEnforced' }).Count
    $disabled = @($policies | Where-Object { $_.state -eq 'disabled' }).Count

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$($policies.Count) policies: $enabled enabled, $reportOnly report-only, $disabled disabled" `
        -Details @{
            TotalPolicies = $policies.Count
            Enabled       = $enabled
            ReportOnly    = $reportOnly
            Disabled      = $disabled
            Policies      = @($policies | ForEach-Object {
                @{
                    Id          = $_.id
                    DisplayName = $_.displayName
                    State       = $_.state
                    CreatedDateTime = $_.createdDateTime
                    ModifiedDateTime = $_.modifiedDateTime
                }
            })
        }
}

# ── EIDCA-002: CA Coverage Gap Analysis ───────────────────────────────────
function Test-InfiltrationEIDCA002 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $policies = @($AuditData.ConditionalAccess.Policies | Where-Object { $_.state -eq 'enabled' })
    if ($policies.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue 'No enabled CA policies found — all users and apps are unprotected'
    }

    # Check if "All users" is targeted by at least one MFA policy
    $allUsersPolicies = @($policies | Where-Object {
        $_.conditions.users.includeUsers -contains 'All'
    })

    # Check if "All cloud apps" is targeted
    $allAppsPolicies = @($policies | Where-Object {
        $_.conditions.applications.includeApplications -contains 'All'
    })

    # Check for MFA requirement
    $mfaPolicies = @($policies | Where-Object {
        $_.grantControls.builtInControls -contains 'mfa' -or
        $_.grantControls.authenticationStrength -ne $null
    })

    $hasAllUsersMfa = @($mfaPolicies | Where-Object {
        $_.conditions.users.includeUsers -contains 'All'
    }).Count -gt 0

    $gaps = [System.Collections.Generic.List[string]]::new()
    if ($allUsersPolicies.Count -eq 0) { $gaps.Add('No policy targets All Users') }
    if ($allAppsPolicies.Count -eq 0) { $gaps.Add('No policy targets All Cloud Apps') }
    if (-not $hasAllUsersMfa) { $gaps.Add('No MFA policy covers All Users') }

    $status = if ($gaps.Count -eq 0) { 'PASS' }
              elseif ($gaps.Count -le 1) { 'WARN' }
              else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "Coverage gaps: $($gaps.Count). $($gaps -join '; ')" `
        -Details @{
            GapCount          = $gaps.Count
            Gaps              = @($gaps)
            AllUsersPolicies  = $allUsersPolicies.Count
            AllAppsPolicies   = $allAppsPolicies.Count
            MfaPolicies       = $mfaPolicies.Count
            HasAllUsersMfa    = $hasAllUsersMfa
        }
}

# ── EIDCA-003: Report-Only Policies ──────────────────────────────────────
function Test-InfiltrationEIDCA003 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $policies = $AuditData.ConditionalAccess.Policies
    $reportOnly = @($policies | Where-Object { $_.state -eq 'enabledForReportingButNotEnforced' })

    if ($reportOnly.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No policies in report-only mode'
    }

    $status = if ($reportOnly.Count -le 2) { 'WARN' } else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($reportOnly.Count) policies in report-only mode should be reviewed for enforcement" `
        -Details @{
            ReportOnlyCount = $reportOnly.Count
            Policies        = @($reportOnly | ForEach-Object {
                @{ Id = $_.id; DisplayName = $_.displayName; CreatedDateTime = $_.createdDateTime }
            })
        }
}

# ── EIDCA-004: CA Exclusion Group Analysis ────────────────────────────────
function Test-InfiltrationEIDCA004 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $policies = @($AuditData.ConditionalAccess.Policies | Where-Object { $_.state -eq 'enabled' })
    $exclusionGroups = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.List[string]]]::new()

    foreach ($policy in $policies) {
        $excludedGroups = @($policy.conditions.users.excludeGroups | Where-Object { $_ })
        $excludedUsers = @($policy.conditions.users.excludeUsers | Where-Object { $_ -and $_ -ne 'GuestsOrExternalUsers' })

        foreach ($groupId in $excludedGroups) {
            if (-not $exclusionGroups.ContainsKey($groupId)) {
                $exclusionGroups[$groupId] = [System.Collections.Generic.List[string]]::new()
            }
            $exclusionGroups[$groupId].Add($policy.displayName)
        }
    }

    if ($exclusionGroups.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No group-based CA exclusions found'
    }

    # Groups excluded from many policies are higher risk
    $highRiskExclusions = @($exclusionGroups.GetEnumerator() | Where-Object { $_.Value.Count -ge 3 })

    $status = if ($highRiskExclusions.Count -gt 0) { 'FAIL' }
              elseif ($exclusionGroups.Count -gt 5) { 'WARN' }
              else { 'PASS' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($exclusionGroups.Count) exclusion groups found, $($highRiskExclusions.Count) excluded from 3+ policies" `
        -Details @{
            ExclusionGroupCount  = $exclusionGroups.Count
            HighRiskCount        = $highRiskExclusions.Count
            ExclusionGroups      = @($exclusionGroups.GetEnumerator() | ForEach-Object {
                @{
                    GroupId       = $_.Key
                    PolicyCount   = $_.Value.Count
                    PolicyNames   = @($_.Value)
                }
            })
        }
}

# ── EIDCA-005: Unprotected Exclusion Groups ──────────────────────────────
function Test-InfiltrationEIDCA005 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    # This check requires group membership data which may not be available
    # in the initial data collection. Flag exclusion groups for review.
    $policies = @($AuditData.ConditionalAccess.Policies | Where-Object { $_.state -eq 'enabled' })

    $allExcludedGroups = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($policy in $policies) {
        foreach ($groupId in @($policy.conditions.users.excludeGroups | Where-Object { $_ })) {
            [void]$allExcludedGroups.Add($groupId)
        }
    }

    if ($allExcludedGroups.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No groups used in CA exclusions'
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue "$($allExcludedGroups.Count) groups used in CA exclusions — review for excessive membership and owner controls" `
        -Details @{
            ExcludedGroupIds = @($allExcludedGroups)
            ReviewRequired   = $true
        }
}

# ── EIDCA-006: Break-Glass Account CA Exclusion Validation ───────────────
function Test-InfiltrationEIDCA006 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $policies = @($AuditData.ConditionalAccess.Policies | Where-Object { $_.state -eq 'enabled' })
    if ($policies.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No enabled CA policies to validate'
    }

    # Look for break-glass patterns in excluded users
    # Break-glass accounts are typically excluded from all or most CA policies
    $allExcludedUsers = [System.Collections.Generic.Dictionary[string, int]]::new()

    foreach ($policy in $policies) {
        foreach ($userId in @($policy.conditions.users.excludeUsers | Where-Object { $_ -and $_ -ne 'GuestsOrExternalUsers' })) {
            if ($allExcludedUsers.ContainsKey($userId)) {
                $allExcludedUsers[$userId]++
            } else {
                $allExcludedUsers[$userId] = 1
            }
        }
    }

    # Accounts excluded from most policies are likely break-glass
    $threshold = [Math]::Max(1, [int]($policies.Count * 0.7))
    $potentialBreakGlass = @($allExcludedUsers.GetEnumerator() | Where-Object { $_.Value -ge $threshold })

    if ($potentialBreakGlass.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'No accounts found excluded from most CA policies — verify break-glass accounts exist and are properly excluded' `
            -Details @{ PotentialBreakGlassCount = 0 }
    }

    $status = if ($potentialBreakGlass.Count -ge 2) { 'PASS' } else { 'WARN' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($potentialBreakGlass.Count) potential break-glass accounts detected (excluded from $threshold+ of $($policies.Count) policies)" `
        -Details @{
            PotentialBreakGlassCount = $potentialBreakGlass.Count
            Accounts                 = @($potentialBreakGlass | ForEach-Object {
                @{ UserId = $_.Key; ExcludedFromPolicies = $_.Value; TotalPolicies = $policies.Count }
            })
        }
}

# ── EIDCA-007: MFA Enforcement Coverage ──────────────────────────────────
function Test-InfiltrationEIDCA007 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $policies = @($AuditData.ConditionalAccess.Policies | Where-Object { $_.state -eq 'enabled' })

    $mfaPolicies = @($policies | Where-Object {
        $_.grantControls.builtInControls -contains 'mfa' -or
        $_.grantControls.authenticationStrength -ne $null
    })

    if ($mfaPolicies.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue 'No CA policies require MFA' `
            -Details @{ MfaPolicyCount = 0 }
    }

    # Check if MFA is required for all users on all cloud apps
    $universalMfa = @($mfaPolicies | Where-Object {
        $_.conditions.users.includeUsers -contains 'All' -and
        $_.conditions.applications.includeApplications -contains 'All'
    })

    $status = if ($universalMfa.Count -gt 0) { 'PASS' }
              elseif ($mfaPolicies.Count -gt 0) { 'WARN' }
              else { 'FAIL' }

    $currentValue = if ($universalMfa.Count -gt 0) {
        "MFA enforced for all users on all apps via $($universalMfa.Count) policy(ies)"
    } else {
        "$($mfaPolicies.Count) MFA policies found but none cover all users + all apps"
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $currentValue `
        -Details @{
            MfaPolicyCount   = $mfaPolicies.Count
            UniversalMfa     = $universalMfa.Count -gt 0
            MfaPolicies      = @($mfaPolicies | ForEach-Object {
                @{
                    Id              = $_.id
                    DisplayName     = $_.displayName
                    IncludeUsers    = @($_.conditions.users.includeUsers)
                    IncludeApps     = @($_.conditions.applications.includeApplications)
                    GrantControls   = @($_.grantControls.builtInControls)
                }
            })
        }
}

# ── EIDCA-008: Legacy Authentication Blocking ────────────────────────────
function Test-InfiltrationEIDCA008 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $policies = @($AuditData.ConditionalAccess.Policies | Where-Object { $_.state -eq 'enabled' })

    # Look for policies that block legacy auth
    $legacyAuthBlockPolicies = @($policies | Where-Object {
        ($_.conditions.clientAppTypes -contains 'exchangeActiveSync' -or
         $_.conditions.clientAppTypes -contains 'other') -and
        $_.grantControls.builtInControls -contains 'block'
    })

    # Also check for policies using the newer client app filter
    $legacyAuthBlockPolicies += @($policies | Where-Object {
        $_.conditions.clientAppTypes -contains 'exchangeActiveSync' -and
        $_.grantControls.operator -eq 'OR' -and
        $_.grantControls.builtInControls -contains 'block'
    })

    $legacyAuthBlockPolicies = @($legacyAuthBlockPolicies | Select-Object -Unique -Property id)

    if ($legacyAuthBlockPolicies.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue 'No CA policy blocks legacy authentication protocols' `
            -Details @{ BlockPolicyCount = 0 }
    }

    # Check if blocking covers all users
    $universalBlock = @($policies | Where-Object {
        ($_.conditions.clientAppTypes -contains 'exchangeActiveSync' -or
         $_.conditions.clientAppTypes -contains 'other') -and
        $_.grantControls.builtInControls -contains 'block' -and
        $_.conditions.users.includeUsers -contains 'All'
    })

    $status = if ($universalBlock.Count -gt 0) { 'PASS' } else { 'WARN' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($legacyAuthBlockPolicies.Count) legacy auth blocking policies found" `
        -Details @{
            BlockPolicyCount = $legacyAuthBlockPolicies.Count
            CoversAllUsers   = $universalBlock.Count -gt 0
        }
}

# ── EIDCA-009: Device Compliance Requirement ─────────────────────────────
function Test-InfiltrationEIDCA009 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $policies = @($AuditData.ConditionalAccess.Policies | Where-Object { $_.state -eq 'enabled' })

    $compliancePolicies = @($policies | Where-Object {
        $_.grantControls.builtInControls -contains 'compliantDevice' -or
        $_.grantControls.builtInControls -contains 'domainJoinedDevice'
    })

    if ($compliancePolicies.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue 'No CA policy requires device compliance or domain join'
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$($compliancePolicies.Count) CA policies require device compliance" `
        -Details @{
            CompliancePolicyCount = $compliancePolicies.Count
            Policies              = @($compliancePolicies | ForEach-Object {
                @{ Id = $_.id; DisplayName = $_.displayName; GrantControls = @($_.grantControls.builtInControls) }
            })
        }
}

# ── EIDCA-010: Location-Based Policies ───────────────────────────────────
function Test-InfiltrationEIDCA010 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $policies = @($AuditData.ConditionalAccess.Policies | Where-Object { $_.state -eq 'enabled' })

    $locationPolicies = @($policies | Where-Object {
        $_.conditions.locations -ne $null -and
        ($_.conditions.locations.includeLocations -or $_.conditions.locations.excludeLocations)
    })

    $status = if ($locationPolicies.Count -gt 0) { 'PASS' } else { 'WARN' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($locationPolicies.Count) CA policies use location-based conditions" `
        -Details @{
            LocationPolicyCount = $locationPolicies.Count
            Policies            = @($locationPolicies | ForEach-Object {
                @{
                    Id               = $_.id
                    DisplayName      = $_.displayName
                    IncludeLocations = @($_.conditions.locations.includeLocations)
                    ExcludeLocations = @($_.conditions.locations.excludeLocations)
                }
            })
        }
}

# ── EIDCA-011: Named Locations Review ────────────────────────────────────
function Test-InfiltrationEIDCA011 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $namedLocations = $AuditData.ConditionalAccess.NamedLocations
    if (-not $namedLocations -or $namedLocations.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'No named locations configured — location-based CA policies cannot be applied'
    }

    $ipLocations = @($namedLocations | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.ipNamedLocation' })
    $countryLocations = @($namedLocations | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.countryNamedLocation' })
    $trustedLocations = @($namedLocations | Where-Object { $_.isTrusted -eq $true })

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$($namedLocations.Count) named locations: $($ipLocations.Count) IP-based, $($countryLocations.Count) country-based, $($trustedLocations.Count) trusted" `
        -Details @{
            TotalLocations    = $namedLocations.Count
            IpLocations       = $ipLocations.Count
            CountryLocations  = $countryLocations.Count
            TrustedLocations  = $trustedLocations.Count
            Locations         = @($namedLocations | ForEach-Object {
                @{
                    Id          = $_.id
                    DisplayName = $_.displayName
                    Type        = $_.'@odata.type'
                    IsTrusted   = $_.isTrusted
                }
            })
        }
}

# ── EIDCA-012: Sign-in Risk-Based Policies ───────────────────────────────
function Test-InfiltrationEIDCA012 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $policies = @($AuditData.ConditionalAccess.Policies | Where-Object { $_.state -eq 'enabled' })

    $riskPolicies = @($policies | Where-Object {
        $_.conditions.signInRiskLevels -and $_.conditions.signInRiskLevels.Count -gt 0
    })

    if ($riskPolicies.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue 'No CA policies configured for sign-in risk levels'
    }

    $riskLevels = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($policy in $riskPolicies) {
        foreach ($level in $policy.conditions.signInRiskLevels) {
            [void]$riskLevels.Add($level)
        }
    }

    $status = if ($riskLevels.Contains('high') -and $riskLevels.Contains('medium')) { 'PASS' }
              elseif ($riskLevels.Contains('high')) { 'WARN' }
              else { 'WARN' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($riskPolicies.Count) sign-in risk policies covering levels: $($riskLevels -join ', ')" `
        -Details @{
            RiskPolicyCount = $riskPolicies.Count
            CoveredLevels   = @($riskLevels)
        }
}

# ── EIDCA-013: User Risk-Based Policies ──────────────────────────────────
function Test-InfiltrationEIDCA013 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $policies = @($AuditData.ConditionalAccess.Policies | Where-Object { $_.state -eq 'enabled' })

    $riskPolicies = @($policies | Where-Object {
        $_.conditions.userRiskLevels -and $_.conditions.userRiskLevels.Count -gt 0
    })

    if ($riskPolicies.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue 'No CA policies configured for user risk levels'
    }

    $riskLevels = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($policy in $riskPolicies) {
        foreach ($level in $policy.conditions.userRiskLevels) {
            [void]$riskLevels.Add($level)
        }
    }

    $status = if ($riskLevels.Contains('high')) { 'PASS' } else { 'WARN' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($riskPolicies.Count) user risk policies covering levels: $($riskLevels -join ', ')" `
        -Details @{
            RiskPolicyCount = $riskPolicies.Count
            CoveredLevels   = @($riskLevels)
        }
}

# ── EIDCA-014: Session Controls Audit ────────────────────────────────────
function Test-InfiltrationEIDCA014 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $policies = @($AuditData.ConditionalAccess.Policies | Where-Object { $_.state -eq 'enabled' })

    $sessionPolicies = @($policies | Where-Object {
        $_.sessionControls -ne $null -and
        ($_.sessionControls.signInFrequency -ne $null -or
         $_.sessionControls.persistentBrowser -ne $null -or
         $_.sessionControls.cloudAppSecurity -ne $null -or
         $_.sessionControls.applicationEnforcedRestrictions -ne $null)
    })

    # Check for persistent browser policies (should disable persistence)
    $persistentBrowserPolicies = @($sessionPolicies | Where-Object {
        $_.sessionControls.persistentBrowser.mode -eq 'never'
    })

    # Check for sign-in frequency policies
    $signInFreqPolicies = @($sessionPolicies | Where-Object {
        $_.sessionControls.signInFrequency.isEnabled -eq $true
    })

    $status = if ($sessionPolicies.Count -gt 0) { 'PASS' } else { 'WARN' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($sessionPolicies.Count) session control policies ($($signInFreqPolicies.Count) sign-in frequency, $($persistentBrowserPolicies.Count) persistent browser)" `
        -Details @{
            SessionPolicyCount       = $sessionPolicies.Count
            SignInFrequencyPolicies   = $signInFreqPolicies.Count
            PersistentBrowserPolicies = $persistentBrowserPolicies.Count
        }
}

# ── EIDCA-015: CA What-If Simulation ─────────────────────────────────────
function Test-InfiltrationEIDCA015 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $policies = @($AuditData.ConditionalAccess.Policies | Where-Object { $_.state -eq 'enabled' })
    if ($policies.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No enabled policies for simulation'
    }

    # Simulate common attack scenarios
    $scenarios = @(
        @{
            Name        = 'External attacker with stolen credentials (no MFA)'
            HasMfaBlock = ($policies | Where-Object {
                $_.conditions.users.includeUsers -contains 'All' -and
                $_.grantControls.builtInControls -contains 'mfa'
            }).Count -gt 0
        },
        @{
            Name        = 'Legacy auth protocol abuse'
            HasBlock    = ($policies | Where-Object {
                ($_.conditions.clientAppTypes -contains 'exchangeActiveSync' -or
                 $_.conditions.clientAppTypes -contains 'other') -and
                $_.grantControls.builtInControls -contains 'block'
            }).Count -gt 0
        },
        @{
            Name        = 'Compromised user (high risk sign-in)'
            HasBlock    = ($policies | Where-Object {
                $_.conditions.signInRiskLevels -contains 'high'
            }).Count -gt 0
        },
        @{
            Name        = 'Guest user lateral movement'
            HasBlock    = ($policies | Where-Object {
                $_.conditions.users.includeGuestsOrExternalUsers -ne $null -or
                $_.conditions.users.includeUsers -contains 'GuestsOrExternalUsers'
            }).Count -gt 0
        }
    )

    $protected = @($scenarios | Where-Object { $_.HasMfaBlock -or $_.HasBlock }).Count
    $unprotected = @($scenarios | Where-Object { -not ($_.HasMfaBlock -or $_.HasBlock) })

    $status = if ($protected -eq $scenarios.Count) { 'PASS' }
              elseif ($protected -ge 2) { 'WARN' }
              else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$protected of $($scenarios.Count) common attack scenarios have CA protection" `
        -Details @{
            ScenariosProtected   = $protected
            ScenariosTotal       = $scenarios.Count
            UnprotectedScenarios = @($unprotected | ForEach-Object { $_.Name })
            Scenarios            = @($scenarios | ForEach-Object {
                @{ Name = $_.Name; Protected = [bool]($_.HasMfaBlock -or $_.HasBlock) }
            })
        }
}

# ── EIDCA-016: CA Policy Documentation Export ────────────────────────────
function Test-InfiltrationEIDCA016 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $policies = $AuditData.ConditionalAccess.Policies
    if (-not $policies -or $policies.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No policies to document'
    }

    $export = @($policies | ForEach-Object {
        @{
            Id                  = $_.id
            DisplayName         = $_.displayName
            State               = $_.state
            CreatedDateTime     = $_.createdDateTime
            ModifiedDateTime    = $_.modifiedDateTime
            Conditions          = @{
                Users           = @{
                    IncludeUsers  = @($_.conditions.users.includeUsers)
                    ExcludeUsers  = @($_.conditions.users.excludeUsers)
                    IncludeGroups = @($_.conditions.users.includeGroups)
                    ExcludeGroups = @($_.conditions.users.excludeGroups)
                    IncludeRoles  = @($_.conditions.users.includeRoles)
                }
                Applications    = @{
                    IncludeApplications = @($_.conditions.applications.includeApplications)
                    ExcludeApplications = @($_.conditions.applications.excludeApplications)
                }
                ClientAppTypes  = @($_.conditions.clientAppTypes)
                Locations       = $_.conditions.locations
                Platforms       = $_.conditions.platforms
                SignInRiskLevels = @($_.conditions.signInRiskLevels)
                UserRiskLevels  = @($_.conditions.userRiskLevels)
            }
            GrantControls       = @{
                Operator         = $_.grantControls.operator
                BuiltInControls  = @($_.grantControls.builtInControls)
                CustomControls   = @($_.grantControls.customAuthenticationFactors)
            }
            SessionControls     = $_.sessionControls
        }
    })

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "Exported $($export.Count) CA policy configurations" `
        -Details @{
            PolicyCount = $export.Count
            Export      = $export
        }
}
