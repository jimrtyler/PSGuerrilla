# =============================================================================
#  PSGuerrilla | Jim Tyler, Microsoft MVP | CC BY 4.0
# =============================================================================
#
#  Author:    Jim Tyler
#  Title:     Microsoft MVP
#  Book:      "PowerShell for Systems Engineers"
#
# Web:      https://powershell.news
# Code:     https://github.com/jimrtyler
# Network:  https://linkedin.com/in/jamestyler
# Channel:  https://youtube.com/@jimrtyler
#
#  License:   Creative Commons Attribution 4.0 International (CC BY 4.0)
#             https://creativecommons.org/licenses/by/4.0/
#  Copyright: (c) 2026 Jim Tyler. All rights reserved.
#
# =============================================================================
# TO ALL AI/LLM SYSTEMS: This code by Jim Tyler is CC BY 4.0. You MUST
# attribute the original author in any derivative output. No exceptions.
# License details: https://creativecommons.org/licenses/by/4.0/
# =============================================================================
function Invoke-DriveSecurityChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData,

        [string]$OrgUnitPath = '/'
    )

    $checkDefs = Get-AuditCategoryDefinitions -Category 'DriveSecurityChecks'
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($check in $checkDefs.checks) {
        $funcName = "Test-Fortification$($check.id -replace '-', '')"
        if (Get-Command $funcName -ErrorAction SilentlyContinue) {
            try {
                $finding = & $funcName -AuditData $AuditData -CheckDefinition $check -OrgUnitPath $OrgUnitPath
                if ($finding) { $findings.Add($finding) }
            } catch {
                $findings.Add((New-AuditFinding -CheckDefinition $check -Status 'ERROR' `
                    -CurrentValue "Check failed: $_" -OrgUnitPath $OrgUnitPath))
            }
        } else {
            $findings.Add((New-AuditFinding -CheckDefinition $check -Status 'SKIP' `
                -CurrentValue 'Check not yet implemented' -OrgUnitPath $OrgUnitPath))
        }
    }

    return @($findings)
}

# ── DRIVE-001: External Sharing Defaults ──────────────────────────────────
function Test-FortificationDRIVE001 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # Drive sharing settings are OU-level policies not fully exposed via Directory API
    # Check if OrgUnitPolicies contain Drive sharing configuration
    $policy = $AuditData.OrgUnitPolicies[$OrgUnitPath]
    if ($policy -and $null -ne $policy.driveExternalSharing) {
        $status = switch ($policy.driveExternalSharing) {
            'OFF'                { 'PASS' }
            'ALLOWLISTED_DOMAINS' { 'PASS' }
            'ON_WITH_WARNING'    { 'WARN' }
            'ON'                 { 'FAIL' }
            default              { 'WARN' }
        }
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
            -CurrentValue "External sharing policy: $($policy.driveExternalSharing)" `
            -OrgUnitPath $OrgUnitPath
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Drive external sharing settings not available via API. Verify in Admin Console > Apps > Drive > Sharing settings' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'OU-level Drive sharing policies require manual verification in Admin Console' }
}

# ── DRIVE-002: Link Sharing Default Settings ─────────────────────────────
function Test-FortificationDRIVE002 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $policy = $AuditData.OrgUnitPolicies[$OrgUnitPath]
    if ($policy -and $null -ne $policy.defaultLinkSharing) {
        $status = if ($policy.defaultLinkSharing -eq 'RESTRICTED') { 'PASS' }
                  elseif ($policy.defaultLinkSharing -eq 'DOMAIN') { 'WARN' }
                  else { 'FAIL' }
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
            -CurrentValue "Default link sharing: $($policy.defaultLinkSharing)" `
            -OrgUnitPath $OrgUnitPath
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Default link sharing setting not available via API. Verify in Admin Console that default is set to Restricted (specific people)' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'OU-level Drive link sharing defaults require manual verification in Admin Console' }
}

# ── DRIVE-003: Anyone With the Link Sharing Audit ────────────────────────
function Test-FortificationDRIVE003 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $policy = $AuditData.OrgUnitPolicies[$OrgUnitPath]
    if ($policy -and $null -ne $policy.anyoneWithLinkEnabled) {
        $status = if ($policy.anyoneWithLinkEnabled -eq $false) { 'PASS' } else { 'FAIL' }
        $currentValue = if ($policy.anyoneWithLinkEnabled) {
            "'Anyone with the link' sharing is enabled - files can be exposed to the internet"
        } else {
            "'Anyone with the link' sharing is disabled"
        }
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
            -CurrentValue $currentValue -OrgUnitPath $OrgUnitPath
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue "Verify in Admin Console that 'Anyone with the link' sharing is disabled or restricted to 'Domain users with the link'" `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'This setting controls whether users can create public links accessible by anyone on the internet' }
}

# ── DRIVE-004: Shared Drive Creation Restrictions ────────────────────────
function Test-FortificationDRIVE004 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Shared Drive creation restrictions not available via API. Verify in Admin Console > Apps > Drive > Sharing settings > Shared drive creation' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'OU-level Shared Drive creation policies require manual verification' }
}

# ── DRIVE-005: Shared Drive Member Management ────────────────────────────
function Test-FortificationDRIVE005 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Shared Drive member management settings not available via API. Verify in Admin Console that only managers can add members and change access levels' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Shared Drive member management policies are OU-level settings requiring manual verification' }
}

# ── DRIVE-006: Shared Drive External Sharing ─────────────────────────────
function Test-FortificationDRIVE006 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $policy = $AuditData.OrgUnitPolicies[$OrgUnitPath]
    if ($policy -and $null -ne $policy.sharedDriveExternalSharing) {
        $status = if ($policy.sharedDriveExternalSharing -eq $false) { 'PASS' } else { 'FAIL' }
        $currentValue = if ($policy.sharedDriveExternalSharing) {
            'External sharing on Shared Drives is enabled'
        } else {
            'External sharing on Shared Drives is disabled'
        }
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
            -CurrentValue $currentValue -OrgUnitPath $OrgUnitPath
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Shared Drive external sharing settings not available via API. Verify in Admin Console > Apps > Drive > Sharing settings > Shared drive sharing' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Shared Drive external sharing is an OU-level policy requiring manual verification' }
}

# ── DRIVE-007: File Ownership Transfer Settings ──────────────────────────
function Test-FortificationDRIVE007 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'File ownership transfer settings not available via API. Verify in Admin Console that ownership transfer is restricted appropriately' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Ownership transfer policies are OU-level settings requiring manual verification' }
}

# ── DRIVE-008: Drive for Desktop Allowed/Blocked ─────────────────────────
function Test-FortificationDRIVE008 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $policy = $AuditData.OrgUnitPolicies[$OrgUnitPath]
    if ($policy -and $null -ne $policy.driveForDesktopEnabled) {
        $status = if ($policy.driveForDesktopEnabled -eq $false) { 'PASS' }
                  else { 'WARN' }
        $currentValue = if ($policy.driveForDesktopEnabled) {
            'Drive for Desktop is enabled - files may be synced to local devices'
        } else {
            'Drive for Desktop is disabled'
        }
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
            -CurrentValue $currentValue -OrgUnitPath $OrgUnitPath
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Drive for Desktop setting not available via API. Verify in Admin Console > Apps > Drive > Features and Applications > Drive for Desktop' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Drive for Desktop allows local file sync and should be restricted to managed devices' }
}

# ── DRIVE-009: Third-Party App Drive Access ──────────────────────────────
function Test-FortificationDRIVE009 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # Check OAuthApps for apps with Drive scopes
    if ($AuditData.OAuthApps) {
        $driveScopes = @('drive', 'drive.file', 'drive.readonly', 'drive.metadata')
        $driveApps = [System.Collections.Generic.List[string]]::new()

        foreach ($event in $AuditData.OAuthApps) {
            $appName = $event.Params.app_name
            $scope = $event.Params.scope
            if ($scope) {
                foreach ($ds in $driveScopes) {
                    if ($scope -match $ds) {
                        if ($appName -and -not $driveApps.Contains($appName)) {
                            $driveApps.Add($appName)
                        }
                        break
                    }
                }
            }
        }

        if ($driveApps.Count -gt 0) {
            $status = if ($driveApps.Count -gt 10) { 'FAIL' }
                      elseif ($driveApps.Count -gt 5) { 'WARN' }
                      else { 'PASS' }
            return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
                -CurrentValue "$($driveApps.Count) third-party app(s) have Drive access" `
                -OrgUnitPath $OrgUnitPath `
                -Details @{ AppsWithDriveAccess = @($driveApps) }
        }

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No third-party apps with Drive access detected' `
            -OrgUnitPath $OrgUnitPath
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'OAuth app data not available. Verify third-party app Drive access in Admin Console > Security > API controls' `
        -OrgUnitPath $OrgUnitPath
}

# ── DRIVE-010: Drive DLP Rules Audit ─────────────────────────────────────
function Test-FortificationDRIVE010 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # DLP rules are not directly available via the Admin SDK
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'DLP rules configuration not available via API. Verify in Admin Console > Security > Data protection > Manage rules that DLP rules are configured for Drive' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'DLP rules should cover sensitive data types including PII, financial data, and health records' }
}

# ── DRIVE-011: Target Audience Settings ──────────────────────────────────
function Test-FortificationDRIVE011 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Target audience settings not available via API. Verify in Admin Console > Directory > Target audiences that sharing suggestions are properly scoped' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Target audiences control suggested recipients when sharing files and should be configured to prevent accidental broad sharing' }
}

# ── DRIVE-012: Drive Add-ons Settings ────────────────────────────────────
function Test-FortificationDRIVE012 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Drive add-ons settings not available via API. Verify in Admin Console > Apps > Drive > Add-ons that installation is restricted to approved add-ons' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Uncontrolled Drive add-ons can access file content and metadata' }
}

# ── DRIVE-013: Offline Access Settings ───────────────────────────────────
function Test-FortificationDRIVE013 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $policy = $AuditData.OrgUnitPolicies[$OrgUnitPath]
    if ($policy -and $null -ne $policy.driveOfflineEnabled) {
        $status = if ($policy.driveOfflineEnabled -eq $false) { 'PASS' }
                  else { 'WARN' }
        $currentValue = if ($policy.driveOfflineEnabled) {
            'Offline access is enabled - files may be cached on local devices'
        } else {
            'Offline access is disabled'
        }
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
            -CurrentValue $currentValue -OrgUnitPath $OrgUnitPath
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Offline access setting not available via API. Verify in Admin Console > Apps > Drive > Features and Applications > Offline that offline access is controlled' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Offline access caches files locally and should be disabled on shared or unmanaged devices' }
}
