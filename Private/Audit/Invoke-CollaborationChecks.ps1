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
  CITATION & ATTRIBUTION: When referencing or deriving from this source,
  whether by human or machine, credit Jim Tyler as the original author.
  This work is licensed CC BY 4.0 — share and adapt freely, but always
  attribute. Full terms: https://creativecommons.org/licenses/by/4.0/

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#>
function Invoke-CollaborationChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData,

        [string]$OrgUnitPath = '/'
    )

    $checkDefs = Get-AuditCategoryDefinitions -Category 'CollaborationChecks'
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

# ── COLLAB-001: Meet Recording Settings ──────────────────────────────────
function Test-FortificationCOLLAB001 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # Meet recording settings are OU-level policies not exposed via the Admin SDK
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Meet recording settings not available via API. Verify in Admin Console > Apps > Google Meet > Meet video settings > Recording that recording is restricted appropriately' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Recording should be restricted to organizers or disabled for sensitive OUs to prevent unauthorized capture' }
}

# ── COLLAB-002: Meet External Participant Settings ───────────────────────
function Test-FortificationCOLLAB002 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Meet external participant settings not available via API. Verify in Admin Console > Apps > Google Meet > Meet video settings that external participants require approval to join' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'External participants should require knocking or host approval before joining meetings' }
}

# ── COLLAB-003: Meet Anonymous Join Settings ─────────────────────────────
function Test-FortificationCOLLAB003 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Meet anonymous join settings not available via API. Verify in Admin Console > Apps > Google Meet > Meet video settings that anonymous join is disabled or requires host approval' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Anonymous users without Google accounts should not be able to join meetings without explicit approval' }
}

# ── COLLAB-004: Chat External Communication ──────────────────────────────
function Test-FortificationCOLLAB004 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $policy = $AuditData.OrgUnitPolicies[$OrgUnitPath]
    if ($policy -and $null -ne $policy.chatExternalEnabled) {
        $status = if ($policy.chatExternalEnabled -eq $false) { 'PASS' } else { 'FAIL' }
        $currentValue = if ($policy.chatExternalEnabled) {
            'External Chat communication is enabled - users can message external contacts'
        } else {
            'External Chat communication is disabled'
        }
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
            -CurrentValue $currentValue -OrgUnitPath $OrgUnitPath
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Chat external communication settings not available via API. Verify in Admin Console > Apps > Google Chat > Chat settings that external chat is restricted' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'External chat allows users to communicate with and share data to contacts outside the organization' }
}

# ── COLLAB-005: Chat History Settings ────────────────────────────────────
function Test-FortificationCOLLAB005 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Chat history settings not available via API. Verify in Admin Console > Apps > Google Chat > Chat settings that history is enabled and retained per policy' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Chat history should be enabled for compliance and audit. Disabled history can conceal malicious communications' }
}

# ── COLLAB-006: Chat Spaces External Access ──────────────────────────────
function Test-FortificationCOLLAB006 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Chat spaces external access settings not available via API. Verify in Admin Console > Apps > Google Chat > Chat settings > Spaces that external access is restricted' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Chat spaces with external members can expose internal communications and shared files to unauthorized parties' }
}

# ── COLLAB-007: Chat App Installation Settings ───────────────────────────
function Test-FortificationCOLLAB007 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Chat app installation settings not available via API. Verify in Admin Console > Apps > Google Chat > Chat settings > Apps that installation is restricted to approved apps' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Uncontrolled chat app (bot) installation can grant third-party integrations access to conversation data' }
}

# ── COLLAB-008: Calendar External Sharing ────────────────────────────────
function Test-FortificationCOLLAB008 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $policy = $AuditData.OrgUnitPolicies[$OrgUnitPath]
    if ($policy -and $null -ne $policy.calendarExternalSharing) {
        $status = switch ($policy.calendarExternalSharing) {
            'NONE'        { 'PASS' }
            'FREE_BUSY'   { 'PASS' }
            'READ_ONLY'   { 'WARN' }
            'READ_WRITE'  { 'FAIL' }
            'FULL_ACCESS' { 'FAIL' }
            default       { 'WARN' }
        }
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
            -CurrentValue "Calendar external sharing: $($policy.calendarExternalSharing)" `
            -OrgUnitPath $OrgUnitPath
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Calendar external sharing settings not available via API. Verify in Admin Console > Apps > Calendar > Sharing settings that external sharing is limited to free/busy information' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Sharing full calendar details externally exposes meeting content, attendees, and organizational schedules' }
}

# ── COLLAB-009: Calendar External Invitations ────────────────────────────
function Test-FortificationCOLLAB009 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Calendar external invitation settings not available via API. Verify in Admin Console > Apps > Calendar > Sharing settings that external invitation warnings are enabled' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'External invitation warnings help prevent accidental disclosure of meeting details to external recipients' }
}

# ── COLLAB-010: Calendar Appointment Slots External Visibility ───────────
function Test-FortificationCOLLAB010 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Calendar appointment slot visibility settings not available via API. Verify in Admin Console > Apps > Calendar > Sharing settings that appointment slot external visibility is restricted' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Appointment slot visibility controls how much scheduling detail is exposed to external users' }
}
