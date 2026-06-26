# PSGuerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/PSGuerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
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

    # GWS-1: meet.automatic_recording { enabled=bool }. Automatic recording captures every
    # meeting by default; weakest-OU-wins (FAIL if enabled in any targeted OU).
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'meet.automatic_recording' -Field 'enabled')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No meet.automatic_recording policy returned for this tenant' -OrgUnitPath $OrgUnitPath
    }
    $enabled = @($vals | Where-Object { $_ -eq $true })
    if ($enabled.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "Automatic Meet recording enabled in $($enabled.Count) of $($vals.Count) targeted policy/policies" `
            -OrgUnitPath $OrgUnitPath `
            -Details @{ Note = 'Recording should be restricted to organizers or disabled for sensitive OUs to prevent unauthorized capture' }
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue 'Automatic Meet recording is disabled' -OrgUnitPath $OrgUnitPath
}

# ── COLLAB-002: Meet External Participant Settings ───────────────────────
function Test-FortificationCOLLAB002 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # GWS-1: meet.meet_joining { allowedAudience=enum(TRUSTED…) } controls who may join meetings
    # this OU hosts. ENUM GUESS: TRUSTED restricts to trusted/internal audiences (secure); a
    # value that admits anyone external is insecure. Unknown values WARN — never PASS blindly.
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'meet.meet_joining' -Field 'allowedAudience')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No meet.meet_joining policy returned for this tenant' -OrgUnitPath $OrgUnitPath
    }
    $note = "Allowed Meet audience: $((@($vals) | Select-Object -Unique) -join ', ') (across $($vals.Count) targeted policy/policies)"
    # Clearly-insecure: an audience that explicitly admits anyone / all external participants.
    $insecure = @($vals | Where-Object { "$_" -match '(?i)\b(ALL|ANYONE|EVERYONE|PUBLIC|NO_RESTRICTION|UNRESTRICTED)\b' })
    $trusted  = @($vals | Where-Object { "$_" -match '(?i)TRUSTED|INTERNAL|RESTRICTED|LOGGED_IN' })
    if ($insecure.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "Meet permits an unrestricted external audience — $note" -OrgUnitPath $OrgUnitPath `
            -Details @{ Note = 'External participants should require knocking or host approval before joining meetings' }
    }
    if ($trusted.Count -eq $vals.Count) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue "Meet join audience restricted to trusted participants — $note" -OrgUnitPath $OrgUnitPath
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue "Meet join audience could not be confirmed as restricted — $note" -OrgUnitPath $OrgUnitPath
}

# ── COLLAB-003: Meet Anonymous Join Settings ─────────────────────────────
function Test-FortificationCOLLAB003 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # GWS-1: meet.safety_domain { usersAllowedToJoin=enum(LOGGED_IN…) }. ENUM GUESS: LOGGED_IN
    # requires a Google account (no anonymous join, secure); a value permitting anonymous /
    # all users is insecure. Unknown values WARN — never PASS blindly.
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'meet.safety_domain' -Field 'usersAllowedToJoin')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No meet.safety_domain policy returned for this tenant' -OrgUnitPath $OrgUnitPath
    }
    $note = "Users allowed to join: $((@($vals) | Select-Object -Unique) -join ', ') (across $($vals.Count) targeted policy/policies)"
    $insecure = @($vals | Where-Object { "$_" -match '(?i)ANONYMOUS|\b(ALL|ANYONE|EVERYONE|PUBLIC)\b' })
    $loggedIn = @($vals | Where-Object { "$_" -match '(?i)LOGGED_IN|SIGNED_IN|AUTHENTICATED' })
    if ($insecure.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "Meet permits anonymous / unauthenticated join — $note" -OrgUnitPath $OrgUnitPath `
            -Details @{ Note = 'Anonymous users without Google accounts should not be able to join meetings without explicit approval' }
    }
    if ($loggedIn.Count -eq $vals.Count) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue "Meet requires signed-in users to join — $note" -OrgUnitPath $OrgUnitPath
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue "Meet join eligibility could not be confirmed as restricted — $note" -OrgUnitPath $OrgUnitPath
}

# ── COLLAB-004: Chat External Communication ──────────────────────────────
function Test-FortificationCOLLAB004 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # GWS-1 PRIMARY: chat.external_chat_restriction { allowExternalChat=bool,
    # externalChatRestriction=enum }. External chat with no restriction lets users message and
    # share data to outside contacts freely; weakest-OU-wins. ENUM GUESS: NO_RESTRICTION/ALL/
    # UNRESTRICTED is fully open (insecure); any other restriction value is "allowed but limited"
    # (WARN). Unknown values WARN — never PASS blindly. (OrgUnitPolicies fallback retained below.)
    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey @('CloudIdentityPolicies', 'OrgUnits') -Subject 'Chat external-communication policy'
    if ($na) { return $na }

    $pol = $AuditData.CloudIdentityPolicies
    if ($pol) {
        $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'chat.external_chat_restriction')
        if ($vals.Count -gt 0) {
            $allowed     = @($vals | Where-Object { $_.allowExternalChat -eq $true })
            $unrestricted = @($allowed | Where-Object { "$($_.externalChatRestriction)" -match '(?i)\b(NO_RESTRICTION|ALL|UNRESTRICTED)\b' })
            if ($unrestricted.Count -gt 0) {
                return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
                    -CurrentValue "External Chat is enabled with no restriction in $($unrestricted.Count) of $($vals.Count) targeted policy/policies" `
                    -OrgUnitPath $OrgUnitPath `
                    -Details @{ Note = 'External chat allows users to communicate with and share data to contacts outside the organization' }
            }
            if ($allowed.Count -gt 0) {
                $restrictions = (@($allowed | ForEach-Object { "$($_.externalChatRestriction)" }) | Select-Object -Unique) -join ', '
                return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
                    -CurrentValue "External Chat is enabled but restricted in $($allowed.Count) of $($vals.Count) targeted policy/policies (restriction: $restrictions)" `
                    -OrgUnitPath $OrgUnitPath `
                    -Details @{ Note = 'External chat allows users to communicate with and share data to contacts outside the organization' }
            }
            return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
                -CurrentValue 'External Chat communication is disabled' -OrgUnitPath $OrgUnitPath
        }
    }

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

    # GWS-1: chat.chat_history { historyOnByDefault=bool }. History off conceals communications;
    # weakest-OU-wins (FAIL if history off in any targeted OU).
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'chat.chat_history' -Field 'historyOnByDefault')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No chat.chat_history policy returned for this tenant' -OrgUnitPath $OrgUnitPath
    }
    $historyOff = @($vals | Where-Object { $_ -ne $true })
    if ($historyOff.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "Chat history off by default in $($historyOff.Count) of $($vals.Count) targeted policy/policies" `
            -OrgUnitPath $OrgUnitPath `
            -Details @{ Note = 'Chat history should be enabled for compliance and audit. Disabled history can conceal malicious communications' }
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue 'Chat history is on by default' -OrgUnitPath $OrgUnitPath
}

# ── COLLAB-006: Chat Spaces External Access ──────────────────────────────
function Test-FortificationCOLLAB006 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # GWS-1: chat.chat_external_spaces { enabled=bool }. External spaces let outsiders into
    # Chat spaces; weakest-OU-wins (FAIL if enabled in any targeted OU).
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'chat.chat_external_spaces' -Field 'enabled')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No chat.chat_external_spaces policy returned for this tenant' -OrgUnitPath $OrgUnitPath
    }
    $enabled = @($vals | Where-Object { $_ -eq $true })
    if ($enabled.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "External Chat spaces enabled in $($enabled.Count) of $($vals.Count) targeted policy/policies" `
            -OrgUnitPath $OrgUnitPath `
            -Details @{ Note = 'Chat spaces with external members can expose internal communications and shared files to unauthorized parties' }
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue 'External Chat spaces are disabled' -OrgUnitPath $OrgUnitPath
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

    # GWS-1 PRIMARY: calendar.primary_calendar_max_allowed_external_sharing
    # { maxAllowedExternalSharing=enum }. The most-permissive value shares all event details
    # externally (insecure); weakest-OU-wins. CONFIRMED enums (live tenant): EXTERNAL_ALL_INFO_*
    # (READ_ONLY / READ_WRITE / READ_WRITE_MANAGE) share full event details externally -> FAIL;
    # EXTERNAL_FREE_BUSY_ONLY / EXTERNAL_NO_SHARING are limited -> PASS. Older-shape guesses kept as
    # a fallback. Unknown values WARN — never PASS blindly. (OrgUnitPolicies fallback retained.)
    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey @('CloudIdentityPolicies', 'OrgUnits') -Subject 'Calendar external-sharing policy'
    if ($na) { return $na }

    $pol = $AuditData.CloudIdentityPolicies
    if ($pol) {
        $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'calendar.primary_calendar_max_allowed_external_sharing' -Field 'maxAllowedExternalSharing')
        if ($vals.Count -gt 0) {
            $note = "Max allowed external sharing: $((@($vals) | Select-Object -Unique) -join ', ') (across $($vals.Count) targeted policy/policies)"
            $permissive = @($vals | Where-Object { "$_" -match '(?i)(EXTERNAL_ALL_INFO|READ_WRITE|SHARE_ALL|READ_ALL|MANAGE|EVERYTHING)' })
            $limited    = @($vals | Where-Object { "$_" -match '(?i)(EXTERNAL_FREE_BUSY|EXTERNAL_NO_SHARING|FREE_BUSY|DOMAIN_ONLY|^NONE$|^LIMITED$)' })
            if ($permissive.Count -gt 0) {
                return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
                    -CurrentValue "Calendar shares full event details externally — $note" -OrgUnitPath $OrgUnitPath `
                    -Details @{ Note = 'Sharing full calendar details externally exposes meeting content, attendees, and organizational schedules' }
            }
            if ($limited.Count -eq $vals.Count) {
                return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
                    -CurrentValue "Calendar external sharing limited — $note" -OrgUnitPath $OrgUnitPath
            }
            return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
                -CurrentValue "Calendar external sharing level could not be confirmed as limited — $note" -OrgUnitPath $OrgUnitPath
        }
    }

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

# ── COLLAB-011: Meet External Participant Labeling ───────────────────────
function Test-FortificationCOLLAB011 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # GWS-1: meet.safety_external_participants { enableExternalLabel=bool }. External participants
    # should be visibly labeled so hosts/attendees can spot outsiders; true=secure. Weakest-OU-wins
    # (WARN if labeling off in any targeted OU).
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'meet.safety_external_participants' -Field 'enableExternalLabel')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No meet.safety_external_participants policy returned for this tenant' -OrgUnitPath $OrgUnitPath
    }
    $off = @($vals | Where-Object { $_ -ne $true })
    if ($off.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "External participant labeling off in $($off.Count) of $($vals.Count) targeted policy/policies" `
            -OrgUnitPath $OrgUnitPath `
            -Details @{ Note = 'External participants should be visibly labeled so hosts and attendees can identify outsiders in meetings' }
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue 'External participant labeling is enabled' -OrgUnitPath $OrgUnitPath
}

# ── COLLAB-012: Meet Host Management ─────────────────────────────────────
function Test-FortificationCOLLAB012 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # GWS-1: meet.safety_host_management { enableHostManagement=bool }. Host management gives hosts
    # moderation controls (mute/remove/lock) to prevent meeting hijacking/disruption; true=secure.
    # Weakest-OU-wins (WARN if host management off in any targeted OU).
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'meet.safety_host_management' -Field 'enableHostManagement')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No meet.safety_host_management policy returned for this tenant' -OrgUnitPath $OrgUnitPath
    }
    $off = @($vals | Where-Object { $_ -ne $true })
    if ($off.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "Host management off in $($off.Count) of $($vals.Count) targeted policy/policies" `
            -OrgUnitPath $OrgUnitPath `
            -Details @{ Note = 'Host management gives meeting hosts moderation controls (mute, remove, lock) to prevent meeting hijacking and disruption' }
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue 'Host management is enabled' -OrgUnitPath $OrgUnitPath
}
