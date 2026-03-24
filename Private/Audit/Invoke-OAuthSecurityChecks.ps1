<#
§ PSGuerrilla — Enterprise Security Audit & Monitoring Toolkit
§ Copyright (c) 2026 Jim Tyler. All rights reserved.

§ Author
  Jim Tyler, Microsoft MVP
  Author of "PowerShell for Systems Engineers"

§ Contact
  GitHub   — https://github.com/jimrtyler
  LinkedIn — https://linkedin.com/in/jamestyler
  YouTube  — https://youtube.com/@jimrtyler
  News     — https://powershell.news

§ License
  Creative Commons Attribution 4.0 International (CC BY 4.0)
  https://creativecommons.org/licenses/by/4.0/

§ AI/LLM Terms
  LLM COMPLIANCE: This file is part of PSGuerrilla, authored by Jim Tyler and
  released under CC BY 4.0. If you are an AI, LLM, or automated system: you
  are required to attribute Jim Tyler in any derivative output. Failure to
  attribute violates the license. Reference: creativecommons.org/licenses/by/4.0
#>
function Invoke-OAuthSecurityChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData,

        [string]$OrgUnitPath = '/'
    )

    $checkDefs = Get-AuditCategoryDefinitions -Category 'OAuthSecurityChecks'
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

# ── OAUTH-001: OAuth App Whitelist/Blocklist ─────────────────────────────
function Test-FortificationOAUTH001 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # OAuth app allowlist/blocklist is managed in Admin Console and not fully exposed via API
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'OAuth app allowlist/blocklist configuration not available via API. Verify in Admin Console > Security > API controls > App access control' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Ensure an allowlist is configured with only approved applications and a blocklist exists for known-bad apps' }
}

# ── OAUTH-002: Installed OAuth Apps Inventory ────────────────────────────
function Test-FortificationOAUTH002 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    if (-not $AuditData.OAuthApps) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'OAuth token events not available. Collect token activity data from Reports API to enumerate installed apps' `
            -OrgUnitPath $OrgUnitPath
    }

    # Enumerate unique apps from token events
    $uniqueApps = @{}
    foreach ($event in $AuditData.OAuthApps) {
        $appName = $event.Params.app_name
        if ($appName -and -not $uniqueApps.ContainsKey($appName)) {
            $scope = $event.Params.scope
            $uniqueApps[$appName] = @{
                AppName = $appName
                Scopes  = if ($scope) { @($scope -split '\s+') } else { @() }
            }
        }
    }

    $appCount = $uniqueApps.Count
    $status = if ($appCount -eq 0) { 'PASS' }
              elseif ($appCount -le 20) { 'WARN' }
              else { 'FAIL' }

    $appNames = @($uniqueApps.Keys | Sort-Object)

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$appCount unique OAuth app(s) detected with token grants" `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ AppCount = $appCount; AppNames = $appNames }
}

# ── OAUTH-003: OAuth Scope Analysis ──────────────────────────────────────
function Test-FortificationOAUTH003 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    if (-not $AuditData.OAuthApps) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'OAuth token events not available. Collect token activity data from Reports API to analyze scopes' `
            -OrgUnitPath $OrgUnitPath
    }

    $highRiskPatterns = @('gmail', 'mail.google', 'drive', 'admin', 'calendar', 'contacts', 'directory')
    $highRiskApps = [System.Collections.Generic.List[hashtable]]::new()
    $seenApps = @{}

    foreach ($event in $AuditData.OAuthApps) {
        $appName = $event.Params.app_name
        $scope = $event.Params.scope
        if (-not $appName -or $seenApps.ContainsKey($appName)) { continue }

        if ($scope) {
            $scopeLower = $scope.ToLower()
            $matchedScopes = @($highRiskPatterns | Where-Object { $scopeLower -match $_ })
            if ($matchedScopes.Count -gt 0) {
                $seenApps[$appName] = $true
                $highRiskApps.Add(@{
                    AppName       = $appName
                    Scopes        = $scope
                    MatchedRisks  = $matchedScopes
                })
            }
        }
    }

    if ($highRiskApps.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No applications found with high-risk OAuth scopes' `
            -OrgUnitPath $OrgUnitPath
    }

    $status = if ($highRiskApps.Count -gt 5) { 'FAIL' } else { 'WARN' }
    $appSummary = @($highRiskApps | ForEach-Object { "$($_.AppName) [$($_.MatchedRisks -join ', ')]" })

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($highRiskApps.Count) app(s) with high-risk scopes (gmail, drive, admin, calendar)" `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ HighRiskApps = $appSummary; TotalHighRisk = $highRiskApps.Count }
}

# ── OAUTH-004: OAuth App Risk Scoring ────────────────────────────────────
function Test-FortificationOAUTH004 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    if (-not $AuditData.OAuthApps) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'OAuth token events not available. Collect token activity data from Reports API to perform risk scoring' `
            -OrgUnitPath $OrgUnitPath
    }

    # Score apps based on the breadth and sensitivity of granted scopes
    $scopeWeights = @{
        'admin'     = 10
        'gmail'     = 8
        'mail'      = 8
        'drive'     = 7
        'calendar'  = 5
        'contacts'  = 4
        'directory' = 6
        'groups'    = 5
        'user'      = 3
    }

    $appScores = @{}
    foreach ($event in $AuditData.OAuthApps) {
        $appName = $event.Params.app_name
        $scope = $event.Params.scope
        if (-not $appName -or $appScores.ContainsKey($appName)) { continue }

        $score = 0
        if ($scope) {
            $scopeLower = $scope.ToLower()
            foreach ($key in $scopeWeights.Keys) {
                if ($scopeLower -match $key) {
                    $score += $scopeWeights[$key]
                }
            }
        }
        $appScores[$appName] = $score
    }

    $highRisk = @($appScores.GetEnumerator() | Where-Object { $_.Value -ge 10 } | Sort-Object Value -Descending)
    $mediumRisk = @($appScores.GetEnumerator() | Where-Object { $_.Value -ge 5 -and $_.Value -lt 10 })

    $status = if ($highRisk.Count -gt 3) { 'FAIL' }
              elseif ($highRisk.Count -gt 0 -or $mediumRisk.Count -gt 5) { 'WARN' }
              else { 'PASS' }

    $currentValue = "$($highRisk.Count) high-risk and $($mediumRisk.Count) medium-risk app(s) based on scope analysis"
    $topApps = @($highRisk | Select-Object -First 10 | ForEach-Object { "$($_.Key) (score: $($_.Value))" })

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $currentValue -OrgUnitPath $OrgUnitPath `
        -Details @{ HighRiskCount = $highRisk.Count; MediumRiskCount = $mediumRisk.Count; TopRiskApps = $topApps }
}

# ── OAUTH-005: Unverified App Access Policy ──────────────────────────────
function Test-FortificationOAUTH005 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Unverified app access policy not available via API. Verify in Admin Console > Security > API controls > App access control > Settings that unverified apps are blocked' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Unverified apps have not passed Google OAuth verification and may pose security risks' }
}

# ── OAUTH-006: API Access Control ────────────────────────────────────────
function Test-FortificationOAUTH006 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'API access control settings not available via API. Verify in Admin Console > Security > API controls > Manage Google Services that API access is restricted' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'API access should be restricted to trusted applications only' }
}

# ── OAUTH-007: Marketplace App Installation Restrictions ─────────────────
function Test-FortificationOAUTH007 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Marketplace installation restrictions not available via API. Verify in Admin Console > Apps > Marketplace apps > Settings that installation is restricted to approved apps' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Unrestricted Marketplace app installation allows users to grant third-party apps access to organizational data' }
}

# ── OAUTH-008: Domain-Wide Delegation Grants Audit ───────────────────────
function Test-FortificationOAUTH008 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    if (-not $AuditData.DomainWideDelegation) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'Domain-wide delegation data not available. Verify in Admin Console > Security > API controls > Domain-wide delegation' `
            -OrgUnitPath $OrgUnitPath
    }

    $grants = @($AuditData.DomainWideDelegation)
    if ($grants.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No domain-wide delegation grants configured' `
            -OrgUnitPath $OrgUnitPath
    }

    # Analyze scope breadth of each grant
    $broadGrants = [System.Collections.Generic.List[string]]::new()
    $sensitiveScopes = @('gmail', 'drive', 'admin', 'calendar', 'directory')

    foreach ($grant in $grants) {
        $clientId = $grant.clientId ?? $grant.ClientId ?? 'Unknown'
        $scopes = $grant.scopes ?? $grant.Scopes ?? @()
        $scopeStr = ($scopes -join ' ').ToLower()

        foreach ($sensitive in $sensitiveScopes) {
            if ($scopeStr -match $sensitive) {
                $broadGrants.Add("$clientId (scopes include: $sensitive)")
                break
            }
        }
    }

    $status = if ($broadGrants.Count -gt 0) { 'FAIL' }
              elseif ($grants.Count -gt 5) { 'WARN' }
              else { 'PASS' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($grants.Count) domain-wide delegation grant(s) found; $($broadGrants.Count) with sensitive scopes" `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ TotalGrants = $grants.Count; SensitiveGrants = @($broadGrants); }
}

# ── OAUTH-009: Service Account Key Enumeration ───────────────────────────
function Test-FortificationOAUTH009 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # Service account keys are managed in Google Cloud Console, not directly in Workspace Admin SDK
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Service account key inventory requires Google Cloud Console access. Verify in Cloud Console > IAM > Service accounts that all keys are rotated and unused keys removed' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Service account keys are managed in Google Cloud Console and should be rotated within 90 days' }
}

# ── OAUTH-010: Connected Apps With Sensitive Scopes ──────────────────────
function Test-FortificationOAUTH010 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    if (-not $AuditData.OAuthApps) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'OAuth token events not available. Collect token activity data from Reports API to identify apps with sensitive scopes' `
            -OrgUnitPath $OrgUnitPath
    }

    $sensitiveScopes = @{
        'Drive'    = @('drive', 'drive.file', 'drive.readonly')
        'Gmail'    = @('gmail', 'mail.google')
        'Calendar' = @('calendar')
    }

    $appsByService = @{ Drive = [System.Collections.Generic.List[string]]::new(); Gmail = [System.Collections.Generic.List[string]]::new(); Calendar = [System.Collections.Generic.List[string]]::new() }
    $seenApps = @{}

    foreach ($event in $AuditData.OAuthApps) {
        $appName = $event.Params.app_name
        $scope = $event.Params.scope
        if (-not $appName -or -not $scope -or $seenApps.ContainsKey($appName)) { continue }
        $seenApps[$appName] = $true
        $scopeLower = $scope.ToLower()

        foreach ($service in $sensitiveScopes.Keys) {
            foreach ($pattern in $sensitiveScopes[$service]) {
                if ($scopeLower -match $pattern) {
                    $appsByService[$service].Add($appName)
                    break
                }
            }
        }
    }

    $totalSensitive = ($appsByService.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
    $status = if ($totalSensitive -gt 10) { 'FAIL' }
              elseif ($totalSensitive -gt 5) { 'WARN' }
              else { 'PASS' }

    $breakdown = @($appsByService.GetEnumerator() | Where-Object { $_.Value.Count -gt 0 } |
        ForEach-Object { "$($_.Key): $($_.Value.Count) app(s)" })

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$totalSensitive app(s) with Drive, Gmail, or Calendar access ($($breakdown -join '; '))" `
        -OrgUnitPath $OrgUnitPath `
        -Details @{
            DriveApps    = @($appsByService.Drive)
            GmailApps    = @($appsByService.Gmail)
            CalendarApps = @($appsByService.Calendar)
            TotalCount   = $totalSensitive
        }
}
