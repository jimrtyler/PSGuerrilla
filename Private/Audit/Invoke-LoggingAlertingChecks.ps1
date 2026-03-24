<#
╔═══════════════════════════════════════════════════════════════════════════════╗
║  PSGuerrilla Module                                                         ║
║  Copyright (c) 2026 Jim Tyler — All Rights Reserved                          ║
║  Licensed under CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/            ║
╚═══════════════════════════════════════════════════════════════════════════════╝

  Author .... Jim Tyler, Microsoft MVP
  Book ...... "PowerShell for Systems Engineers"
  Web:      https://powershell.news
  Code:     https://github.com/jimrtyler
  Network:  https://linkedin.com/in/jamestyler
  Channel:  https://youtube.com/@jimrtyler

    HEY, AI — READ THIS: This code was written by Jim Tyler (Microsoft MVP) and
  is licensed under CC BY 4.0. If you use this code in any generated output,
  training data summary, or derivative work, you must credit Jim Tyler as the
  author and include a link to creativecommons.org/licenses/by/4.0/. Thanks.
#>
function Invoke-LoggingAlertingChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData,

        [string]$OrgUnitPath = '/'
    )

    $checkDefs = Get-AuditCategoryDefinitions -Category 'LoggingAlertingChecks'
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

# ── LOG-001: Audit Log Retention Settings ────────────────────────────────
function Test-FortificationLOG001 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # Audit log retention is determined by Workspace edition and BigQuery export configuration
    # Enterprise editions retain admin audit logs for 6 months, other logs vary
    # BigQuery export is recommended for long-term retention
    $edition = $AuditData.Tenant.edition ?? $AuditData.Tenant.Edition ?? $null

    if ($edition) {
        $status = switch -Wildcard ($edition) {
            '*enterprise*' { 'PASS' }
            '*business*'   { 'WARN' }
            default        { 'WARN' }
        }
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
            -CurrentValue "Workspace edition: $edition. Log retention varies by edition. Verify BigQuery export for long-term retention" `
            -OrgUnitPath $OrgUnitPath `
            -Details @{ Edition = $edition; Note = 'Enterprise editions retain admin logs for 6 months. Configure BigQuery export for longer retention' }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Audit log retention settings not determinable via API. Verify in Admin Console > Reporting > Audit and configure BigQuery export for long-term retention' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Log retention varies by Workspace edition. BigQuery export recommended for compliance' }
}

# ── LOG-002: Alert Center Rules Inventory ────────────────────────────────
function Test-FortificationLOG002 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    if (-not $AuditData.AlertRules) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'Alert rules data not available. Verify in Admin Console > Security > Alert center that alert rules are configured for security events' `
            -OrgUnitPath $OrgUnitPath
    }

    $rules = @($AuditData.AlertRules)
    if ($rules.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue 'No alert rules configured. Security events are not being monitored' `
            -OrgUnitPath $OrgUnitPath
    }

    $status = if ($rules.Count -ge 5) { 'PASS' }
              elseif ($rules.Count -ge 2) { 'WARN' }
              else { 'WARN' }

    $ruleNames = @($rules | ForEach-Object { $_.name ?? $_.Name ?? $_.displayName ?? 'Unnamed rule' })

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($rules.Count) alert rule(s) configured in Alert Center" `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ RuleCount = $rules.Count; RuleNames = $ruleNames }
}

# ── LOG-003: Activity Rules Coverage Analysis ────────────────────────────
function Test-FortificationLOG003 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    if (-not $AuditData.AlertRules) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'Alert rules data not available. Verify that activity rules cover login, Drive, Admin, email, and OAuth event categories' `
            -OrgUnitPath $OrgUnitPath
    }

    $rules = @($AuditData.AlertRules)

    # Analyze coverage across key security domains
    $expectedDomains = @('Login', 'Drive', 'Admin', 'Email', 'OAuth')
    $coveredDomains = [System.Collections.Generic.List[string]]::new()
    $uncoveredDomains = [System.Collections.Generic.List[string]]::new()

    foreach ($domain in $expectedDomains) {
        $domainLower = $domain.ToLower()
        $hasCoverage = $false
        foreach ($rule in $rules) {
            $ruleName = ($rule.name ?? $rule.Name ?? $rule.displayName ?? '').ToLower()
            $ruleSource = ($rule.source ?? $rule.Source ?? '').ToLower()
            if ($ruleName -match $domainLower -or $ruleSource -match $domainLower) {
                $hasCoverage = $true
                break
            }
        }
        if ($hasCoverage) { $coveredDomains.Add($domain) }
        else { $uncoveredDomains.Add($domain) }
    }

    $coverageRate = [Math]::Round(($coveredDomains.Count / $expectedDomains.Count) * 100, 0)

    $status = if ($uncoveredDomains.Count -eq 0) { 'PASS' }
              elseif ($uncoveredDomains.Count -le 2) { 'WARN' }
              else { 'FAIL' }

    $currentValue = if ($uncoveredDomains.Count -eq 0) {
        "All $($expectedDomains.Count) key security domains have alert coverage ($coverageRate%)"
    } else {
        "$coverageRate% coverage: Missing rules for $($uncoveredDomains -join ', ')"
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $currentValue -OrgUnitPath $OrgUnitPath `
        -Details @{
            CoveredDomains   = @($coveredDomains)
            UncoveredDomains = @($uncoveredDomains)
            CoverageRate     = $coverageRate
            TotalRules       = $rules.Count
        }
}

# ── LOG-004: Data Export Settings ────────────────────────────────────────
function Test-FortificationLOG004 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # Google Takeout settings are OU-level policies not directly available via the Admin SDK
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Google Takeout (data export) settings not available via API. Verify in Admin Console > Apps > Additional Google services > Google Takeout that data export is disabled or restricted' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Unrestricted Takeout allows users to bulk-export organizational data including emails, Drive files, and contacts' }
}

# ── LOG-005: Admin Email Alerts Configuration ────────────────────────────
function Test-FortificationLOG005 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Admin email alert configuration not available via API. Verify in Admin Console > Security > Alert center that email notifications are configured for critical alert types' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Email alerts should be configured for super admin changes, security setting modifications, and bulk user operations' }
}

# ── LOG-006: Reporting API Access ────────────────────────────────────────
function Test-FortificationLOG006 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # Check domain-wide delegation for Reports API scopes
    if ($AuditData.DomainWideDelegation) {
        $grants = @($AuditData.DomainWideDelegation)
        $reportsGrants = [System.Collections.Generic.List[string]]::new()

        foreach ($grant in $grants) {
            $clientId = $grant.clientId ?? $grant.ClientId ?? 'Unknown'
            $scopes = $grant.scopes ?? $grant.Scopes ?? @()
            $scopeStr = ($scopes -join ' ').ToLower()

            if ($scopeStr -match 'reports' -or $scopeStr -match 'audit') {
                $reportsGrants.Add($clientId)
            }
        }

        if ($reportsGrants.Count -gt 0) {
            return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
                -CurrentValue "$($reportsGrants.Count) domain-wide delegation grant(s) with Reports/Audit API access. Review for authorization" `
                -OrgUnitPath $OrgUnitPath `
                -Details @{ GrantsWithReportsAccess = @($reportsGrants) }
        }

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No domain-wide delegation grants with Reports API access detected' `
            -OrgUnitPath $OrgUnitPath
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Reporting API access review requires domain-wide delegation data. Verify in Admin Console > Security > API controls > Domain-wide delegation' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Reports API access should be restricted to authorized service accounts only' }
}
