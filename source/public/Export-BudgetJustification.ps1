# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Export-BudgetJustification {
    <#
    .SYNOPSIS
        Generates a board-ready budget justification document from audit findings.
    .DESCRIPTION
        Produces an HTML document suitable for presenting to school boards, executives,
        or budget committees. Groups remediation items by cost tier, shows total cost
        estimates, and maps findings to compliance requirements.
    .PARAMETER Findings
        Array of audit finding objects. If not provided, reads from latest state.
    .PARAMETER OutputPath
        File path for the HTML output. Default: Guerrilla-Budget-Justification.html in current directory.
    .PARAMETER ProfileName
        Baseline profile context. Default: uses configured profile.
    .PARAMETER OrganizationName
        Name of the organization for the report header.
    .PARAMETER ConfigPath
        Override config file path.
    .PARAMETER Style
        Report style: Auto (follow the OS), Light, or Dark. Legacy names accepted.
    .EXAMPLE
        Export-BudgetJustification -OrganizationName 'Springfield USD'
        Generates a budget justification report for the district.
    .EXAMPLE
        $findings = Invoke-GWSAudit -PassThru; Export-BudgetJustification -Findings $findings -OutputPath ./budget.html
        Generates report from specific findings.
    #>
    [CmdletBinding()]
    param(
        [PSCustomObject[]]$Findings,

        [string]$OutputPath,
        [string]$OrganizationName = 'Organization',
        [string]$ProfileName,
        [Alias('RuntimeConfig')]
        [string]$ConfigPath,

        [ValidateSet('Auto', 'Light', 'Dark', 'Guerrilla', 'Professional', 'Slate')]
        [string]$Style = 'Auto'
    )

    # Load config
    $cfgPath = if ($ConfigPath) { $ConfigPath } else { $script:ConfigPath }
    $config = $null
    if ($cfgPath -and (Test-Path $cfgPath)) {
        $config = Get-Content -Path $cfgPath -Raw | ConvertFrom-Json -AsHashtable
    }

    if (-not $ProfileName) { $ProfileName = $config.profile ?? 'Default' }
    if (-not $OutputPath) { $OutputPath = Join-Path (Get-Location) 'Guerrilla-Budget-Justification.html' }

    # Load findings from state if not provided
    if (-not $Findings -or $Findings.Count -eq 0) {
        $dataDir = Get-GuerrillaDataRoot
        $findingsFiles = @()
        if (Test-Path $dataDir) {
            $findingsFiles = @(Get-ChildItem -Path $dataDir -Filter '*.findings.json' -ErrorAction SilentlyContinue)
        }
        if ($findingsFiles.Count -gt 0) {
            $Findings = @()
            foreach ($f in $findingsFiles) {
                try {
                    $data = Get-Content -Path $f.FullName -Raw | ConvertFrom-Json
                    $Findings += @($data)
                } catch { Write-Verbose "Failed to load findings: $_" }
            }
        }
    }

    if (-not $Findings -or $Findings.Count -eq 0) {
        Write-Warning 'No audit findings available. Run a scan first.'
        return [PSCustomObject]@{ Success = $false; Message = 'No findings'; Path = $null }
    }

    # Load remediation costs
    $remPath = Join-Path $script:ModuleRoot 'Data/RemediationCosts.json'
    $remData = $null
    if (Test-Path $remPath) {
        $remData = Get-Content -Path $remPath -Raw | ConvertFrom-Json -AsHashtable
    }

    # Get all actionable findings with cost info
    $allFixes = Get-ResourceConstrainedFixes -Findings $Findings -MaxCostTier 'Medium' -RemediationData $remData

    # Also get high/enterprise items
    $tierOrder = @{ 'Free' = 0; 'Low' = 1; 'Medium' = 2; 'High' = 3; 'Enterprise' = 4 }
    $highCostFixes = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($finding in $Findings) {
        if ($finding.Status -notin @('FAIL', 'WARN')) { continue }
        $checkId = $finding.CheckId ?? $finding.Id ?? ''
        $prefix = if ($checkId -match '^([A-Z0-9]+)-') { $Matches[1] } else { '' }
        $costInfo = $remData.overrides.$checkId ?? $remData.categoryDefaults.$prefix
        if (-not $costInfo) { continue }
        $tier = $costInfo.costTier ?? 'Medium'
        if ($tierOrder[$tier] -gt 2) {
            $highCostFixes.Add([PSCustomObject]@{
                CheckId    = $checkId
                CheckName  = $finding.Name ?? $checkId
                Severity   = $finding.Severity ?? 'Medium'
                Status     = $finding.Status
                CostTier   = $tier
                Effort     = $costInfo.effort ?? 'High'
                Category   = $finding.Category ?? $prefix
                Notes      = $costInfo.notes ?? ''
            })
        }
    }

    # Calculate summary stats
    $failCount = @($Findings | Where-Object Status -eq 'FAIL').Count
    $warnCount = @($Findings | Where-Object Status -eq 'WARN').Count
    $passCount = @($Findings | Where-Object Status -eq 'PASS').Count
    $totalChecks = $Findings.Count
    $criticalFails = @($Findings | Where-Object { $_.Status -eq 'FAIL' -and $_.Severity -eq 'Critical' }).Count
    $highFails = @($Findings | Where-Object { $_.Status -eq 'FAIL' -and $_.Severity -eq 'High' }).Count

    # Guerrilla Score
    $scoreResult = $null
    try { $scoreResult = Get-GuerrillaScoreCalculation -AuditFindings $Findings } catch { }
    $score = $scoreResult.Score ?? 'N/A'
    $label = $scoreResult.Label ?? ''

    $scoreNum = 0
    $scoreIsNumeric = [int]::TryParse("$score", [ref]$scoreNum)
    $scoreColor = if ($scoreIsNumeric) { Get-GuerrillaScoreColorVar -Score $scoreNum } else { 'var(--g-sev-info)' }

    # Group fixes by cost tier
    $freeFixes = @($allFixes | Where-Object CostTier -eq 'Free')
    $lowFixes = @($allFixes | Where-Object CostTier -eq 'Low')
    $medFixes = @($allFixes | Where-Object CostTier -eq 'Medium')

    # Cost estimates from RemediationCosts.json tiers
    $costRanges = $remData.costTiers ?? @{}

    # Build compliance impact summary
    $complianceMappings = @()
    try { $complianceMappings = Get-ComplianceCrosswalk -Findings $Findings -FailOnly } catch { }
    $complianceFrameworks = @($complianceMappings | Group-Object Framework | ForEach-Object {
        [PSCustomObject]@{ Framework = $_.Name; GapCount = $_.Count }
    })

    $esc = { param([string]$s) [System.Web.HttpUtility]::HtmlEncode($s) }
    $timestamp = [datetime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss')

    # Build fix rows HTML
    $fixRowsHtml = { param($fixes)
        $rows = ''
        foreach ($fix in $fixes) {
            $sevClass = switch ("$($fix.Severity)") {
                'Critical' { 'critical' }
                'High'     { 'high' }
                'Medium'   { 'medium' }
                'Low'      { 'low' }
                default    { 'info' }
            }
            $rows += @"
<tr>
<td><code>$([System.Web.HttpUtility]::HtmlEncode($fix.CheckId))</code></td>
<td>$([System.Web.HttpUtility]::HtmlEncode($fix.CheckName))</td>
<td><span class="badge badge-sev-$sevClass">$([System.Web.HttpUtility]::HtmlEncode($fix.Severity))</span></td>
<td>$([System.Web.HttpUtility]::HtmlEncode($fix.Effort))</td>
<td>~$($fix.EstimatedHours)h</td>
</tr>
"@
        }
        return $rows
    }

    $freeRows = & $fixRowsHtml $freeFixes
    $lowRows = & $fixRowsHtml $lowFixes
    $medRows = & $fixRowsHtml $medFixes

    $complianceRows = ''
    foreach ($fw in $complianceFrameworks) {
        $complianceRows += "<tr><td>$(& $esc ([string]$fw.Framework))</td><td><span class=`"verdict-fail`">$($fw.GapCount) gap(s)</span></td></tr>`n"
    }

    $extraCss = @'
.phase { background: var(--g-surface); border-radius: var(--radius); padding: 1.1rem 1.4rem; margin: 1.2rem 0; }
.phase-head { display: flex; justify-content: space-between; align-items: baseline; gap: 1rem; flex-wrap: wrap; }
.phase-title { font-weight: 600; font-size: 1.1rem; color: var(--g-heading); }
.phase-cost { color: var(--g-ok); font-weight: 600; white-space: nowrap; }
.phase > p:first-of-type { margin-top: 0.4em; }
'@

    $subtitle = "<strong>$(& $esc $OrganizationName)</strong> &middot; Profile: $(& $esc $ProfileName) &middot; Generated: $timestamp UTC"
    $shellStart = Get-GuerrillaReportShellStart `
        -Title 'Security Budget Justification' `
        -Subtitle $subtitle `
        -HtmlTitle "Guerrilla Budget Justification - $OrganizationName - $timestamp UTC" `
        -TopbarMeta 'Budget Justification' `
        -Style $Style -ExtraCss $extraCss

    $html = @"
$shellStart
<h2>Executive Summary</h2>
<div class="stat-grid">
<div class="stat">
<span class="value" style="color:$scoreColor">$score</span>
<span class="label">Guerrilla Score$(if ($label) { " ($(& $esc $label))" })</span>
</div>
<div class="stat">
<span class="value" style="color:var(--g-sev-critical)">$criticalFails</span>
<span class="label">Critical Failures</span>
</div>
<div class="stat">
<span class="value" style="color:var(--g-sev-high)">$highFails</span>
<span class="label">High Failures</span>
</div>
<div class="stat">
<span class="value">$totalChecks</span>
<span class="label">Total Checks ($passCount pass / $failCount fail / $warnCount warn)</span>
</div>
</div>

$(if ($complianceFrameworks.Count -gt 0) {
@"
<h2>Compliance Impact</h2>
<p>The following compliance frameworks have gaps based on current audit findings:</p>
<div class="table-wrap">
<table>
<thead><tr><th>Framework</th><th>Gaps Found</th></tr></thead>
<tbody>
$complianceRows
</tbody>
</table>
</div>
"@
})

<h2>Recommended Investment Phases</h2>

<div class="phase">
<div class="phase-head">
<span class="phase-title">Phase 1: Quick Wins (No Cost)</span>
<span class="phase-cost">$($costRanges.Free.annualCostRange ?? '$0')</span>
</div>
<p>Configuration changes using existing tools &middot; highest ROI, immediate security improvement.</p>
$(if ($freeFixes.Count -gt 0) {
@"
<div class="table-wrap">
<table>
<thead><tr><th>Check</th><th>Finding</th><th>Severity</th><th>Effort</th><th>Time</th></tr></thead>
<tbody>
$freeRows
</tbody>
</table>
</div>
<p><strong>$($freeFixes.Count) action(s)</strong> &middot; Estimated total effort: $([Math]::Round(($freeFixes | Measure-Object EstimatedHours -Sum).Sum, 1)) hours</p>
"@
} else { '<p>No free fixes identified.</p>' })
</div>

<div class="phase">
<div class="phase-head">
<span class="phase-title">Phase 2: Low-Cost Improvements</span>
<span class="phase-cost">$($costRanges.Low.annualCostRange ?? '$0 - $500')</span>
</div>
<p>Minor purchases or license add-ons within existing budget.</p>
$(if ($lowFixes.Count -gt 0) {
@"
<div class="table-wrap">
<table>
<thead><tr><th>Check</th><th>Finding</th><th>Severity</th><th>Effort</th><th>Time</th></tr></thead>
<tbody>
$lowRows
</tbody>
</table>
</div>
<p><strong>$($lowFixes.Count) action(s)</strong> &middot; Estimated total effort: $([Math]::Round(($lowFixes | Measure-Object EstimatedHours -Sum).Sum, 1)) hours</p>
"@
} else { '<p>No low-cost fixes identified.</p>' })
</div>

<div class="phase">
<div class="phase-head">
<span class="phase-title">Phase 3: Moderate Investment</span>
<span class="phase-cost">$($costRanges.Medium.annualCostRange ?? '$500 - $5,000')</span>
</div>
<p>License upgrades or add-on products for enhanced security capabilities.</p>
$(if ($medFixes.Count -gt 0) {
@"
<div class="table-wrap">
<table>
<thead><tr><th>Check</th><th>Finding</th><th>Severity</th><th>Effort</th><th>Time</th></tr></thead>
<tbody>
$medRows
</tbody>
</table>
</div>
<p><strong>$($medFixes.Count) action(s)</strong> &middot; Estimated total effort: $([Math]::Round(($medFixes | Measure-Object EstimatedHours -Sum).Sum, 1)) hours</p>
"@
} else { '<p>No medium-cost fixes identified.</p>' })
</div>

$(if ($highCostFixes.Count -gt 0) {
@"
<div class="phase">
<div class="phase-head">
<span class="phase-title">Phase 4: Strategic Investment</span>
<span class="phase-cost">$($costRanges.High.annualCostRange ?? '$5,000+')</span>
</div>
<p>Major purchases or infrastructure changes for long-term security posture improvement.</p>
<p><strong>$($highCostFixes.Count) item(s)</strong> identified requiring significant investment. Contact your security advisor for detailed scoping.</p>
</div>
"@
})

<p style="color:var(--g-muted);font-size:0.9rem;font-style:italic;">This report is for internal planning purposes.</p>
$(Get-GuerrillaReportShellEnd -FooterNote 'Budget Justification' -TimestampText "$timestamp UTC")
"@

    $html | Set-Content -Path $OutputPath -Encoding UTF8

    return [PSCustomObject]@{
        PSTypeName = 'Guerrilla.BudgetJustification'
        Success    = $true
        Path       = (Resolve-Path $OutputPath).Path
        Message    = "Budget justification exported to $OutputPath"
        Summary    = [PSCustomObject]@{
            GuerrillaScore  = $score
            TotalChecks     = $totalChecks
            CriticalFails   = $criticalFails
            HighFails       = $highFails
            FreeFixCount    = $freeFixes.Count
            LowCostFixCount = $lowFixes.Count
            MedCostFixCount = $medFixes.Count
            HighCostFixCount = $highCostFixes.Count
            ComplianceGaps   = $complianceFrameworks
        }
    }
}
