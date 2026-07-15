# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Export-ExecutiveSummary {
    <#
    .SYNOPSIS
        Generates a non-technical board-ready one-pager HTML report.
    .DESCRIPTION
        Produces a concise executive summary suitable for school boards, leadership,
        and non-technical stakeholders. Includes the Guerrilla Score, key risk areas,
        compliance gaps, and top recommended actions — all in plain language.
    .PARAMETER Findings
        Array of audit finding objects. If not provided, reads from latest state.
    .PARAMETER OutputPath
        File path for the HTML output. Default: Guerrilla-Executive-Summary.html
    .PARAMETER OrganizationName
        Name of the organization for the report header.
    .PARAMETER ProfileName
        Baseline profile context. Default: configured profile.
    .PARAMETER Style
        Report style: Auto (follow the OS), Light, or Dark. Legacy names accepted.
    .EXAMPLE
        Export-ExecutiveSummary -OrganizationName 'Springfield USD'
    #>
    [CmdletBinding()]
    param(
        [PSCustomObject[]]$Findings,
        [string]$OutputPath,
        [string]$OrganizationName = 'Organization',
        [string]$ProfileName,

        [ValidateSet('Auto', 'Light', 'Dark', 'Guerrilla', 'Professional', 'Slate')]
        [string]$Style = 'Auto'
    )

    if (-not $OutputPath) { $OutputPath = Join-Path (Get-Location) 'Guerrilla-Executive-Summary.html' }

    $dataDir = Get-GuerrillaDataRoot

    # Load findings if not provided
    if (-not $Findings -or $Findings.Count -eq 0) {
        if (Test-Path $dataDir) {
            foreach ($f in (Get-ChildItem -Path $dataDir -Filter '*.findings.json' -ErrorAction SilentlyContinue)) {
                try { $Findings += @(Get-Content $f.FullName -Raw | ConvertFrom-Json) } catch { }
            }
        }
    }

    $esc = { param([string]$s) [System.Web.HttpUtility]::HtmlEncode($s) }
    $timestamp = [datetime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss')

    # Calculate score
    $scoreResult = $null
    try { $scoreResult = Get-GuerrillaScoreCalculation -AuditFindings $Findings } catch { }
    $score = $scoreResult.Score ?? 'N/A'
    $label = $scoreResult.Label ?? ''

    $scoreNum = 0
    $scoreIsNumeric = [int]::TryParse("$score", [ref]$scoreNum)
    $scoreColor = if ($scoreIsNumeric) { Get-GuerrillaScoreColorVar -Score $scoreNum } else { 'var(--g-sev-info)' }

    # Maturity model (CMMI-style 1-5) — the executive maturity rating
    $maturity = $null
    try { $maturity = Get-GuerrillaMaturity -Findings $Findings } catch { }
    $matColors = @{
        '1' = 'var(--g-sev-critical)'
        '2' = 'var(--g-sev-high)'
        '3' = 'var(--g-sev-medium)'
        '4' = 'var(--g-sev-low)'
        '5' = 'var(--g-ok)'
    }
    $maturityStat = ''
    $maturitySection = ''
    if ($maturity -and $maturity.OverallLevel) {
        $matLevel = [int]$maturity.OverallLevel
        $matColor = $matColors["$matLevel"] ?? 'var(--g-sev-info)'
        $matLabel = & $esc ([string]$maturity.OverallLabel)
        $maturityStat = "<div class=`"stat`"><span class=`"value`" style=`"color:$matColor`">$matLevel/5</span><span class=`"label`">Maturity ($matLabel)</span></div>"

        $catRows = ''
        foreach ($k in ($maturity.CategoryLevels.Keys | Sort-Object { [int]$maturity.CategoryLevels[$_].Level })) {
            $cl = $maturity.CategoryLevels[$k]
            $cc = $matColors["$([int]$cl.Level)"] ?? 'var(--g-sev-info)'
            $catRows += "<tr><td>$(& $esc ([string]$cl.Category))</td><td style=`"color:$cc;font-weight:600;`">Level $([int]$cl.Level)</td><td>$(& $esc ([string]$cl.Label))</td></tr>"
        }
        $blockerHtml = ''
        if ($maturity.NextLevel) {
            $bl = (@($maturity.NextLevelBlockers | Select-Object -First 8 | ForEach-Object { "<li>$(& $esc ([string]$_))</li>" }) -join '')
            if ($bl) { $blockerHtml = "<p>To reach <strong>Level $([int]$maturity.NextLevel)</strong>, address:</p><ul>$bl</ul>" }
        }
        $maturitySection = @"
<h2>Security Maturity</h2>
<div class="card">
<p>Overall maturity: <strong style="color:$matColor">Level $matLevel of 5: $matLabel</strong>. The lowest unmet control anchors the rating, so a single critical exposure caps the score until it is resolved (CMMI-style scale: 1 Initial to 5 Optimized).</p>
$blockerHtml
<div class="table-wrap">
<table><thead><tr><th>Category</th><th>Level</th><th>Maturity</th></tr></thead><tbody>$catRows</tbody></table>
</div>
</div>
"@
    }

    # Key stats
    $totalFindings = ($Findings ?? @()).Count
    $criticalFails = @($Findings | Where-Object { $_.Status -eq 'FAIL' -and $_.Severity -eq 'Critical' }).Count
    $highFails = @($Findings | Where-Object { $_.Status -eq 'FAIL' -and $_.Severity -eq 'High' }).Count
    $passCount = @($Findings | Where-Object Status -eq 'PASS').Count
    $passRate = if ($totalFindings -gt 0) { [Math]::Round(100 * $passCount / $totalFindings, 0) } else { 0 }

    # Compliance
    $complianceGaps = @()
    try {
        $complianceGaps = @(Get-ComplianceCrosswalk -Findings $Findings -FailOnly | Group-Object Framework | ForEach-Object {
            [PSCustomObject]@{ Framework = $_.Name; Gaps = $_.Count }
        })
    } catch { }

    # Quick wins
    $quickWins = @()
    try { $quickWins = @(Get-QuickWins -Findings $Findings -Top 5 -MaxCostTier Free) } catch { }

    # Top critical findings for narrative
    $topCritical = @($Findings | Where-Object { $_.Status -eq 'FAIL' -and $_.Severity -eq 'Critical' } | Select-Object -First 5)
    $topHigh = @($Findings | Where-Object { $_.Status -eq 'FAIL' -and $_.Severity -eq 'High' } | Select-Object -First 5)

    # Build critical findings rows
    $criticalRows = ''
    foreach ($f in $topCritical) {
        $criticalRows += "<li><strong>$(& $esc ($f.Name ?? $f.CheckId ?? 'Unknown'))</strong> &middot; $(& $esc ($f.Description ?? ''))</li>`n"
    }
    foreach ($f in $topHigh) {
        $criticalRows += "<li><strong>$(& $esc ($f.Name ?? $f.CheckId ?? 'Unknown'))</strong> &middot; $(& $esc ($f.Description ?? ''))</li>`n"
    }

    # Quick wins rows
    $quickWinRows = ''
    foreach ($qw in $quickWins) {
        $quickWinRows += "<li><strong>$(& $esc $qw.CheckName)</strong> ($(& $esc $qw.Severity), ~$($qw.EstimatedHours)h effort)</li>`n"
    }

    # Compliance rows
    $complianceHtml = ''
    foreach ($cg in $complianceGaps) {
        $complianceHtml += "<span class=`"badge`"><strong>$(& $esc ([string]$cg.Framework))</strong>: $($cg.Gaps) gap(s)</span>`n"
    }

    $html = [System.Text.StringBuilder]::new(32768)

    $subtitle = "$(& $esc $OrganizationName) &middot; $(if ($ProfileName) { "$(& $esc $ProfileName) Profile &middot; " })$timestamp UTC"
    [void]$html.Append((Get-GuerrillaReportShellStart `
        -Title 'Executive Security Summary' `
        -Subtitle $subtitle `
        -HtmlTitle "Guerrilla Executive Summary - $OrganizationName - $timestamp UTC" `
        -TopbarMeta 'Executive Summary' `
        -Style $Style))

    $circumference = 2 * [Math]::PI * 50
    $dashOffset = if ($scoreIsNumeric) { $circumference * (1 - ($scoreNum / 100)) } else { $circumference }
    $verdict = if (-not $scoreIsNumeric) { 'No score could be computed from the available findings. Run a scan to establish a baseline.' }
        elseif ($scoreNum -ge 75) { 'Your organization has a strong security foundation. Continue monitoring and address remaining gaps.' }
        elseif ($scoreNum -ge 50) { 'Your security posture has room for improvement. Priority action on critical findings is recommended.' }
        else { 'Immediate attention required. Critical security gaps put your organization at elevated risk.' }

    [void]$html.Append(@"
<div class="score-panel">
  <div class="score-ring">
    <svg viewBox="0 0 120 120" width="120" height="120">
      <circle cx="60" cy="60" r="50" fill="none" stroke="var(--g-surface-alt)" stroke-width="10"/>
      <circle cx="60" cy="60" r="50" fill="none" stroke="$scoreColor" stroke-width="10"
              stroke-dasharray="$circumference" stroke-dashoffset="$dashOffset"
              stroke-linecap="round"/>
    </svg>
    <div class="value">$score</div>
  </div>
  <div class="score-detail">
    <div class="label" style="color:$scoreColor">Security Posture: $(& $esc $label)</div>
    <div class="desc">$verdict</div>
  </div>
</div>

<div class="stat-grid">
<div class="stat"><span class="value">$totalFindings</span><span class="label">Total Checks</span></div>
<div class="stat"><span class="value" style="color:var(--g-ok)">$passRate%</span><span class="label">Pass Rate</span></div>
<div class="stat"><span class="value" style="color:var(--g-sev-critical)">$criticalFails</span><span class="label">Critical Issues</span></div>
<div class="stat"><span class="value" style="color:var(--g-sev-high)">$highFails</span><span class="label">High Issues</span></div>
$maturityStat
</div>

$maturitySection
$(if ($criticalRows) {
@"
<h2>Key Findings Requiring Attention</h2>
<div class="card">
<ul>
$criticalRows
</ul>
</div>
"@
})

$(if ($complianceHtml) {
@"
<h2>Compliance Impact</h2>
<div class="card">
<p>The following compliance frameworks have identified gaps:</p>
$complianceHtml
</div>
"@
})

$(if ($quickWinRows) {
@"
<h2>Recommended Quick Wins (No Cost)</h2>
<div class="card">
<p>These actions can be completed at no cost using existing tools:</p>
<ol>
$quickWinRows
</ol>
</div>
"@
})

<h2>Next Steps</h2>
<div class="card">
<ol>
<li>Address critical findings immediately &middot; these represent the highest risk to your organization.</li>
<li>Implement the quick wins above to improve your security score with minimal effort.</li>
<li>Review the detailed technical report for complete remediation guidance.</li>
<li>Schedule a follow-up scan in 30 days to measure improvement.</li>
</ol>
</div>

<p style="color:var(--g-muted);font-size:0.9rem;font-style:italic;">This report provides a point-in-time security assessment for internal planning purposes. Findings should be validated and remediated according to organizational risk tolerance.</p>
"@)

    [void]$html.Append((Get-GuerrillaReportShellEnd `
        -FooterNote 'Executive Summary' `
        -TimestampText "$timestamp UTC"))

    $html.ToString() | Set-Content -Path $OutputPath -Encoding UTF8

    return [PSCustomObject]@{
        PSTypeName = 'Guerrilla.ExecutiveSummary'
        Success    = $true
        Path       = (Resolve-Path $OutputPath).Path
        Message    = "Executive summary exported to $OutputPath"
        Score      = $score
        Label      = $label
    }
}
