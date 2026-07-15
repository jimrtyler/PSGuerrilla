# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Export-EntraReportHtml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Result,

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [AllowNull()]$RunDiff,

        [ValidateSet('Auto', 'Light', 'Dark', 'Guerrilla', 'Professional', 'Slate')]
        [string]$Style = 'Auto',

        [hashtable]$Branding
    )

    $esc = { param([string]$s) [System.Web.HttpUtility]::HtmlEncode($s) }

    $findings = $Result.Findings
    $score = $Result.Score
    $overallScore = $score.OverallScore
    $categoryScores = $score.CategoryScores
    $timestampStr = $Result.ScanStart.ToString('yyyy-MM-dd HH:mm:ss') + ' UTC'

    # --- Counts ---
    $totalChecks = $findings.Count
    $passCount = @($findings | Where-Object Status -eq 'PASS').Count
    $failCount = @($findings | Where-Object Status -eq 'FAIL').Count
    $warnCount = @($findings | Where-Object Status -eq 'WARN').Count
    $skipCount = @($findings | Where-Object Status -in @('SKIP', 'ERROR')).Count

    $failFindings = @($findings | Where-Object Status -eq 'FAIL')
    $critCount = @($failFindings | Where-Object Severity -eq 'Critical').Count
    $highCount = @($failFindings | Where-Object Severity -eq 'High').Count
    $medCount = @($failFindings | Where-Object Severity -eq 'Medium').Count
    $lowCount = @($failFindings | Where-Object Severity -eq 'Low').Count

    $scoreColor = Get-GuerrillaScoreColorVar -Score $overallScore
    $scoreLabel = Get-AuditScoreLabel -Score $overallScore

    $html = [System.Text.StringBuilder]::new(65536)

    # ═══ SHELL + HEADER ═══
    $subtitle = "Tenant: $(& $esc $Result.TenantId) &middot; Generated: $timestampStr"
    [void]$html.Append((Get-GuerrillaReportShellStart `
        -Title 'Entra ID / M365 Report' `
        -Subtitle $subtitle `
        -HtmlTitle "Guerrilla Entra ID / M365 Report - $($Result.TenantId) - $timestampStr" `
        -TopbarMeta 'Entra ID / M365 Assessment' `
        -Style $Style -Branding $Branding))

    # ═══ SCORE PANEL ═══
    $circumference = 2 * [Math]::PI * 50
    $dashoffset = $circumference * (1 - ($overallScore / 100))

    [void]$html.Append(@"
<div class="score-panel">
  <div class="score-ring">
    <svg viewBox="0 0 120 120" width="120" height="120">
      <circle cx="60" cy="60" r="50" fill="none" stroke="var(--g-surface-alt)" stroke-width="10"/>
      <circle cx="60" cy="60" r="50" fill="none" stroke="$scoreColor" stroke-width="10"
              stroke-dasharray="$circumference" stroke-dashoffset="$dashoffset"
              stroke-linecap="round"/>
    </svg>
    <div class="value">$overallScore</div>
  </div>
  <div class="score-detail">
    <div class="label" style="color:$scoreColor">$(& $esc $scoreLabel)</div>
    <div class="desc">Entra ID / Azure / M365 security posture score (0-100)</div>
    <div class="desc">$totalChecks checks evaluated &middot; $passCount passed, $failCount failed, $warnCount warnings, $skipCount skipped</div>
  </div>
</div>
"@)

    # ═══ SUMMARY STATS ═══
    [void]$html.Append(@"
<div class="stat-grid">
  <div class="stat"><span class="value">$totalChecks</span><span class="label">Total Checks</span></div>
  <div class="stat"><span class="value" style="color:var(--g-ok)">$passCount</span><span class="label">Passed</span></div>
  <div class="stat"><span class="value" style="color:var(--g-bad)">$failCount</span><span class="label">Failed</span></div>
  <div class="stat"><span class="value" style="color:var(--g-warn)">$warnCount</span><span class="label">Warnings</span></div>
  <div class="stat"><span class="value" style="color:var(--g-muted)">$skipCount</span><span class="label">Skipped</span></div>
</div>
"@)

    # ═══ WHAT CHANGED SINCE LAST RUN — shared section, before findings ═══
    [void]$html.Append((Get-GuerrillaComparisonSectionHtml -RunDiff $RunDiff -Esc $esc))

    # ═══ ZERO TRUST POSTURE (CISA ZTMM) — pillar scores that disclose their own coverage ═══
    $ztScores = @($findings | Get-ZeroTrustScore)
    if ($ztScores.Count) {
        $ztLine = ($ztScores | ForEach-Object {
            $pct  = if ($null -ne $_.ScorePercent) { "$($_.ScorePercent)%" } else { 'n/a' }
            $mark = if ($_.CoverageConfidence -ne 'Solid') { " <span style=`"color:var(--g-muted)`">($($_.CoverageConfidence))</span>" } else { '' }
            "$(& $esc $_.Pillar) <strong>$pct</strong>$mark"
        }) -join ' &middot; '
        [void]$html.Append(@"
<div class="notice">
  <p><strong>Zero Trust posture</strong> (CISA ZTMM): $ztLine</p>
</div>
"@)
    }

    # ═══ SEVERITY BREAKDOWN ═══
    if ($failCount -gt 0) {
        [void]$html.Append(@"
<div class="stat-grid">
  <div class="stat"><span class="value" style="color:var(--g-sev-critical)">$critCount</span><span class="label">Critical</span></div>
  <div class="stat"><span class="value" style="color:var(--g-sev-high)">$highCount</span><span class="label">High</span></div>
  <div class="stat"><span class="value" style="color:var(--g-sev-medium)">$medCount</span><span class="label">Medium</span></div>
  <div class="stat"><span class="value" style="color:var(--g-sev-low)">$lowCount</span><span class="label">Low</span></div>
</div>
"@)
    }

    # ═══ CATEGORY SCORES ═══
    [void]$html.Append('<h2>Category Scores</h2><div class="category-grid">')
    foreach ($cat in ($categoryScores.GetEnumerator() | Sort-Object { $_.Value.Score })) {
        $catScore = $cat.Value.Score
        $catColor = Get-GuerrillaScoreColorVar -Score $catScore
        [void]$html.Append(@"
  <div class="cat-card">
    <div class="cat-header">
      <div class="cat-name">$(& $esc $cat.Key)</div>
      <div class="cat-score" style="color:$catColor">$catScore</div>
    </div>
    <div class="cat-bar-bg"><div class="cat-bar-fill" style="width:${catScore}%;background:$catColor"></div></div>
    <div class="cat-counts">
      <span class="verdict-pass">Pass: $($cat.Value.Pass)</span>
      <span class="verdict-fail">Fail: $($cat.Value.Fail)</span>
      <span class="verdict-warn">Warn: $($cat.Value.Warn)</span>
      <span class="verdict-na">Skip: $($cat.Value.Skip)</span>
    </div>
  </div>
"@)
    }
    [void]$html.Append('</div>')

    # ═══ ALL FINDINGS (interactive filter over the table below) ═══
    [void]$html.Append('<h2>All Findings</h2>')
    [void]$html.Append((Get-GuerrillaFindingsFilterHtml))

    [void]$html.Append(@"
<div class="table-wrap">
<table id="findings-table">
  <thead><tr><th>ID</th><th>Check</th><th>Category</th><th>Severity</th><th>Status</th><th>Current Value</th><th>Remediation</th></tr></thead>
  <tbody>
"@)

    foreach ($f in ($findings | Sort-Object -Property @{Expression = { switch ($_.Severity) { 'Critical' { 0 } 'High' { 1 } 'Medium' { 2 } 'Low' { 3 } 'Info' { 4 } default { 5 } } }}, @{Expression = { switch ($_.Status) { 'FAIL' { 0 } 'WARN' { 1 } 'PASS' { 2 } 'SKIP' { 3 } 'ERROR' { 4 } default { 5 } } }})) {
        $isAccepted = try { Test-RiskAccepted -CheckId $f.CheckId } catch { $false }
        $sevClass = $f.Severity.ToLower()
        $statusClass = if ($isAccepted) { 'accepted' } else { $f.Status.ToLower() }
        $statusLabel = if ($isAccepted) { 'ACCEPTED' } else { $f.Status }
        $rowText = & $esc (("$($f.CheckId) $($f.CheckName) $($f.Category) $($f.CurrentValue)").ToLower())

        $remCell = ''
        if ($f.RemediationSteps) {
            $remCell += "<small>$(& $esc $f.RemediationSteps)</small>"
        }
        if ($f.RemediationUrl) {
            $remCell += "<br><a href=`"$(& $esc $f.RemediationUrl)`" target=`"_blank`" rel=`"noopener`">Open in Admin Portal</a>"
        }

        [void]$html.Append(@"
    <tr class="gg-row" data-status="$(& $esc $f.Status)" data-sev="$(& $esc $f.Severity)" data-text="$rowText">
      <td><code>$(& $esc $f.CheckId)</code></td>
      <td>$(& $esc $f.CheckName)<br><small>$(& $esc $f.Description)</small></td>
      <td>$(& $esc $f.Category)<br><small>$(& $esc $f.Subcategory)</small></td>
      <td><span class="badge badge-sev-$sevClass">$(& $esc $f.Severity)</span></td>
      <td><span class="badge badge-status-$statusClass">$(& $esc $statusLabel)</span></td>
      <td>$(& $esc $f.CurrentValue)</td>
      <td>$remCell</td>
    </tr>
"@)

        if ($f.Status -in @('FAIL', 'WARN')) {
            $affectedHtml = Get-GuerrillaReportAffectedHtml -Details $f.Details
            if ($affectedHtml) {
                [void]$html.Append("<tr class=`"gg-row finding-extra`" data-status=`"$(& $esc $f.Status)`" data-sev=`"$(& $esc $f.Severity)`" data-text=`"$rowText`"><td colspan=`"7`">$affectedHtml</td></tr>")
            }
        }
    }

    [void]$html.Append('</tbody></table></div>')

    # ═══ FOOTER + SHELL END ═══
    [void]$html.Append((Get-GuerrillaReportShellEnd `
        -FooterNote 'Entra ID / M365 Audit' `
        -TimestampText $timestampStr))

    $html.ToString() | Set-Content -Path $OutputPath -Encoding UTF8
}
