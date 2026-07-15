# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Export-DashboardHtml {
    <#
    .SYNOPSIS
        Generates the unified HTML dashboard with CSS tabs for each platform.
    .PARAMETER ScoreResult
        Guerrilla Score result object.
    .PARAMETER Findings
        Array of audit finding objects.
    .PARAMETER ScanResults
        Accepted for caller compatibility; not rendered. The dashboard shows
        assessment results only.
    .PARAMETER OutputPath
        File path for the HTML output.
    .PARAMETER OrganizationName
        Organization name for the header.
    .PARAMETER Style
        Report style: Auto (follow the OS), Light, or Dark. Legacy names accepted.
    #>
    [CmdletBinding()]
    param(
        [PSCustomObject]$ScoreResult,
        [PSCustomObject[]]$Findings,
        [PSCustomObject[]]$ScanResults,
        [Parameter(Mandatory)]
        [string]$OutputPath,
        [string]$OrganizationName = 'Organization',
        [ValidateSet('Auto', 'Light', 'Dark', 'Guerrilla', 'Professional', 'Slate')]
        [string]$Style = 'Auto'
    )

    $esc = { param([string]$s) [System.Web.HttpUtility]::HtmlEncode($s) }
    $html = [System.Text.StringBuilder]::new(65536)
    $timestampStr = [datetime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss') + ' UTC'

    $score = $ScoreResult.Score ?? 0
    $label = $ScoreResult.Label ?? ''

    # Score ring
    $ringColor = Get-GuerrillaScoreColorVar -Score ([int]$score)
    $circumference = 2 * [Math]::PI * 50
    $dashoffset = $circumference * (1 - ([int]$score / 100))

    # Stats
    $totalFindings = ($Findings ?? @()).Count
    $failCount = @($Findings | Where-Object Status -eq 'FAIL').Count
    $passCount = @($Findings | Where-Object Status -eq 'PASS').Count
    $warnCount = @($Findings | Where-Object Status -eq 'WARN').Count
    $passRate = if ($totalFindings -gt 0) { [Math]::Round(100 * $passCount / $totalFindings, 0) } else { 0 }

    # Platform data
    $platforms = @{
        'Active Directory' = @{ Findings = @($Findings | Where-Object { ($_.CheckId ?? '') -match '^AD' }) }
        'Cloud'            = @{ Findings = @($Findings | Where-Object { ($_.CheckId ?? '') -match '^(AUTH|ADMIN|EMAIL|COLLAB|DRIVE|OAUTH|DEVICE|LOG|EID|M365|AZIAM|INTUNE)' }) }
    }

    # Components breakdown
    $components = $ScoreResult.Components
    $componentHtml = ''
    if ($components) {
        foreach ($comp in @('Posture', 'Threats', 'Coverage', 'Trend')) {
            $c = $components.$comp
            if ($c) {
                $barWidth = [Math]::Max(2, $c.Score)
                $componentHtml += @"
<div class="comp-row">
  <div class="comp-head"><span>$comp</span><span>$($c.Score) ($([Math]::Round($c.Weight * 100))%)</span></div>
  <div class="comp-bar-bg"><div class="comp-bar-fill" style="width:${barWidth}%"></div></div>
</div>
"@
            }
        }
    }

    # Findings table rows (sorted by severity)
    $findingsTableHtml = ''
    $sortedFindings = @($Findings | Where-Object Status -in @('FAIL', 'WARN') | Sort-Object @{Expression={
        switch ($_.Severity) { 'Critical' { 0 } 'High' { 1 } 'Medium' { 2 } 'Low' { 3 } default { 4 } }
    }} | Select-Object -First 50)

    foreach ($f in $sortedFindings) {
        $sevClass = ("$($f.Severity ?? 'Info')").ToLower()
        $statusClass = ("$($f.Status)").ToLower()
        $findingsTableHtml += @"
    <tr>
      <td><code>$(& $esc ($f.CheckId ?? ''))</code></td>
      <td>$(& $esc ($f.Name ?? $f.CheckName ?? ''))</td>
      <td><span class="badge badge-sev-$sevClass">$(& $esc "$($f.Severity)")</span></td>
      <td><span class="badge badge-status-$statusClass">$(& $esc "$($f.Status)")</span></td>
      <td>$(& $esc ($f.Category ?? ''))</td>
    </tr>
"@
    }

    # Platform cards
    $platformCardsHtml = ''
    foreach ($tName in @('Active Directory', 'Cloud')) {
        $t = $platforms[$tName]
        $tFail = @($t.Findings | Where-Object Status -eq 'FAIL').Count
        $tTotal = $t.Findings.Count
        $tScore = if ($tTotal -gt 0) { [Math]::Round(100 * ($tTotal - $tFail) / $tTotal, 0) } else { 'N/A' }
        $isActive = $tTotal -gt 0
        $tScoreColor = if ($isActive) { Get-GuerrillaScoreColorVar -Score ([int]$tScore) } else { 'var(--g-muted)' }

        $platformCardsHtml += @"
  <div class="cat-card">
    <div class="cat-header">
      <div class="cat-name">$tName</div>
      <div class="cat-score" style="color:$tScoreColor">$(if ($isActive) { "$tScore%" } else { 'N/A' })</div>
    </div>
    $(if ($isActive) {
        "<div class=`"cat-counts`"><span>Checks: $tTotal</span><span class=`"verdict-fail`">Failures: $tFail</span></div>"
    } else {
        "<div class=`"cat-counts`"><span>Not scanned</span></div>"
    })
  </div>
"@
    }

    $extraCss = @'
.comp-row { margin: 0.7rem 0; }
.comp-head { display: flex; justify-content: space-between; font-size: 0.9rem; }
.comp-bar-bg { height: 6px; background: var(--g-surface-alt); border-radius: 3px; overflow: hidden; margin-top: 0.3rem; }
.comp-bar-fill { height: 100%; border-radius: 3px; background: var(--g-accent); }
'@

    $subtitle = "$(& $esc $OrganizationName) &middot; Generated: $timestampStr"
    [void]$html.Append((Get-GuerrillaReportShellStart `
        -Title 'Security Dashboard' `
        -Subtitle $subtitle `
        -HtmlTitle "Security Dashboard - $OrganizationName" `
        -TopbarMeta 'Dashboard' `
        -Style $Style -ExtraCss $extraCss))

    [void]$html.Append(@"
<div class="score-panel">
  <div class="score-ring">
    <svg viewBox="0 0 120 120" width="120" height="120">
      <circle cx="60" cy="60" r="50" fill="none" stroke="var(--g-surface-alt)" stroke-width="10"/>
      <circle cx="60" cy="60" r="50" fill="none" stroke="$ringColor" stroke-width="10"
              stroke-dasharray="$circumference" stroke-dashoffset="$dashoffset"
              stroke-linecap="round"/>
    </svg>
    <div class="value">$score</div>
  </div>
  <div class="score-detail">
    <div class="label" style="color:$ringColor">$(& $esc "$label")</div>
    <div class="desc">Guerrilla Score (0-100)</div>
    <div class="desc">$totalFindings checks evaluated &middot; $passCount passed, $failCount failed, $warnCount warnings</div>
  </div>
</div>

$(if ($componentHtml) {
@"
<h2>Score Components</h2>
<div class="card">
$componentHtml
</div>
"@
})

<div class="stat-grid">
  <div class="stat"><span class="value">$totalFindings</span><span class="label">Total Checks</span></div>
  <div class="stat"><span class="value" style="color:var(--g-ok)">$passRate%</span><span class="label">Pass Rate</span></div>
  <div class="stat"><span class="value" style="color:var(--g-bad)">$failCount</span><span class="label">Failures</span></div>
  <div class="stat"><span class="value" style="color:var(--g-warn)">$warnCount</span><span class="label">Warnings</span></div>
</div>

<h2>Platform Overview</h2>
<div class="category-grid">
$platformCardsHtml
</div>

$(if ($findingsTableHtml) {
@"
<h2>Top Findings</h2>
<div class="table-wrap">
<table>
<thead><tr><th>ID</th><th>Finding</th><th>Severity</th><th>Status</th><th>Category</th></tr></thead>
<tbody>
$findingsTableHtml
</tbody>
</table>
</div>
$(if ($sortedFindings.Count -ge 50) { "<p class='ap-note'>Showing top 50 findings. See detailed reports for full listing.</p>" })
"@
})
"@)

    [void]$html.Append((Get-GuerrillaReportShellEnd `
        -FooterNote 'Unified Dashboard' `
        -TimestampText $timestampStr))

    $html.ToString() | Set-Content -Path $OutputPath -Encoding UTF8
    return $OutputPath
}
