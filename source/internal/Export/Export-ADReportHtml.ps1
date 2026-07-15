# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Export-ADReportHtml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Findings,

        [Parameter(Mandatory)]
        [int]$OverallScore,

        [Parameter(Mandatory)]
        [string]$ScoreLabel,

        [Parameter(Mandatory)]
        [hashtable]$CategoryScores,

        [string]$DomainName = '',
        [AllowNull()]$RunDiff,

        [Parameter(Mandatory)]
        [string]$FilePath,

        [ValidateSet('Auto', 'Light', 'Dark', 'Guerrilla', 'Professional', 'Slate')]
        [string]$Style = 'Auto',

        [hashtable]$Branding,

        # When a BloodHound OpenGraph export was written, its path — surfaced as a report callout.
        [string]$BloodHoundPath
    )

    $esc = { param([string]$s) [System.Web.HttpUtility]::HtmlEncode($s) }

    $timestampStr = [datetime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss') + ' UTC'

    # --- Counts ---
    $totalChecks = $Findings.Count
    $passCount   = @($Findings | Where-Object Status -eq 'PASS').Count
    $failCount   = @($Findings | Where-Object Status -eq 'FAIL').Count
    $warnCount   = @($Findings | Where-Object Status -eq 'WARN').Count
    $skipCount   = @($Findings | Where-Object Status -in @('SKIP', 'ERROR')).Count

    $failFindings = @($Findings | Where-Object Status -eq 'FAIL')
    $critCount    = @($failFindings | Where-Object Severity -eq 'Critical').Count
    $highCount    = @($failFindings | Where-Object Severity -eq 'High').Count
    $medCount     = @($failFindings | Where-Object Severity -eq 'Medium').Count
    $lowCount     = @($failFindings | Where-Object Severity -eq 'Low').Count

    $scoreColor = Get-GuerrillaScoreColorVar -Score $OverallScore

    $html = [System.Text.StringBuilder]::new(65536)

    # ═══ SHELL + HEADER ═══
    $subtitle = "Domain: $(& $esc $DomainName) &middot; Generated: $timestampStr"
    [void]$html.Append((Get-GuerrillaReportShellStart `
        -Title 'Active Directory Report' `
        -Subtitle $subtitle `
        -HtmlTitle "Guerrilla Active Directory Report$(if ($DomainName) { " - $DomainName" }) - $timestampStr" `
        -TopbarMeta 'Active Directory Assessment' `
        -Style $Style -Branding $Branding))

    # ═══ SCORE PANEL ═══
    $circumference = 2 * [Math]::PI * 50
    $dashoffset = $circumference * (1 - ($OverallScore / 100))

    [void]$html.Append(@"
<div class="score-panel">
  <div class="score-ring">
    <svg viewBox="0 0 120 120" width="120" height="120">
      <circle cx="60" cy="60" r="50" fill="none" stroke="var(--g-surface-alt)" stroke-width="10"/>
      <circle cx="60" cy="60" r="50" fill="none" stroke="$scoreColor" stroke-width="10"
              stroke-dasharray="$circumference" stroke-dashoffset="$dashoffset"
              stroke-linecap="round"/>
    </svg>
    <div class="value">$OverallScore</div>
  </div>
  <div class="score-detail">
    <div class="label" style="color:$scoreColor">$(& $esc $ScoreLabel)</div>
    <div class="desc">Active Directory security posture score (0-100)</div>
    <div class="desc">$totalChecks checks evaluated &middot; $passCount passed, $failCount failed, $warnCount warnings, $skipCount skipped</div>
  </div>
</div>
"@)

    # ═══ WHAT CHANGED SINCE LAST RUN — shared section, before findings ═══
    [void]$html.Append((Get-GuerrillaComparisonSectionHtml -RunDiff $RunDiff -Esc $esc))

    # ═══ EXECUTIVE SUMMARY ═══
    $verdict = switch ($true) {
        ($OverallScore -ge 90) { 'The Active Directory environment demonstrates strong security posture with minimal findings.'; break }
        ($OverallScore -ge 75) { 'The AD environment has good security posture with some areas requiring attention.'; break }
        ($OverallScore -ge 60) { 'The AD environment has fair security posture. Several important findings require remediation.'; break }
        ($OverallScore -ge 40) { 'The AD environment has poor security posture. Multiple critical and high-severity findings need immediate attention.'; break }
        default { 'The AD environment has critical security deficiencies. Immediate remediation is required to prevent compromise.' }
    }
    $noticeClass = if ($OverallScore -ge 75) { 'notice-ok' } elseif ($OverallScore -ge 60) { 'notice-warn' } else { 'notice-bad' }

    [void]$html.Append(@"
<div class="notice $noticeClass">
  <h3>Executive Summary</h3>
  <p>$(& $esc $verdict)</p>
  <p>Critical: <strong>$critCount</strong> &middot; High: <strong>$highCount</strong> &middot;
     Medium: <strong>$medCount</strong> &middot; Low: <strong>$lowCount</strong></p>
</div>
"@)

    # ═══ SECURITY MATURITY (CMMI 1-5) — shared section ═══
    [void]$html.Append((Get-GuerrillaMaturitySectionHtml -Findings $Findings -Esc $esc))

    # ═══ INDICATORS OF EXPOSURE — shared ranked exposure view ═══
    [void]$html.Append((Get-GuerrillaIndicatorsOfExposureHtml -Findings $Findings -Esc $esc))

    # ═══ ATTACK-PATH CARTOGRAPHY (visual map) + ATTACK PATHS list — shared sections ═══
    [void]$html.Append((Get-GuerrillaCartographyHtml -Findings $Findings -Esc $esc))
    [void]$html.Append((Get-GuerrillaAttackPathSectionHtml -Findings $Findings -Esc $esc))

    # ═══ BLOODHOUND EXPORT CALLOUT ═══
    if ($BloodHoundPath) {
        [void]$html.Append(@"
<h2>BloodHound Export</h2>
<div class="notice">
  <p>An OpenGraph export of the collected AD attack graph was written to <code>$(& $esc $BloodHoundPath)</code>.</p>
  <p>Import in BloodHound CE: <strong>Administration &rarr; File Ingest</strong> &rarr; upload the file, then run the built-in pathfinding queries. Nodes are SID-keyed (they overlay native SharpHound data) and edges use native BloodHound kinds.</p>
</div>
"@)
    }

    # ═══ STAT CARDS ═══
    [void]$html.Append('<div class="stat-grid">')
    $statCards = @(
        @{ Value = $totalChecks; Label = 'Total Checks'; Color = 'var(--g-heading)' }
        @{ Value = $passCount;   Label = 'Passed';       Color = 'var(--g-ok)' }
        @{ Value = $critCount;   Label = 'Critical';     Color = 'var(--g-sev-critical)' }
        @{ Value = $highCount;   Label = 'High';         Color = 'var(--g-sev-high)' }
        @{ Value = $medCount;    Label = 'Medium';       Color = 'var(--g-sev-medium)' }
        @{ Value = $lowCount;    Label = 'Low';          Color = 'var(--g-sev-low)' }
    )
    foreach ($card in $statCards) {
        [void]$html.Append(@"
  <div class="stat">
    <span class="value" style="color:$($card.Color)">$($card.Value)</span>
    <span class="label">$($card.Label)</span>
  </div>
"@)
    }
    [void]$html.Append('</div>')

    # ═══ CATEGORY SCORES ═══
    [void]$html.Append('<h2>Category Breakdown</h2><div class="category-grid">')
    foreach ($cat in ($CategoryScores.GetEnumerator() | Sort-Object { $_.Value.Score })) {
        $cs = $cat.Value.Score
        $cc = Get-GuerrillaScoreColorVar -Score $cs
        [void]$html.Append(@"
  <div class="cat-card">
    <div class="cat-header">
      <div class="cat-name">$(& $esc $cat.Key)</div>
      <div class="cat-score" style="color:$cc">$cs</div>
    </div>
    <div class="cat-bar-bg"><div class="cat-bar-fill" style="width:${cs}%;background:$cc"></div></div>
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

    # ═══ PRIORITY FINDINGS ═══
    $priorityFindings = @($Findings | Where-Object { $_.Status -eq 'FAIL' } |
        Sort-Object @{Expression={@{Critical=0;High=1;Medium=2;Low=3;Info=4}[$_.Severity] ?? 5}},CheckId)

    # ═══ INTERACTIVE FILTER BAR (live status/severity/search over the findings tables below) ═══
    [void]$html.Append((Get-GuerrillaFindingsFilterHtml))

    if ($priorityFindings.Count -gt 0) {
        [void]$html.Append(@"
<h2>Findings by Priority</h2>
<div class="table-wrap">
<table class="priority-table">
  <thead><tr><th>ID</th><th>Severity</th><th>Status</th><th>Category</th><th>Check</th><th>Finding</th><th>Remediation</th></tr></thead>
  <tbody>
"@)
        foreach ($f in $priorityFindings) {
            $isAccepted = try { Test-RiskAccepted -CheckId $f.CheckId } catch { $false }
            $sevClass = $f.Severity.ToLower()
            $statusClass = if ($isAccepted) { 'accepted' } else { $f.Status.ToLower() }
            $statusLabel = if ($isAccepted) { 'ACCEPTED' } else { $f.Status }
            $remediation = if ($f.RemediationSteps) { $f.RemediationSteps } else { $f.RecommendedValue }
            $rowText = & $esc (("$($f.CheckId) $($f.CheckName) $($f.Category) $($f.CurrentValue)").ToLower())
            [void]$html.Append(@"
    <tr class="gg-row" data-status="$(& $esc $f.Status)" data-sev="$(& $esc $f.Severity)" data-text="$rowText">
      <td><code>$(& $esc $f.CheckId)</code></td>
      <td><span class="badge badge-sev-$sevClass">$(& $esc $f.Severity)</span></td>
      <td><span class="badge badge-status-$statusClass">$(& $esc $statusLabel)</span></td>
      <td>$(& $esc $f.Category)</td>
      <td>$(& $esc $f.CheckName)</td>
      <td>$(& $esc $f.CurrentValue)</td>
      <td><small>$(& $esc $remediation)</small></td>
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
    }

    # ═══ DETAILED CATEGORY SECTIONS ═══
    [void]$html.Append('<h2>Detailed Findings by Category</h2>')

    $categoryGroups = $Findings | Group-Object -Property Category | Sort-Object Name
    foreach ($group in $categoryGroups) {
        $catFindings = @($group.Group | Sort-Object @{Expression={@{Critical=0;High=1;Medium=2;Low=3;Info=4}[$_.Severity] ?? 5}},CheckId)
        $catPass = @($catFindings | Where-Object Status -eq 'PASS').Count
        $catFail = @($catFindings | Where-Object Status -eq 'FAIL').Count
        $catWarn = @($catFindings | Where-Object Status -eq 'WARN').Count

        [void]$html.Append(@"
<details class="cat-detail">
  <summary>$(& $esc $group.Name)<span class="sum-counts">$($catFindings.Count) checks &middot; P:$catPass F:$catFail W:$catWarn</span></summary>
  <div class="detail-body">
    <table>
      <thead><tr><th>ID</th><th>Severity</th><th>Status</th><th>Check</th><th>Current Value</th><th>Recommended</th><th>Remediation</th></tr></thead>
      <tbody>
"@)
        foreach ($f in $catFindings) {
            $isAccepted = try { Test-RiskAccepted -CheckId $f.CheckId } catch { $false }
            $sevClass = $f.Severity.ToLower()
            $statusClass = if ($isAccepted) { 'accepted' } else { $f.Status.ToLower() }
            $statusLabel = if ($isAccepted) { 'ACCEPTED' } else { $f.Status }
            $rowText = & $esc (("$($f.CheckId) $($f.CheckName) $($f.Category) $($f.CurrentValue)").ToLower())
            [void]$html.Append(@"
        <tr class="gg-row" data-status="$(& $esc $f.Status)" data-sev="$(& $esc $f.Severity)" data-text="$rowText">
          <td><code>$(& $esc $f.CheckId)</code></td>
          <td><span class="badge badge-sev-$sevClass">$(& $esc $f.Severity)</span></td>
          <td><span class="badge badge-status-$statusClass">$(& $esc $statusLabel)</span></td>
          <td>$(& $esc $f.CheckName)<br><small>$(& $esc $f.Description)</small></td>
          <td>$(& $esc $f.CurrentValue)</td>
          <td>$(& $esc $f.RecommendedValue)</td>
          <td><small>$(& $esc $f.RemediationSteps)</small></td>
        </tr>
"@)
            if ($f.Status -in @('FAIL', 'WARN')) {
                $affectedHtml = Get-GuerrillaReportAffectedHtml -Details $f.Details
                if ($affectedHtml) {
                    [void]$html.Append("<tr class=`"gg-row finding-extra`" data-status=`"$(& $esc $f.Status)`" data-sev=`"$(& $esc $f.Severity)`" data-text=`"$rowText`"><td colspan=`"7`">$affectedHtml</td></tr>")
                }
            }
        }
        [void]$html.Append('</tbody></table></div></details>')
    }

    # ═══ COMPLIANCE MAPPING ═══
    $findingsWithCompliance = @($Findings | Where-Object {
        $_.Compliance.MitreAttack.Count -gt 0 -or $_.Compliance.NistSp80053.Count -gt 0 -or
        ($_.Compliance.Anssi ?? @()).Count -gt 0 -or ($_.Compliance.CisAd ?? @()).Count -gt 0
    })
    if ($findingsWithCompliance.Count -gt 0) {
        [void]$html.Append(@"
<h2>Compliance Mapping</h2>
<div class="table-wrap">
<table class="compliance-table">
  <thead><tr><th>Check ID</th><th>Status</th><th>MITRE ATT&amp;CK</th><th>NIST SP 800-53</th><th>CIS AD</th><th>ANSSI</th></tr></thead>
  <tbody>
"@)
        foreach ($f in ($findingsWithCompliance | Where-Object Status -eq 'FAIL' | Select-Object -First 50)) {
            $mitre = ($f.Compliance.MitreAttack | ForEach-Object { "<code>$_</code>" }) -join ' '
            $nist = ($f.Compliance.NistSp80053 | ForEach-Object { "<code>$_</code>" }) -join ' '
            $cisAd = (($f.Compliance.CisAd ?? @()) | ForEach-Object { "<code>$_</code>" }) -join ' '
            $anssi = (($f.Compliance.Anssi ?? @()) | ForEach-Object { "<code>$_</code>" }) -join ' '
            $statusClass = $f.Status.ToLower()
            [void]$html.Append(@"
    <tr>
      <td><code>$(& $esc $f.CheckId)</code></td>
      <td><span class="badge badge-status-$statusClass">$(& $esc $f.Status)</span></td>
      <td>$mitre</td><td>$nist</td><td>$cisAd</td><td>$anssi</td>
    </tr>
"@)
        }
        [void]$html.Append('</tbody></table></div>')
    }

    # ═══ FOOTER + SHELL END ═══
    [void]$html.Append((Get-GuerrillaReportShellEnd `
        -FooterNote 'Active Directory Audit' `
        -TimestampText $timestampStr))

    Set-Content -Path $FilePath -Value $html.ToString() -Encoding UTF8
}
