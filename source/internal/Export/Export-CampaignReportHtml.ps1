# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Export-CampaignReportHtml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Result,  # Guerrilla.CampaignResult

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [ValidateSet('Auto', 'Light', 'Dark', 'Guerrilla', 'Professional', 'Slate')]
        [string]$Style = 'Auto',

        [hashtable]$Branding
    )

    $esc = { param([string]$s) [System.Web.HttpUtility]::HtmlEncode($s) }

    $findings      = $Result.Findings
    $overallScore  = $Result.OverallScore
    $scoreLabel    = $Result.ScoreLabel
    $platformScores = $Result.PlatformScores
    $platforms      = $Result.Platforms
    $scanStart     = $Result.ScanStart
    $duration      = $Result.Duration
    $scanId        = $Result.ScanId

    $timestampStr = $scanStart.ToString('yyyy-MM-dd HH:mm:ss') + ' UTC'

    $displayLabel = $scoreLabel
    $durationStr  = if ($duration.TotalMinutes -ge 1) {
        '{0}m {1}s' -f [int][Math]::Floor($duration.TotalMinutes), $duration.Seconds
    } else {
        '{0}s' -f [int]$duration.TotalSeconds
    }

    # --- Counts ---
    $totalChecks = $findings.Count
    $passCount   = @($findings | Where-Object Status -eq 'PASS').Count
    $failCount   = @($findings | Where-Object Status -eq 'FAIL').Count
    $warnCount   = @($findings | Where-Object Status -eq 'WARN').Count
    $skipCount   = @($findings | Where-Object Status -in @('SKIP', 'ERROR')).Count

    $failFindings = @($findings | Where-Object Status -eq 'FAIL')
    $critCount    = @($failFindings | Where-Object Severity -eq 'Critical').Count
    $highCount    = @($failFindings | Where-Object Severity -eq 'High').Count
    $medCount     = @($failFindings | Where-Object Severity -eq 'Medium').Count
    $lowCount     = @($failFindings | Where-Object Severity -eq 'Low').Count

    $scoreColor = Get-GuerrillaScoreColorVar -Score $overallScore

    # --- Platform display name mapping ---
    $platformDisplayNames = @{
        'Workspace' = 'Google Workspace'
        'AD'        = 'Active Directory'
        'Cloud'     = 'Microsoft Cloud'
    }

    $extraCss = @'
.platform-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(17rem, 1fr)); gap: 1rem; margin: 1.4rem 0; }
.platform-card { background: var(--g-surface); border-radius: var(--radius); padding: 1.1rem 1.3rem; }
.platform-card .platform-header { display: flex; justify-content: space-between; align-items: baseline; gap: 0.8rem; margin-bottom: 0.5rem; }
.platform-card .platform-name { font-weight: 600; color: var(--g-heading); }
.platform-card .platform-label { font-size: 0.85rem; color: var(--g-muted); margin-top: 2px; }
.platform-card .platform-score { font-size: 1.6rem; font-weight: 600; letter-spacing: -0.02em; }
.platform-card .platform-bar-bg { height: 6px; background: var(--g-surface-alt); border-radius: 3px; overflow: hidden; margin: 0.5rem 0; }
.platform-card .platform-bar-fill { height: 100%; border-radius: 3px; }
.platform-card .platform-counts { font-size: 0.85rem; color: var(--g-muted); display: flex; flex-wrap: wrap; gap: 0.9em; }
.platform-card .platform-counts span { white-space: nowrap; }
.filter-group { display: flex; align-items: center; gap: 0.4rem; flex-wrap: wrap; margin-right: 0.6rem; }
.filter-count { font-size: 0.85rem; color: var(--g-muted); margin-left: auto; white-space: nowrap; }
.clickable-row { cursor: pointer; }
.finding-detail-row { display: none; }
.finding-detail-row.expanded { display: table-row; }
.finding-detail-row td { background: var(--g-surface); border-left: 3px solid var(--g-border-strong); padding: 1rem 1.25rem; }
.finding-detail-row:hover td { background: var(--g-surface); }
.finding-detail-content { display: grid; grid-template-columns: 1fr 1fr; gap: 0.8rem; }
.finding-detail-content .fd-block { margin-bottom: 0.2rem; }
.finding-detail-content .fd-label { font-size: 0.8rem; font-weight: 600; color: var(--g-muted); margin-bottom: 0.15rem; }
.finding-detail-content .fd-value { font-size: 0.92rem; }
.finding-detail-content .fd-full { grid-column: 1 / -1; }
@media print {
  .finding-detail-row { display: table-row !important; }
  .platform-card { break-inside: avoid; border: 1px solid var(--g-border); }
}
'@

    $html = [System.Text.StringBuilder]::new(131072)

    # ═══ SHELL + HEADER ═══
    $platformList = ($platforms | ForEach-Object {
        $displayName = $platformDisplayNames[$_]
        if (-not $displayName) { $displayName = $_ }
        & $esc $displayName
    }) -join ', '

    $subtitle = "Unified security posture assessment &middot; Generated: $timestampStr &middot; " +
        "$totalChecks checks across $($platforms.Count) platforms ($platformList)<br>" +
        "Scan ID: $(& $esc $scanId) &middot; Duration: $durationStr"

    [void]$html.Append((Get-GuerrillaReportShellStart `
        -Title 'Campaign Report' `
        -Subtitle $subtitle `
        -HtmlTitle "Guerrilla Campaign Report - $timestampStr" `
        -TopbarMeta 'Unified Campaign Assessment' `
        -Style $Style -Branding $Branding -ExtraCss $extraCss))

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
    <div class="label" style="color:$scoreColor">$(& $esc $displayLabel)</div>
    <div class="desc">Campaign score (0-100) &middot; weighted assessment of $totalChecks checks across $($platforms.Count) platforms</div>
    <div class="desc"><span class="verdict-pass">$passCount passed</span> &middot; <span class="verdict-fail">$failCount failed</span> &middot; <span class="verdict-warn">$warnCount warnings</span> &middot; <span class="verdict-na">$skipCount skipped</span></div>
  </div>
</div>
"@)

    # ═══ WHAT CHANGED SINCE LAST RUN — shared section, before findings ═══
    [void]$html.Append((Get-GuerrillaComparisonSectionHtml -RunDiff $Result.RunComparison -Esc $esc))

    # ═══ STAT CARDS ═══
    [void]$html.Append('<div class="stat-grid">')
    $statCards = @(
        @{ Value = $totalChecks; Label = 'Total Checks'; Color = 'var(--g-heading)' }
        @{ Value = $passCount;   Label = 'Passed';       Color = 'var(--g-ok)' }
        @{ Value = $failCount;   Label = 'Failed';       Color = 'var(--g-bad)' }
        @{ Value = $warnCount;   Label = 'Warnings';     Color = 'var(--g-warn)' }
        @{ Value = $skipCount;   Label = 'Skipped';      Color = 'var(--g-muted)' }
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

    # ═══ SECURITY MATURITY + ATTACK PATHS (shared sections) ═══
    # Maturity spans all platforms; attack paths only render if an AD platform was scanned.
    [void]$html.Append((Get-GuerrillaMaturitySectionHtml -Findings $findings -Esc $esc))
    [void]$html.Append((Get-GuerrillaIndicatorsOfExposureHtml -Findings $findings -Esc $esc))
    [void]$html.Append((Get-GuerrillaCartographyHtml -Findings $findings -Esc $esc))
    [void]$html.Append((Get-GuerrillaAttackPathSectionHtml -Findings $findings -Esc $esc -OmitIfAbsent))

    # ═══ PLATFORM SUMMARY CARDS ═══
    [void]$html.Append('<h2>Platform Summary</h2>')
    [void]$html.Append('<div class="platform-grid">')

    foreach ($platformKey in ($platformScores.GetEnumerator() | Sort-Object { $_.Value.Score })) {
        $tName  = $platformKey.Key
        $tData  = $platformKey.Value
        $tScore = $tData.Score
        $tColor = Get-GuerrillaScoreColorVar -Score $tScore
        $tLabel = [string]$tData.ScoreLabel

        $tPassCount = if ($null -ne $tData.PassCount) { $tData.PassCount } else { 0 }
        $tFailCount = if ($null -ne $tData.FailCount) { $tData.FailCount } else { 0 }
        $tWarnCount = if ($null -ne $tData.WarnCount) { $tData.WarnCount } else { 0 }
        $tSkipCount = if ($null -ne $tData.SkipCount) { $tData.SkipCount } else { 0 }
        $tFindingCount = if ($null -ne $tData.FindingCount) { $tData.FindingCount } else { 0 }

        [void]$html.Append(@"
<div class="platform-card">
  <div class="platform-header">
    <div>
      <span class="platform-name">$(& $esc $tName)</span>
      <div class="platform-label">$(& $esc $tLabel) &middot; $tFindingCount checks</div>
    </div>
    <span class="platform-score" style="color:$tColor">$tScore</span>
  </div>
  <div class="platform-bar-bg"><div class="platform-bar-fill" style="width:${tScore}%;background:$tColor"></div></div>
  <div class="platform-counts">
    <span class="verdict-pass">Pass: $tPassCount</span>
    <span class="verdict-fail">Fail: $tFailCount</span>
    <span class="verdict-warn">Warn: $tWarnCount</span>
    <span class="verdict-na">Skip: $tSkipCount</span>
  </div>
</div>
"@)
    }
    [void]$html.Append('</div>')

    # ═══ CATEGORY SCORE GRID (grouped by platform) ═══
    [void]$html.Append('<h2>Category Scores by Platform</h2>')

    foreach ($platformKey in ($platformScores.GetEnumerator() | Sort-Object Key)) {
        $tName = $platformKey.Key
        $tData = $platformKey.Value
        $tCategoryScores = $tData.CategoryScores

        if (-not $tCategoryScores -or $tCategoryScores.Count -eq 0) { continue }

        $tHasFailures = $false
        foreach ($cs in $tCategoryScores.Values) {
            if ($cs.Fail -and $cs.Fail -gt 0) { $tHasFailures = $true; break }
        }
        $openAttr = if ($tHasFailures) { ' open' } else { '' }

        [void]$html.Append("<details class=`"cat-detail`"$openAttr>")
        [void]$html.Append("<summary>$(& $esc $tName)<span class=`"sum-counts`">$($tCategoryScores.Count) categories</span></summary>")
        [void]$html.Append('<div class="detail-body">')
        [void]$html.Append('<div class="category-grid">')

        foreach ($cat in ($tCategoryScores.GetEnumerator() | Sort-Object { $_.Value.Score })) {
            $catScore = $cat.Value.Score
            $catColor = Get-GuerrillaScoreColorVar -Score $catScore
            $catPass  = if ($null -ne $cat.Value.Pass) { $cat.Value.Pass } else { 0 }
            $catFail  = if ($null -ne $cat.Value.Fail) { $cat.Value.Fail } else { 0 }
            $catWarn  = if ($null -ne $cat.Value.Warn) { $cat.Value.Warn } else { 0 }

            [void]$html.Append(@"
<div class="cat-card">
  <div class="cat-header">
    <div class="cat-name">$(& $esc $cat.Key)</div>
    <div class="cat-score" style="color:$catColor">$catScore</div>
  </div>
  <div class="cat-bar-bg"><div class="cat-bar-fill" style="width:${catScore}%;background:$catColor"></div></div>
  <div class="cat-counts">
    <span class="verdict-pass">Pass: $catPass</span>
    <span class="verdict-fail">Fail: $catFail</span>
    <span class="verdict-warn">Warn: $catWarn</span>
  </div>
</div>
"@)
        }
        [void]$html.Append('</div>') # category-grid
        [void]$html.Append('</div></details>')
    }

    # ═══ FINDINGS TABLE (interactive with filters) ═══
    [void]$html.Append('<h2>All Findings</h2>')

    # --- Filter bar ---
    [void]$html.Append('<div class="gg-filter" id="filterBar">')

    # Platform filter group
    [void]$html.Append('<div class="filter-group"><span class="gg-lbl">Platform</span>')
    [void]$html.Append('<button class="gg-btn active" data-filter-type="platform" data-filter-value="all" onclick="toggleFilter(this)">All</button>')
    foreach ($platformKey in ($platformScores.GetEnumerator() | Sort-Object Key)) {
        $tName = $platformKey.Key
        $tSlug = ($tName -replace '[^a-zA-Z0-9]', '-').ToLower()
        [void]$html.Append("<button class=`"gg-btn`" data-filter-type=`"platform`" data-filter-value=`"$(& $esc $tSlug)`" onclick=`"toggleFilter(this)`">$(& $esc $tName)</button>")
    }
    [void]$html.Append('</div>')

    # Status filter group
    [void]$html.Append('<div class="filter-group"><span class="gg-lbl">Status</span>')
    [void]$html.Append('<button class="gg-btn active" data-filter-type="status" data-filter-value="all" onclick="toggleFilter(this)">All</button>')
    foreach ($statusVal in @('PASS', 'FAIL', 'WARN', 'SKIP')) {
        [void]$html.Append("<button class=`"gg-btn`" data-filter-type=`"status`" data-filter-value=`"$statusVal`" onclick=`"toggleFilter(this)`">$statusVal</button>")
    }
    [void]$html.Append('</div>')

    # Severity filter group
    [void]$html.Append('<div class="filter-group"><span class="gg-lbl">Severity</span>')
    [void]$html.Append('<button class="gg-btn active" data-filter-type="severity" data-filter-value="all" onclick="toggleFilter(this)">All</button>')
    foreach ($sevVal in @('Critical', 'High', 'Medium', 'Low')) {
        [void]$html.Append("<button class=`"gg-btn`" data-filter-type=`"severity`" data-filter-value=`"$sevVal`" onclick=`"toggleFilter(this)`">$sevVal</button>")
    }
    [void]$html.Append('</div>')

    [void]$html.Append('<span class="filter-count" id="filterCount">Showing all findings</span>')
    [void]$html.Append('</div>') # gg-filter

    # --- Findings table ---
    [void]$html.Append(@'
<div class="table-wrap">
<table id="findingsTable">
  <thead>
  <tr>
    <th>Platform</th><th>Check ID</th><th>Check Name</th><th>Category</th>
    <th>Severity</th><th>Status</th><th>Current Value</th>
  </tr>
  </thead>
  <tbody>
'@)

    $sortedFindings = @($findings | Sort-Object {
        switch ($_.Severity) { 'Critical' { 0 } 'High' { 1 } 'Medium' { 2 } 'Low' { 3 } default { 4 } }
    }, {
        switch ($_.Status) { 'FAIL' { 0 } 'WARN' { 1 } 'PASS' { 2 } 'SKIP' { 3 } default { 4 } }
    }, CheckId)

    $findingIdx = 0
    foreach ($f in $sortedFindings) {
        $statusClass = $f.Status.ToLower()
        $sevClass    = $f.Severity.ToLower()
        $platform     = if ($f.Platform) { $f.Platform } else { 'Unknown' }
        $platformSlug = ($platform -replace '[^a-zA-Z0-9]', '-').ToLower()

        [void]$html.Append(@"
  <tr class="clickable-row finding-row" data-platform="$platformSlug" data-status="$($f.Status)" data-severity="$($f.Severity)" data-idx="$findingIdx" onclick="toggleFindingDetail($findingIdx)">
    <td><span class="badge">$(& $esc $platform)</span></td>
    <td><code>$(& $esc $f.CheckId)</code></td>
    <td>$(& $esc $f.CheckName)</td>
    <td>$(& $esc $f.Category)</td>
    <td><span class="badge badge-sev-$sevClass">$($f.Severity)</span></td>
    <td><span class="badge badge-status-$statusClass">$($f.Status)</span></td>
    <td>$(& $esc $f.CurrentValue)</td>
  </tr>
"@)

        # --- Finding detail row (hidden by default) ---
        $descHtml = if ($f.Description) { & $esc $f.Description } else { '' }
        $curValHtml = if ($f.CurrentValue) { & $esc $f.CurrentValue } else { '' }
        $recValHtml = if ($f.RecommendedValue) { & $esc $f.RecommendedValue } else { '' }
        $remStepsHtml = if ($f.RemediationSteps) { & $esc $f.RemediationSteps } else { '' }
        $remUrlHtml = if ($f.RemediationUrl) {
            "<a href=`"$(& $esc $f.RemediationUrl)`" target=`"_blank`" rel=`"noopener`">$(& $esc $f.RemediationUrl)</a>"
        } else { '' }

        # Compliance mappings
        $compHtml = [System.Text.StringBuilder]::new(512)
        if ($f.Compliance) {
            $compEntries = @()
            if ($f.Compliance.NistSp80053 -and $f.Compliance.NistSp80053.Count -gt 0) {
                $codes = ($f.Compliance.NistSp80053 | ForEach-Object { "<code>$(& $esc $_)</code>" }) -join ' '
                $compEntries += "<strong>NIST SP 800-53:</strong> $codes"
            }
            if ($f.Compliance.MitreAttack -and $f.Compliance.MitreAttack.Count -gt 0) {
                $codes = ($f.Compliance.MitreAttack | ForEach-Object { "<code>$(& $esc $_)</code>" }) -join ' '
                $compEntries += "<strong>MITRE ATT&amp;CK:</strong> $codes"
            }
            if ($f.Compliance.CisBenchmark -and $f.Compliance.CisBenchmark.Count -gt 0) {
                $codes = ($f.Compliance.CisBenchmark | ForEach-Object { "<code>$(& $esc $_)</code>" }) -join ' '
                $compEntries += "<strong>CIS Benchmark:</strong> $codes"
            }

            # Handle any additional compliance keys beyond the known three
            foreach ($compKey in $f.Compliance.Keys) {
                if ($compKey -in @('NistSp80053', 'MitreAttack', 'CisBenchmark')) { continue }
                $compVal = $f.Compliance[$compKey]
                if ($compVal -and $compVal.Count -gt 0) {
                    $codes = ($compVal | ForEach-Object { "<code>$(& $esc $_)</code>" }) -join ' '
                    $compEntries += "<strong>$(& $esc $compKey):</strong> $codes"
                }
            }

            if ($compEntries.Count -gt 0) {
                [void]$compHtml.Append($compEntries -join '<br>')
            }
        }

        # Affected entities (FAIL/WARN only) — bulleted list of impacted accounts/objects.
        $affectedBlock = ''
        if ($f.Status -in @('FAIL', 'WARN')) {
            $affectedHtml = Get-GuerrillaReportAffectedHtml -Details $f.Details
            if ($affectedHtml) {
                $affectedBlock = @"

        <div class="fd-block fd-full">
          <div class="fd-label">Affected Entities</div>
          <div class="fd-value">$affectedHtml</div>
        </div>
"@
            }
        }

        [void]$html.Append(@"
  <tr class="finding-detail-row" data-detail-idx="$findingIdx">
    <td colspan="7">
      <div class="finding-detail-content">
        <div class="fd-block fd-full">
          <div class="fd-label">Description</div>
          <div class="fd-value">$descHtml</div>
        </div>$affectedBlock
        <div class="fd-block">
          <div class="fd-label">Current Value</div>
          <div class="fd-value">$curValHtml</div>
        </div>
        <div class="fd-block">
          <div class="fd-label">Recommended Value</div>
          <div class="fd-value">$recValHtml</div>
        </div>
        <div class="fd-block fd-full">
          <div class="fd-label">Remediation Steps</div>
          <div class="fd-value">$remStepsHtml</div>
        </div>
        <div class="fd-block fd-full">
          <div class="fd-label">Remediation URL</div>
          <div class="fd-value">$remUrlHtml</div>
        </div>
        <div class="fd-block fd-full">
          <div class="fd-label">Compliance Mappings</div>
          <div class="fd-value">$($compHtml.ToString())</div>
        </div>
      </div>
    </td>
  </tr>
"@)
        $findingIdx++
    }

    [void]$html.Append('</tbody></table></div>')

    # ═══ COMPLIANCE CROSS-REFERENCE ═══
    $complianceFindings = @($failFindings | Where-Object {
        ($_.Compliance.NistSp80053 -and $_.Compliance.NistSp80053.Count -gt 0) -or
        ($_.Compliance.MitreAttack -and $_.Compliance.MitreAttack.Count -gt 0) -or
        ($_.Compliance.CisBenchmark -and $_.Compliance.CisBenchmark.Count -gt 0)
    } | Sort-Object {
        switch ($_.Severity) { 'Critical' { 0 } 'High' { 1 } 'Medium' { 2 } 'Low' { 3 } default { 4 } }
    }, CheckId)

    if ($complianceFindings.Count -gt 0) {
        [void]$html.Append(@'
<h2>Compliance Cross-Reference</h2>
<div class="table-wrap">
<table class="compliance-table">
  <thead>
  <tr>
    <th>Platform</th><th>Check ID</th><th>Check Name</th><th>Severity</th>
    <th>NIST SP 800-53</th><th>MITRE ATT&amp;CK</th><th>CIS Benchmark</th>
  </tr>
  </thead>
  <tbody>
'@)
        foreach ($f in $complianceFindings) {
            $sevClass = $f.Severity.ToLower()
            $platform  = if ($f.Platform) { $f.Platform } else { 'Unknown' }

            $nistCodes = if ($f.Compliance.NistSp80053 -and $f.Compliance.NistSp80053.Count -gt 0) {
                ($f.Compliance.NistSp80053 | ForEach-Object { "<code>$(& $esc $_)</code>" }) -join ' '
            } else { '' }

            $mitreCodes = if ($f.Compliance.MitreAttack -and $f.Compliance.MitreAttack.Count -gt 0) {
                ($f.Compliance.MitreAttack | ForEach-Object { "<code>$(& $esc $_)</code>" }) -join ' '
            } else { '' }

            $cisCodes = if ($f.Compliance.CisBenchmark -and $f.Compliance.CisBenchmark.Count -gt 0) {
                ($f.Compliance.CisBenchmark | ForEach-Object { "<code>$(& $esc $_)</code>" }) -join ' '
            } else { '' }

            [void]$html.Append(@"
  <tr>
    <td><span class="badge">$(& $esc $platform)</span></td>
    <td><code>$(& $esc $f.CheckId)</code></td>
    <td>$(& $esc $f.CheckName)</td>
    <td><span class="badge badge-sev-$sevClass">$($f.Severity)</span></td>
    <td>$nistCodes</td>
    <td>$mitreCodes</td>
    <td>$cisCodes</td>
  </tr>
"@)
        }
        [void]$html.Append('</tbody></table></div>')
    }

    # ═══ JAVASCRIPT ═══
    [void]$html.Append(@'
<script>
(function() {
  'use strict';

  var activeFilters = {
    platform: 'all',
    status: 'all',
    severity: 'all'
  };

  window.toggleFilter = function(btn) {
    var type = btn.getAttribute('data-filter-type');
    var value = btn.getAttribute('data-filter-value');

    // Deactivate all buttons in this filter group
    var siblings = btn.parentNode.querySelectorAll('.gg-btn');
    for (var i = 0; i < siblings.length; i++) {
      siblings[i].classList.remove('active');
    }
    btn.classList.add('active');
    activeFilters[type] = value;

    applyFilters();
  };

  window.toggleFindingDetail = function(idx) {
    var detailRows = document.querySelectorAll('.finding-detail-row[data-detail-idx="' + idx + '"]');
    for (var i = 0; i < detailRows.length; i++) {
      detailRows[i].classList.toggle('expanded');
    }
  };

  function applyFilters() {
    var rows = document.querySelectorAll('#findingsTable tbody .finding-row');
    var detailRows = document.querySelectorAll('#findingsTable tbody .finding-detail-row');
    var visibleCount = 0;
    var totalCount = rows.length;

    // Hide all detail rows first
    for (var d = 0; d < detailRows.length; d++) {
      detailRows[d].classList.remove('expanded');
    }

    for (var i = 0; i < rows.length; i++) {
      var row = rows[i];
      var platform = row.getAttribute('data-platform');
      var status = row.getAttribute('data-status');
      var severity = row.getAttribute('data-severity');
      var idx = row.getAttribute('data-idx');

      var showPlatform = (activeFilters.platform === 'all' || platform === activeFilters.platform);
      var showStatus = (activeFilters.status === 'all' || status === activeFilters.status);
      var showSeverity = (activeFilters.severity === 'all' || severity === activeFilters.severity);

      if (showPlatform && showStatus && showSeverity) {
        row.style.display = '';
        visibleCount++;
      } else {
        row.style.display = 'none';
        // Also hide associated detail row
        var detail = document.querySelector('.finding-detail-row[data-detail-idx="' + idx + '"]');
        if (detail) detail.style.display = 'none';
      }
    }

    var countEl = document.getElementById('filterCount');
    if (countEl) {
      if (visibleCount === totalCount) {
        countEl.textContent = 'Showing all ' + totalCount + ' findings';
      } else {
        countEl.textContent = 'Showing ' + visibleCount + ' of ' + totalCount + ' findings';
      }
    }
  }
})();
</script>
'@)

    # ═══ FOOTER + SHELL END ═══
    [void]$html.Append((Get-GuerrillaReportShellEnd `
        -FooterNote 'Unified Campaign Audit' `
        -TimestampText $timestampStr))

    Set-Content -Path $OutputPath -Value $html.ToString() -Encoding UTF8
}
