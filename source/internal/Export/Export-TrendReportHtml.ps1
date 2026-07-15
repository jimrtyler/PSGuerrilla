# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Export-TrendReportHtml {
    <#
    .SYNOPSIS
        Generates an HTML trend report with embedded SVG sparklines.
    .PARAMETER History
        Array of score history entries (timestamp, score, label).
    .PARAMETER OutputPath
        File path for the HTML output.
    .PARAMETER OrganizationName
        Organization name for the report header.
    .PARAMETER Style
        Report style: Auto (follow the OS), Light, or Dark. Legacy names accepted.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$History,

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [string]$OrganizationName = 'Organization',

        [ValidateSet('Auto', 'Light', 'Dark', 'Guerrilla', 'Professional', 'Slate')]
        [string]$Style = 'Auto'
    )

    $esc = { param([string]$s) [System.Web.HttpUtility]::HtmlEncode($s) }
    # ConvertFrom-Json on PS 7.5+ rehydrates ISO 8601 strings into [DateTime],
    # which would interpolate as a culture-dependent string. Always normalize.
    $fmtTs = {
        param($t)
        if ($null -eq $t) { return '' }
        if ($t -is [datetime]) { return $t.ToString('yyyy-MM-ddTHH:mm:ssZ') }
        return "$t"
    }
    $html = [System.Text.StringBuilder]::new(32768)

    $timestampStr = [datetime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss') + ' UTC'

    # Calculate stats
    $scores = @($History | ForEach-Object { [int]$_.Score })
    $avgScore = if ($scores.Count -gt 0) { [Math]::Round(($scores | Measure-Object -Average).Average, 0) } else { 0 }
    $maxScore = if ($scores.Count -gt 0) { ($scores | Measure-Object -Maximum).Maximum } else { 0 }
    $minScore = if ($scores.Count -gt 0) { ($scores | Measure-Object -Minimum).Minimum } else { 0 }
    $latestScore = if ($scores.Count -gt 0) { $scores[-1] } else { 0 }
    $firstScore = if ($scores.Count -gt 0) { $scores[0] } else { 0 }
    $delta = $latestScore - $firstScore
    $trendDir = if ($delta -gt 2) { 'Improving' } elseif ($delta -lt -2) { 'Declining' } else { 'Stable' }
    $trendArrow = if ($delta -gt 2) { '&#x25B2;' } elseif ($delta -lt -2) { '&#x25BC;' } else { '&#x25CF;' }
    $trendColor = if ($delta -gt 2) { 'var(--g-ok)' } elseif ($delta -lt -2) { 'var(--g-bad)' } else { 'var(--g-muted)' }

    # Build SVG sparkline
    $svgWidth = 700
    $svgHeight = 200
    $padding = 40
    $chartW = $svgWidth - (2 * $padding)
    $chartH = $svgHeight - (2 * $padding)

    $svgPoints = ''
    $svgDots = ''
    if ($scores.Count -gt 1) {
        $xStep = $chartW / ([Math]::Max(1, $scores.Count - 1))
        for ($i = 0; $i -lt $scores.Count; $i++) {
            $x = $padding + ($i * $xStep)
            $y = $padding + $chartH - ($scores[$i] / 100.0 * $chartH)
            $svgPoints += "$x,$y "
            $svgDots += "<circle cx='$x' cy='$y' r='4' fill='var(--g-accent)' stroke='var(--g-surface)' stroke-width='2'><title>$(& $fmtTs $History[$i].Timestamp): $($scores[$i])</title></circle>`n"
        }
    } elseif ($scores.Count -eq 1) {
        $x = $padding + ($chartW / 2)
        $y = $padding + $chartH - ($scores[0] / 100.0 * $chartH)
        $svgPoints = "$x,$y"
        $svgDots = "<circle cx='$x' cy='$y' r='4' fill='var(--g-accent)' stroke='var(--g-surface)' stroke-width='2'/>"
    }

    # Grid lines for SVG
    $gridLines = ''
    foreach ($val in @(0, 20, 40, 60, 80, 100)) {
        $gy = $padding + $chartH - ($val / 100.0 * $chartH)
        $gridLines += "<line x1='$padding' y1='$gy' x2='$($svgWidth - $padding)' y2='$gy' stroke='var(--g-border)' stroke-dasharray='4,4'/>`n"
        $gridLines += "<text x='$($padding - 5)' y='$($gy + 4)' fill='var(--g-muted)' font-size='11' text-anchor='end'>$val</text>`n"
    }

    # Scan history table rows
    $tableRows = ''
    for ($i = $History.Count - 1; $i -ge 0; $i--) {
        $entry = $History[$i]
        $scoreColor = Get-GuerrillaScoreColorVar -Score ([int]$entry.Score)
        $entryDelta = if ($i -gt 0) { [int]$entry.Score - [int]$History[$i-1].Score } else { 0 }
        $deltaDisplay = if ($entryDelta -gt 0) { "+$entryDelta" } elseif ($entryDelta -lt 0) { "$entryDelta" } else { '&middot;' }
        $deltaClass = if ($entryDelta -gt 0) { 'cmp-up' } elseif ($entryDelta -lt 0) { 'cmp-down' } else { 'cmp-flat' }

        $tableRows += @"
    <tr>
      <td>$(& $esc (& $fmtTs $entry.Timestamp))</td>
      <td style="color:$scoreColor;font-weight:600;">$($entry.Score)</td>
      <td>$(& $esc ($entry.Label ?? ''))</td>
      <td class="$deltaClass">$deltaDisplay</td>
      <td>$(& $esc ($entry.ProfileUsed ?? 'Default'))</td>
    </tr>
"@
    }

    $subtitle = "$(& $esc $OrganizationName) &middot; $($History.Count) scan(s) &middot; Generated: $timestampStr"
    [void]$html.Append((Get-GuerrillaReportShellStart `
        -Title 'Security Trend Report' `
        -Subtitle $subtitle `
        -HtmlTitle "Security Trend Report - $OrganizationName" `
        -TopbarMeta 'Score Trend' `
        -Style $Style))

    $deltaLabel = if ($delta -ge 0) { "+$delta" } else { "$delta" }
    [void]$html.Append(@"
<div class="stat-grid">
  <div class="stat"><span class="value" style="color:$trendColor">$latestScore</span><span class="label">Current Score</span></div>
  <div class="stat"><span class="value">$avgScore</span><span class="label">Average Score</span></div>
  <div class="stat"><span class="value" style="color:$trendColor">$trendArrow $trendDir</span><span class="label">Trend ($deltaLabel)</span></div>
  <div class="stat"><span class="value">$maxScore / $minScore</span><span class="label">Highest / Lowest</span></div>
</div>

<h2>Score History</h2>
<div class="ap-map">
<svg viewBox="0 0 $svgWidth $svgHeight" xmlns="http://www.w3.org/2000/svg" style="width:100%;height:auto;min-width:600px;">
$gridLines
$(if ($svgPoints) { "<polyline points='$svgPoints' fill='none' stroke='var(--g-accent)' stroke-width='2.5' stroke-linejoin='round'/>" })
$svgDots
</svg>
</div>

<h2>Scan Log</h2>
<div class="table-wrap">
<table>
<thead><tr><th>Timestamp</th><th>Score</th><th>Label</th><th>Delta</th><th>Profile</th></tr></thead>
<tbody>
$tableRows
</tbody>
</table>
</div>
"@)

    [void]$html.Append((Get-GuerrillaReportShellEnd `
        -FooterNote 'Score Trend' `
        -TimestampText $timestampStr))

    $html.ToString() | Set-Content -Path $OutputPath -Encoding UTF8
    return $OutputPath
}
