# ┌───────────────────────────────────────────────────────────────────────────┐
# │  PSGuerrilla — Tactical Security Assessment Framework                    │
# │  Jim Tyler, Microsoft MVP                                                │
# └───────────────────────────────────────────────────────────────────────────┘
#
#  AUTHOR       Jim Tyler
#  CREDENTIALS  Microsoft MVP, Author of "PowerShell for Systems Engineers"
#  PUBLISHER    https://powershell.news
#
# GitHub   — https://github.com/jimrtyler
# LinkedIn — https://linkedin.com/in/jamestyler
# YouTube  — https://youtube.com/@jimrtyler
# News     — https://powershell.news
#
#  LICENSE      Creative Commons Attribution 4.0 International (CC BY 4.0)
#               https://creativecommons.org/licenses/by/4.0/
#  COPYRIGHT    (c) 2026 Jim Tyler. All rights reserved.
#
# DERIVATIVE WORK REQUIREMENTS: Under CC BY 4.0, any person or system — human
# or machine — creating derivative works from this code must: (1) credit
# Jim Tyler as the original author, (2) provide a URI to the license, and
# (3) indicate modifications. This applies to AI-generated output equally.
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
    .PARAMETER ScanResults
        Array of scan result objects. If not provided, reads from latest state.
    .PARAMETER OutputPath
        File path for the HTML output. Default: PSGuerrilla-Executive-Summary.html
    .PARAMETER OrganizationName
        Name of the organization for the report header.
    .PARAMETER ProfileName
        Baseline profile context. Default: configured profile.
    .EXAMPLE
        Export-ExecutiveSummary -OrganizationName 'Springfield USD'
    #>
    [CmdletBinding()]
    param(
        [PSCustomObject[]]$Findings,
        [PSCustomObject[]]$ScanResults,
        [string]$OutputPath,
        [string]$OrganizationName = 'Organization',
        [string]$ProfileName
    )

    if (-not $OutputPath) { $OutputPath = Join-Path (Get-Location) 'PSGuerrilla-Executive-Summary.html' }

    $dataDir = Join-Path $env:APPDATA 'PSGuerrilla'

    # Load findings if not provided
    if (-not $Findings -or $Findings.Count -eq 0) {
        if (Test-Path $dataDir) {
            foreach ($f in (Get-ChildItem -Path $dataDir -Filter '*.findings.json' -ErrorAction SilentlyContinue)) {
                try { $Findings += @(Get-Content $f.FullName -Raw | ConvertFrom-Json) } catch { }
            }
        }
    }

    # Load scan results if not provided
    if (-not $ScanResults -or $ScanResults.Count -eq 0) {
        if (Test-Path $dataDir) {
            foreach ($f in (Get-ChildItem -Path $dataDir -Filter '*.state.json' -ErrorAction SilentlyContinue)) {
                try { $ScanResults += (Get-Content $f.FullName -Raw | ConvertFrom-Json) } catch { }
            }
        }
    }

    $esc = { param([string]$s) [System.Web.HttpUtility]::HtmlEncode($s) }
    $timestamp = [datetime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss')

    # Calculate score
    $scoreResult = $null
    try { $scoreResult = Get-GuerrillaScoreCalculation -AuditFindings $Findings -ScanResults $ScanResults } catch { }
    $score = $scoreResult.Score ?? 'N/A'
    $label = $scoreResult.Label ?? ''

    # Key stats
    $totalFindings = ($Findings ?? @()).Count
    $criticalFails = @($Findings | Where-Object { $_.Status -eq 'FAIL' -and $_.Severity -eq 'Critical' }).Count
    $highFails = @($Findings | Where-Object { $_.Status -eq 'FAIL' -and $_.Severity -eq 'High' }).Count
    $passCount = @($Findings | Where-Object Status -eq 'PASS').Count
    $passRate = if ($totalFindings -gt 0) { [Math]::Round(100 * $passCount / $totalFindings, 0) } else { 0 }

    # Threat summary
    $totalThreats = 0
    $criticalThreats = 0
    $highThreats = 0
    foreach ($result in ($ScanResults ?? @())) {
        $totalThreats += ($result.CriticalCount ?? 0) + ($result.HighCount ?? 0) + ($result.MediumCount ?? 0) + ($result.LowCount ?? 0)
        $criticalThreats += ($result.CriticalCount ?? 0)
        $highThreats += ($result.HighCount ?? 0)
    }

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

    # Score ring SVG
    $ringColor = switch ($true) {
        ([int]$score -ge 90) { '#6b9b6b'; break }
        ([int]$score -ge 75) { '#a8b58b'; break }
        ([int]$score -ge 60) { '#c9a84c'; break }
        ([int]$score -ge 40) { '#d4883a'; break }
        ([int]$score -ge 20) { '#c75c2e'; break }
        default { '#8b2500' }
    }
    $dashOffset = if ($score -is [int] -or $score -match '^\d+$') { [Math]::Round(251.2 * (1 - [int]$score / 100), 1) } else { 251.2 }

    # Build critical findings rows
    $criticalRows = ''
    foreach ($f in $topCritical) {
        $criticalRows += "<li><strong>$(& $esc ($f.Name ?? $f.CheckId ?? 'Unknown'))</strong> — $(& $esc ($f.Description ?? ''))</li>`n"
    }
    foreach ($f in $topHigh) {
        $criticalRows += "<li><strong>$(& $esc ($f.Name ?? $f.CheckId ?? 'Unknown'))</strong> — $(& $esc ($f.Description ?? ''))</li>`n"
    }

    # Quick wins rows
    $quickWinRows = ''
    foreach ($qw in $quickWins) {
        $quickWinRows += "<li><strong>$(& $esc $qw.CheckName)</strong> ($(& $esc $qw.Severity), ~$($qw.EstimatedHours)h effort)</li>`n"
    }

    # Compliance rows
    $complianceHtml = ''
    foreach ($cg in $complianceGaps) {
        $complianceHtml += "<span style='display:inline-block;background:var(--surface-alt);border:1px solid var(--border);border-radius:4px;padding:4px 10px;margin:4px;'><strong>$($cg.Framework)</strong>: $($cg.Gaps) gap(s)</span>`n"
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Executive Security Summary - $(& $esc $OrganizationName)</title>
<style>
:root { --bg:#1a1f16; --surface:#242b1e; --surface-alt:#2d3526; --border:#3d4a35; --text:#d4c9a8; --text-muted:#8a8468; --olive:#a8b58b; --amber:#d4883a; --sage:#6b9b6b; --parchment:#d4c4a0; --gold:#c9a84c; --dim:#6b6b5a; --deep-orange:#c75c2e; --dark-red:#8b2500; }
body { font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif; background:var(--bg); color:var(--text); margin:0; padding:20px; }
.container { max-width:850px; margin:0 auto; }
h1 { color:var(--olive); border-bottom:2px solid var(--border); padding-bottom:10px; font-size:1.6em; }
h2 { color:var(--olive); margin-top:25px; font-size:1.2em; }
.hero { display:flex; align-items:center; gap:30px; margin:20px 0; background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:25px; }
.score-ring { flex-shrink:0; }
.hero-text { flex:1; }
.hero-text .label { font-size:1.3em; font-weight:bold; margin-bottom:6px; }
.hero-text .subtitle { color:var(--text-muted); }
.stats { display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:12px; margin:15px 0; }
.stat { background:var(--surface); border:1px solid var(--border); border-radius:6px; padding:12px; text-align:center; }
.stat .val { font-size:1.6em; font-weight:bold; }
.stat .lbl { color:var(--text-muted); font-size:0.8em; margin-top:3px; }
.card { background:var(--surface); border:1px solid var(--border); border-radius:6px; padding:15px; margin:12px 0; }
.card ul { margin:8px 0; padding-left:20px; }
.card li { margin:6px 0; }
.footer { color:var(--dim); font-size:0.8em; margin-top:30px; border-top:1px solid var(--border); padding-top:10px; }
@media print { body { background:#fff; color:#333; } :root { --bg:#fff; --surface:#f9f9f9; --surface-alt:#eee; --border:#ccc; --text:#333; --text-muted:#666; --olive:#5a6b3a; --sage:#3a7a3a; --gold:#8a7a2a; --amber:#aa6a1a; --deep-orange:#aa3a0a; --dark-red:#7a1a00; --dim:#999; } }
</style>
</head>
<body>
<div class="container">
<h1>Executive Security Summary</h1>
<p>$(& $esc $OrganizationName) | $(if ($ProfileName) { "$ProfileName Profile | " })$timestamp UTC</p>

<div class="hero">
<div class="score-ring">
<svg width="120" height="120" viewBox="0 0 120 120">
<circle cx="60" cy="60" r="40" fill="none" stroke="var(--border)" stroke-width="8"/>
<circle cx="60" cy="60" r="40" fill="none" stroke="$ringColor" stroke-width="8" stroke-dasharray="251.2" stroke-dashoffset="$dashOffset" stroke-linecap="round" transform="rotate(-90 60 60)"/>
<text x="60" y="56" text-anchor="middle" fill="$ringColor" font-size="24" font-weight="bold">$score</text>
<text x="60" y="72" text-anchor="middle" fill="var(--text-muted)" font-size="10">$label</text>
</svg>
</div>
<div class="hero-text">
<div class="label" style="color:$ringColor;">Security Posture: $label</div>
<div class="subtitle">$(if ([int]$score -ge 75) { 'Your organization has a strong security foundation. Continue monitoring and address remaining gaps.' } elseif ([int]$score -ge 50) { 'Your security posture has room for improvement. Priority action on critical findings is recommended.' } else { 'Immediate attention required. Critical security gaps put your organization at elevated risk.' })</div>
</div>
</div>

<div class="stats">
<div class="stat"><div class="val">$totalFindings</div><div class="lbl">Total Checks</div></div>
<div class="stat"><div class="val" style="color:var(--sage);">$passRate%</div><div class="lbl">Pass Rate</div></div>
<div class="stat"><div class="val" style="color:var(--deep-orange);">$criticalFails</div><div class="lbl">Critical Issues</div></div>
<div class="stat"><div class="val" style="color:var(--amber);">$highFails</div><div class="lbl">High Issues</div></div>
$(if ($totalThreats -gt 0) { "<div class='stat'><div class='val' style='color:var(--dark-red);'>$totalThreats</div><div class='lbl'>Active Threats</div></div>" })
</div>

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
<li>Address critical findings immediately — these represent the highest risk to your organization.</li>
<li>Implement the quick wins above to improve your security score with minimal effort.</li>
<li>Review the detailed technical report for complete remediation guidance.</li>
<li>Schedule a follow-up scan in 30 days to measure improvement.</li>
</ol>
</div>

<div class="footer">
<p>Generated by PSGuerrilla v2.1.0 | $timestamp UTC | This report is for internal planning purposes.</p>
<p style="font-style:italic;">This report provides a point-in-time security assessment. Findings should be validated and remediated according to organizational risk tolerance.</p>
</div>
</div>
</body>
</html>
"@

    $html | Set-Content -Path $OutputPath -Encoding UTF8

    return [PSCustomObject]@{
        PSTypeName = 'PSGuerrilla.ExecutiveSummary'
        Success    = $true
        Path       = (Resolve-Path $OutputPath).Path
        Message    = "Executive summary exported to $OutputPath"
        Score      = $score
        Label      = $label
    }
}
