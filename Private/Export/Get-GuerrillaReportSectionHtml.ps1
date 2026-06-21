# PSGuerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/PSGuerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# Shared report sections so the per-scan AD report, the GWS report, and the unified Campaign report
# all surface the same things consistently. Each returns an HTML fragment (or '') and styles itself
# with theme CSS variables, so it drops into any of the three report themes unchanged.

# Maps a maturity level (1-5) to a theme colour var. Worst is red, best is sage.
function Get-GuerrillaMaturityLevelColor {
    param($Level)
    switch ([int]$Level) {
        1 { 'var(--dark-red)' }
        2 { 'var(--deep-orange)' }
        3 { 'var(--gold)' }
        4 { 'var(--olive)' }
        5 { 'var(--sage)' }
        default { 'var(--dim)' }
    }
}

# Security Maturity (CMMI 1-5) section. Returns '' if maturity can't be computed.
function Get-GuerrillaMaturitySectionHtml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][AllowNull()][PSCustomObject[]]$Findings,
        [Parameter(Mandatory)][scriptblock]$Esc
    )

    $maturity = $null
    try { $maturity = Get-GuerrillaMaturity -Findings $Findings } catch { }
    if (-not ($maturity -and $maturity.OverallLevel)) { return '' }

    $lvl   = [int]$maturity.OverallLevel
    $c     = Get-GuerrillaMaturityLevelColor $lvl
    $label = & $Esc ([string]$maturity.OverallLabel)

    $catRows = ''
    foreach ($k in ($maturity.CategoryLevels.Keys | Sort-Object { [int]$maturity.CategoryLevels[$_].Level })) {
        $cl = $maturity.CategoryLevels[$k]
        $cc = Get-GuerrillaMaturityLevelColor ([int]$cl.Level)
        $lvlCell = if ([int]$cl.Level -eq 0) { 'n/a' } else { "Level $([int]$cl.Level)" }
        $catRows += "<tr><td>$(& $Esc ([string]$cl.Category))</td><td style='color:$cc;font-weight:700'>$lvlCell</td><td>$(& $Esc ([string]$cl.Label))</td></tr>"
    }
    $blockerHtml = ''
    if ($maturity.NextLevel) {
        $bl = (@($maturity.NextLevelBlockers | Select-Object -First 8 | ForEach-Object { "<li>$(& $Esc ([string]$_))</li>" }) -join '')
        if ($bl) { $blockerHtml = "<p>To reach <strong>Level $([int]$maturity.NextLevel)</strong>, address:</p><ul style='margin:4px 0 8px 20px'>$bl</ul>" }
    }

    return @"
<style>
  .mat-sec { background: var(--surface-alt, var(--surface)); border: 1px solid var(--border); border-left: 4px solid $c;
             border-radius: 0 4px 4px 0; padding: 16px 20px; margin-bottom: 24px; }
  .mat-sec h3 { margin-top: 0; }
  .mat-tbl { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 0.85em; }
  .mat-tbl th, .mat-tbl td { text-align: left; padding: 6px 10px; border-bottom: 1px solid var(--border); }
  .mat-tbl th { opacity: 0.7; text-transform: uppercase; letter-spacing: 1px; font-size: 0.8em; }
</style>
<h2>Security Maturity</h2>
<div class="mat-sec">
  <h3 style="color:$c">Overall maturity: Level $lvl of 5 &mdash; $label</h3>
  <p>The lowest unmet control anchors the rating (CMMI-style scale: 1 Initial to 5 Optimized), so a single critical exposure caps the score until it is resolved.</p>
  $blockerHtml
  <table class="mat-tbl"><thead><tr><th>Category</th><th>Level</th><th>Maturity</th></tr></thead><tbody>$catRows</tbody></table>
</div>
"@
}

# Shared gather: collect the renderable attack chains from the ADPATH-001/002 findings.
# ADPATH-001 carries its rich objects under Details.Paths; ADPATH-002 under Details.Chains — read
# BOTH. Filter $null explicitly (an absent property wrapped with @() yields @($null) whose .Count is
# 1, which would otherwise defeat the AffectedItems fallback). Exclude Expected (by-design Tier-0
# service-account) paths — they're tracked by ADTIER-001, not escalation findings. Dedup by path.
function Get-GuerrillaAttackChainData {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][AllowNull()][PSCustomObject[]]$Findings)

    $pathFails = @($Findings | Where-Object { $_.CheckId -in @('ADPATH-001', 'ADPATH-002') -and $_.Status -eq 'FAIL' })
    $map = [ordered]@{}
    foreach ($pf in $pathFails) {
        $rich = @(@($pf.Details.Paths) + @($pf.Details.Chains) | Where-Object { $null -ne $_ })
        if ($rich.Count -gt 0) {
            foreach ($c in $rich) {
                if ($c.Expected) { continue }
                $p = "$($c.Path)"
                if (-not $p -or $map.Contains($p)) { continue }
                $len = if ($c.Length) { [int]$c.Length } else { ([regex]::Matches($p, '==>').Count + 1) }
                $map[$p] = [PSCustomObject]@{ Path = $p; NonPriv = (-not $c.SourceIsPrivileged); Length = $len }
            }
        } else {
            foreach ($p in @($pf.Details.AffectedItems | Where-Object { $null -ne $_ })) {
                $ps = "$p"
                if (-not $ps -or $map.Contains($ps)) { continue }
                $map[$ps] = [PSCustomObject]@{ Path = $ps; NonPriv = $true; Length = ([regex]::Matches($ps, '==>').Count + 1) }
            }
        }
    }
    return @($map.Values)
}

# Attack Paths to Tier-0 section, rendered from the ADPATH-001/002 findings' chain detail.
# -OmitIfAbsent returns '' when there are no attack-path findings at all (e.g. a GWS-only report or
# a multi-theater report with no AD theater); otherwise it emits a coverage note when none are found.
function Get-GuerrillaAttackPathSectionHtml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][AllowNull()][PSCustomObject[]]$Findings,
        [Parameter(Mandatory)][scriptblock]$Esc,
        [switch]$OmitIfAbsent
    )

    $pathFindings = @($Findings | Where-Object { $_.CheckId -in @('ADPATH-001', 'ADPATH-002') })
    if ($pathFindings.Count -eq 0 -and $OmitIfAbsent) { return '' }

    $chains = @((Get-GuerrillaAttackChainData -Findings $Findings) | Sort-Object `
        @{ Expression = { if ($_.NonPriv) { 0 } else { 1 } } }, `
        @{ Expression = { -1 * ([int]($_.Length ?? 0)) } })

    $css = @"
<style>
  .ap-note { color: var(--dim); font-size: 0.85em; margin: 4px 0 12px; }
  .ap-list { list-style: none; margin: 0 0 24px; padding: 0; }
  .ap-item { background: var(--surface); border: 1px solid var(--border); border-left: 4px solid var(--deep-orange);
             border-radius: 0 4px 4px 0; padding: 10px 14px; margin-bottom: 8px; }
  .ap-item.priv { border-left-color: var(--amber); }
  .ap-path { font-size: 0.9em; color: var(--parchment); word-break: break-word; }
  .ap-meta { font-size: 0.72em; color: var(--dim); margin-top: 4px; text-transform: uppercase; letter-spacing: 1px; }
  .ap-box { background: var(--surface-alt, var(--surface)); border: 1px solid var(--border); border-left: 4px solid var(--olive);
            border-radius: 0 4px 4px 0; padding: 16px 20px; margin-bottom: 24px; }
</style>
"@

    if ($chains.Count -eq 0) {
        $ran = @($pathFindings | Where-Object Status -in @('PASS', 'FAIL')).Count -gt 0
        $msg = if ($ran) {
            'No escalation paths to Tier-0 were found in the collected ACL scope. Deep low-privilege chains require full-domain ACL collection &mdash; re-run with <code>-FullDomainAcl</code> to widen coverage.'
        } else {
            'Attack-path analysis was not run. Enable the <code>ACLDelegation</code> + <code>PrivilegedAccounts</code> categories (or <code>All</code>), and add <code>-FullDomainAcl</code> for deep transitive chains.'
        }
        return "$css<h2>Attack Paths to Tier-0</h2><div class=`"ap-box`"><p>$msg</p></div>"
    }

    $npCount = @($chains | Where-Object NonPriv).Count
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append("$css<h2>Attack Paths to Tier-0</h2><p class=`"ap-note`">$($chains.Count) escalation path(s) reaching Tier-0 &mdash; $npCount from NON-privileged principals (shown first, highest risk). Each arrow is a control or membership edge an attacker can traverse.</p><ul class=`"ap-list`">")
    foreach ($c in $chains) {
        $cls = if ($c.NonPriv) { 'ap-item' } else { 'ap-item priv' }
        $meta = @()
        if ($c.Length) { $meta += "$([int]$c.Length) hop$(if ([int]$c.Length -ne 1) { 's' })" }
        $meta += if ($c.NonPriv) { 'non-privileged source' } else { 'already-privileged source' }
        [void]$sb.Append("<li class=`"$cls`"><div class=`"ap-path`">$(& $Esc $c.Path)</div><div class=`"ap-meta`">$(($meta) -join ' &middot; ')</div></li>")
    }
    [void]$sb.Append('</ul>')
    return $sb.ToString()
}

# Attack-Path Cartography: a native in-report SVG node-link map of the escalation routes to Tier-0,
# laid out left-to-right by longest-path rank. Built purely from the ADPATH chain Path strings already
# in findings (no extra data plumbing), so it renders self-contained in any report — no external tool.
# Returns '' when there are no attack-path chains. This is the PingCastle-cartography answer, inline.
function Get-GuerrillaCartographyHtml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][AllowNull()][PSCustomObject[]]$Findings,
        [Parameter(Mandatory)][scriptblock]$Esc,
        [int]$MaxChains = 25
    )

    # Same gather as the attack-path list: reads Details.Paths (ADPATH-001) + Details.Chains
    # (ADPATH-002), filters $null, excludes by-design Expected paths.
    $chainList = @(Get-GuerrillaAttackChainData -Findings $Findings)
    if ($chainList.Count -eq 0) { return '' }
    $truncated = $false
    if ($chainList.Count -gt $MaxChains) { $truncated = $true; $chainList = @($chainList | Select-Object -First $MaxChains) }

    # Parse each chain "A --[edge]--> B  ==>  B --[edge]--> C  =>  reaches ..." into nodes + edges.
    $nodes = [ordered]@{}
    $edges = [System.Collections.Generic.List[object]]::new()
    $edgeSeen = [System.Collections.Generic.HashSet[string]]::new()
    $tier0Re = '(?i)(domain admins|enterprise admins|schema admins|^administrators$|administrators \(tier)'
    $ensure = { param($n) if (-not $nodes.Contains($n)) { $nodes[$n] = @{ IsTier0 = $false; NonPrivSource = $false; IsSource = $false; IsTarget = $false } } }

    foreach ($ch in $chainList) {
        $core = ($ch.Path -replace '\s*=>\s*reaches.*$', '').Trim()
        $hops = @($core -split '\s*==>\s*')
        $firstFrom = $null; $lastTo = $null
        foreach ($h in $hops) {
            if ($h -match '^(.*?)\s+--\[(.*?)\]-->\s+(.*)$') {
                $from = $Matches[1].Trim(); $tech = $Matches[2].Trim(); $to = $Matches[3].Trim()
                if (-not $from -or -not $to) { continue }
                & $ensure $from; & $ensure $to
                if (-not $firstFrom) { $firstFrom = $from }
                $lastTo = $to
                $k = "$from|$to|$tech"
                if ($edgeSeen.Add($k)) { $edges.Add([PSCustomObject]@{ From = $from; To = $to; Tech = $tech }) }
            }
        }
        if ($firstFrom) { $nodes[$firstFrom].IsSource = $true; if ($ch.NonPriv) { $nodes[$firstFrom].NonPrivSource = $true } }
        if ($lastTo) { $nodes[$lastTo].IsTarget = $true }
    }
    if ($edges.Count -eq 0) { return '' }

    $toSet = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($e in $edges) { [void]$toSet.Add($e.To) }
    foreach ($n in @($nodes.Keys)) {
        if ($n -match $tier0Re -or $nodes[$n].IsTarget) { $nodes[$n].IsTier0 = $true }
        if (-not $toSet.Contains($n)) { $nodes[$n].IsSource = $true }
    }

    # Longest-path rank from sources (DAG; chains are acyclic and depth-bounded).
    $rank = @{}
    foreach ($n in $nodes.Keys) { $rank[$n] = 0 }
    for ($i = 0; $i -lt $nodes.Count; $i++) {
        $changed = $false
        foreach ($e in $edges) { if ($rank[$e.To] -lt $rank[$e.From] + 1) { $rank[$e.To] = $rank[$e.From] + 1; $changed = $true } }
        if (-not $changed) { break }
    }
    $maxRank = 0; foreach ($v in $rank.Values) { if ($v -gt $maxRank) { $maxRank = $v } }
    foreach ($n in @($nodes.Keys)) { if ($nodes[$n].IsTier0) { $rank[$n] = $maxRank } }  # targets on the right

    # Layout
    $nodeW = 168; $nodeH = 34; $colGap = 74; $rowGap = 22
    $colW = $nodeW + $colGap
    $byRank = @{}
    foreach ($n in $nodes.Keys) { $r = $rank[$n]; if (-not $byRank.ContainsKey($r)) { $byRank[$r] = [System.Collections.Generic.List[string]]::new() }; $byRank[$r].Add($n) }
    $pos = @{}; $maxRows = 1
    foreach ($r in ($byRank.Keys | Sort-Object)) {
        $list = $byRank[$r]
        if ($list.Count -gt $maxRows) { $maxRows = $list.Count }
        for ($j = 0; $j -lt $list.Count; $j++) { $pos[$list[$j]] = @{ X = (20 + $r * $colW); Y = (50 + $j * ($nodeH + $rowGap)) } }
    }
    $svgW = 40 + ($maxRank + 1) * $colW
    $svgH = 60 + $maxRows * ($nodeH + $rowGap) + 10
    $trunc = { param($s) if ("$s".Length -gt 22) { "$s".Substring(0, 21) + [char]0x2026 } else { "$s" } }
    $half = $nodeH / 2

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append('<h2>Attack-Path Cartography</h2>')
    [void]$sb.Append("<p class=`"ap-note`">Visual map of escalation routes to Tier-0. <span style='color:var(--deep-orange)'>&#9873; Red</span> = non-privileged start, <span style='color:var(--amber)'>amber</span> = already-privileged, <span style='color:var(--gold)'>&#9733; gold</span> = Tier-0 objective. Follow the arrows left to right.$(if ($truncated) { " Showing the first $MaxChains paths." })</p>")
    [void]$sb.Append("<div style='overflow-x:auto;border:1px solid var(--border);border-radius:4px;background:var(--surface);padding:8px;margin-bottom:24px'>")
    [void]$sb.Append("<svg viewBox='0 0 $svgW $svgH' width='$svgW' height='$svgH' style='max-width:100%;height:auto;font-family:var(--font-body,sans-serif)' xmlns='http://www.w3.org/2000/svg'>")
    [void]$sb.Append("<defs><marker id='ggarrow' markerWidth='9' markerHeight='9' refX='7' refY='3' orient='auto'><path d='M0,0 L7,3 L0,6 Z' fill='var(--dim)'/></marker></defs>")

    foreach ($e in $edges) {
        $a = $pos[$e.From]; $b = $pos[$e.To]
        if (-not $a -or -not $b) { continue }
        $x1 = $a.X + $nodeW; $y1 = $a.Y + $half; $x2 = $b.X; $y2 = $b.Y + $half; $mx = ($x1 + $x2) / 2
        [void]$sb.Append("<path d='M $x1 $y1 C $mx $y1 $mx $y2 $x2 $y2' fill='none' stroke='var(--dim)' stroke-width='1.5' marker-end='url(#ggarrow)' opacity='0.75'/>")
        [void]$sb.Append("<text x='$mx' y='$(($y1 + $y2) / 2 - 4)' text-anchor='middle' font-size='9' fill='var(--gold)'>$(& $Esc (& $trunc $e.Tech))</text>")
    }
    foreach ($n in $nodes.Keys) {
        $p = $pos[$n]; if (-not $p) { continue }
        $meta = $nodes[$n]
        $border = if ($meta.IsTier0) { 'var(--gold)' } elseif ($meta.NonPrivSource) { 'var(--deep-orange)' } elseif ($meta.IsSource) { 'var(--amber)' } else { 'var(--olive)' }
        $fill = if ($meta.IsTier0) { 'rgba(201,168,76,0.18)' } else { 'var(--surface-alt,var(--surface))' }
        $weight = if ($meta.IsTier0) { '700' } else { '400' }
        $icon = if ($meta.IsTier0) { [char]0x2605 + ' ' } elseif ($meta.NonPrivSource) { [char]0x2691 + ' ' } else { '' }
        [void]$sb.Append("<g><title>$(& $Esc $n)</title>")
        [void]$sb.Append("<rect x='$($p.X)' y='$($p.Y)' width='$nodeW' height='$nodeH' rx='4' fill='$fill' stroke='$border' stroke-width='2'/>")
        [void]$sb.Append("<text x='$($p.X + $nodeW / 2)' y='$($p.Y + $half + 4)' text-anchor='middle' font-size='11' font-weight='$weight' fill='var(--parchment)'>$(& $Esc ($icon + (& $trunc $n)))</text>")
        [void]$sb.Append('</g>')
    }
    [void]$sb.Append('</svg></div>')
    return $sb.ToString()
}
