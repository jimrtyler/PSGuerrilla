# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# Shared report sections so the per-scan AD report, the GWS report, and the unified Campaign report
# all surface the same things consistently. Each returns an HTML fragment (or '') styled by the
# shared component classes Get-GuerrillaReportThemeStyleBlock emits, so a section drops into any
# report unchanged. No section carries its own <style> block.

# Maps a maturity level (1-5) to a theme colour var. Worst is red, best is green.
function Get-GuerrillaMaturityLevelColor {
    param($Level)
    switch ([int]$Level) {
        1 { 'var(--g-sev-critical)' }
        2 { 'var(--g-sev-high)' }
        3 { 'var(--g-sev-medium)' }
        4 { 'var(--g-sev-low)' }
        5 { 'var(--g-ok)' }
        default { 'var(--g-sev-info)' }
    }
}

# Security Maturity (CMMI 1-5) section. Returns '' if maturity can't be computed.
function Get-GuerrillaMaturitySectionHtml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][AllowNull()][PSCustomObject[]]$Findings,
        [Parameter(Mandatory)][scriptblock]$Esc,
        [string]$Language = 'en'
    )

    $t  = Get-GuerrillaReportStringResolver -Language $Language
    $tr = Get-GuerrillaReportStringResolver -Language $Language -Raw

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
        $lvlCell = if ([int]$cl.Level -eq 0) { & $t 'maturity.na' } else { & $t 'maturity.levelCell' ([int]$cl.Level) }
        $catName = & $Esc (Get-GuerrillaLocalizedCategoryName -Name ([string]$cl.Category) -Language $Language)
        $catRows += "<tr><td>$catName</td><td style='color:$cc;font-weight:600'>$lvlCell</td><td>$(& $Esc ([string]$cl.Label))</td></tr>"
    }
    $blockerHtml = ''
    if ($maturity.NextLevel) {
        $bl = (@($maturity.NextLevelBlockers | Select-Object -First 8 | ForEach-Object { "<li>$(& $Esc ([string]$_))</li>" }) -join '')
        if ($bl) { $blockerHtml = "<p>$(& $tr 'maturity.toReach' ([int]$maturity.NextLevel))</p><ul>$bl</ul>" }
    }

    return @"
<h2>$(& $t 'maturity.heading')</h2>
<div class="mat-sec" style="border-left-color:$c">
  <h3 style="color:$c">$(& $tr 'maturity.overall' $lvl $label)</h3>
  <p>$(& $t 'maturity.anchorNote')</p>
  $blockerHtml
  <div class="table-wrap"><table><thead><tr><th>$(& $t 'maturity.thCategory')</th><th>$(& $t 'maturity.thLevel')</th><th>$(& $t 'maturity.thMaturity')</th></tr></thead><tbody>$catRows</tbody></table></div>
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
# a multi-platform report with no AD platform); otherwise it emits a coverage note when none are found.
function Get-GuerrillaAttackPathSectionHtml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][AllowNull()][PSCustomObject[]]$Findings,
        [Parameter(Mandatory)][scriptblock]$Esc,
        [switch]$OmitIfAbsent,
        [string]$Language = 'en'
    )

    $t  = Get-GuerrillaReportStringResolver -Language $Language
    $tr = Get-GuerrillaReportStringResolver -Language $Language -Raw

    $pathFindings = @($Findings | Where-Object { $_.CheckId -in @('ADPATH-001', 'ADPATH-002') })
    if ($pathFindings.Count -eq 0 -and $OmitIfAbsent) { return '' }

    $chains = @((Get-GuerrillaAttackChainData -Findings $Findings) | Sort-Object `
        @{ Expression = { if ($_.NonPriv) { 0 } else { 1 } } }, `
        @{ Expression = { -1 * ([int]($_.Length ?? 0)) } })

    if ($chains.Count -eq 0) {
        $ran = @($pathFindings | Where-Object Status -in @('PASS', 'FAIL')).Count -gt 0
        $msg = if ($ran) {
            & $tr 'attackpath.noneRan'
        } else {
            & $tr 'attackpath.noneNotRun'
        }
        return "<h2>$(& $t 'attackpath.heading')</h2><div class=`"notice notice-ok`"><p>$msg</p></div>"
    }

    $npCount = @($chains | Where-Object NonPriv).Count
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append("<h2>$(& $t 'attackpath.heading')</h2><p class=`"ap-note`">$(& $tr 'attackpath.summary' $chains.Count $npCount)</p><ul class=`"ap-list`">")
    foreach ($c in $chains) {
        $cls = if ($c.NonPriv) { 'ap-item' } else { 'ap-item priv' }
        $meta = @()
        if ($c.Length) { $meta += "$([int]$c.Length) $(if ([int]$c.Length -ne 1) { & $t 'attackpath.hops' } else { & $t 'attackpath.hop' })" }
        $meta += if ($c.NonPriv) { & $t 'attackpath.nonPrivSource' } else { & $t 'attackpath.privSource' }
        [void]$sb.Append("<li class=`"$cls`"><div class=`"ap-path`">$(& $Esc $c.Path)</div><div class=`"ap-meta`">$(($meta) -join ' &middot; ')</div></li>")
    }
    [void]$sb.Append('</ul>')
    return $sb.ToString()
}

# Attack-Path Cartography: a native in-report SVG node-link map of the escalation routes to Tier-0,
# laid out left-to-right by longest-path rank. Built purely from the ADPATH chain Path strings already
# in findings (no extra data plumbing), so it renders self-contained in any report — no external tool.
# Returns '' when there are no attack-path chains. A self-contained, in-report attack-path map.
function Get-GuerrillaCartographyHtml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][AllowNull()][PSCustomObject[]]$Findings,
        [Parameter(Mandatory)][scriptblock]$Esc,
        [int]$MaxChains = 25,
        [string]$Language = 'en'
    )

    $t  = Get-GuerrillaReportStringResolver -Language $Language
    $tr = Get-GuerrillaReportStringResolver -Language $Language -Raw

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
    [void]$sb.Append("<h2>$(& $t 'cartography.heading')</h2>")
    [void]$sb.Append("<p class=`"ap-note`">$(& $tr 'cartography.legend')$(if ($truncated) { & $tr 'cartography.showingFirst' $MaxChains })</p>")
    [void]$sb.Append("<div class='ap-map'>")
    [void]$sb.Append("<svg viewBox='0 0 $svgW $svgH' width='$svgW' height='$svgH' style='max-width:100%;height:auto;font-family:var(--font-sans)' xmlns='http://www.w3.org/2000/svg'>")
    [void]$sb.Append("<defs><marker id='ggarrow' markerWidth='9' markerHeight='9' refX='7' refY='3' orient='auto'><path d='M0,0 L7,3 L0,6 Z' fill='var(--g-muted)'/></marker></defs>")

    foreach ($e in $edges) {
        $a = $pos[$e.From]; $b = $pos[$e.To]
        if (-not $a -or -not $b) { continue }
        $x1 = $a.X + $nodeW; $y1 = $a.Y + $half; $x2 = $b.X; $y2 = $b.Y + $half; $mx = ($x1 + $x2) / 2
        [void]$sb.Append("<path d='M $x1 $y1 C $mx $y1 $mx $y2 $x2 $y2' fill='none' stroke='var(--g-muted)' stroke-width='1.5' marker-end='url(#ggarrow)' opacity='0.75'/>")
        [void]$sb.Append("<text x='$mx' y='$(($y1 + $y2) / 2 - 4)' text-anchor='middle' font-size='9' fill='var(--g-muted)'>$(& $Esc (& $trunc $e.Tech))</text>")
    }
    foreach ($n in $nodes.Keys) {
        $p = $pos[$n]; if (-not $p) { continue }
        $meta = $nodes[$n]
        $border = if ($meta.IsTier0) { 'var(--g-accent)' } elseif ($meta.NonPrivSource) { 'var(--g-sev-critical)' } elseif ($meta.IsSource) { 'var(--g-sev-high)' } else { 'var(--g-border-strong)' }
        $fill = if ($meta.IsTier0) { 'var(--g-surface-alt)' } else { 'var(--g-surface)' }
        $weight = if ($meta.IsTier0) { '700' } else { '400' }
        $icon = if ($meta.IsTier0) { [char]0x2605 + ' ' } elseif ($meta.NonPrivSource) { [char]0x2691 + ' ' } else { '' }
        [void]$sb.Append("<g><title>$(& $Esc $n)</title>")
        [void]$sb.Append("<rect x='$($p.X)' y='$($p.Y)' width='$nodeW' height='$nodeH' rx='8' fill='$fill' stroke='$border' stroke-width='2'/>")
        [void]$sb.Append("<text x='$($p.X + $nodeW / 2)' y='$($p.Y + $half + 4)' text-anchor='middle' font-size='11' font-weight='$weight' fill='var(--g-heading)'>$(& $Esc ($icon + (& $trunc $n)))</text>")
        [void]$sb.Append('</g>')
    }
    [void]$sb.Append('</svg></div>')
    return $sb.ToString()
}

# Indicators of Exposure — a ranked view of the estate's actual exposures, derived
# from the FAIL/WARN findings: each is a named, severity-scored indicator with its blast radius
# (affected count). Returns '' when there are no open exposures. Platform-agnostic.
function Get-GuerrillaIndicatorsOfExposureHtml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][AllowNull()][PSCustomObject[]]$Findings,
        [Parameter(Mandatory)][scriptblock]$Esc,
        [int]$Top = 12,
        [string]$Language = 'en'
    )

    $t  = Get-GuerrillaReportStringResolver -Language $Language
    $tr = Get-GuerrillaReportStringResolver -Language $Language -Raw

    $open = @($Findings | Where-Object { $_.Status -in @('FAIL', 'WARN') })
    if ($open.Count -eq 0) { return '' }

    $sevRank = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4 }
    $affectedOf = {
        param($f)
        $d = $f.Details
        if ($d.AffectedItems) { return @($d.AffectedItems).Count }
        if ($null -ne $d.ChainCount) { return [int]$d.ChainCount }
        if ($null -ne $d.PathCount) { return [int]$d.PathCount }
        return 1
    }

    $ind = foreach ($f in $open) {
        [PSCustomObject]@{
            Name     = "$($f.CheckName)"
            CheckId  = "$($f.CheckId)"
            Category = "$($f.Category)"
            Severity = "$($f.Severity)"
            Status   = "$($f.Status)"
            Affected = (& $affectedOf $f)
            Evidence = "$($f.CurrentValue)"
        }
    }
    $ranked = @($ind | Sort-Object `
        @{ Expression = { $sevRank["$($_.Severity)"] ?? 5 } }, `
        @{ Expression = { if ($_.Status -eq 'FAIL') { 0 } else { 1 } } }, `
        @{ Expression = { -1 * [int]$_.Affected } }, `
        Name)

    $crit = @($open | Where-Object Severity -eq 'Critical').Count
    $high = @($open | Where-Object Severity -eq 'High').Count
    $med  = @($open | Where-Object Severity -eq 'Medium').Count
    $low  = @($open | Where-Object Severity -eq 'Low').Count

    $shown = @($ranked | Select-Object -First $Top)
    $more = $ranked.Count - $shown.Count
    $trunc = { param($s) if ("$s".Length -gt 140) { "$s".Substring(0, 138) + [char]0x2026 } else { "$s" } }

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append(@"
<h2>$(& $t 'ioe.heading')</h2>
<p class="ioe-note">$(& $t 'ioe.note' $open.Count)</p>
<div class="ioe-sum">
  <span class="badge badge-sev-critical">$(& $t 'ioe.critical'): $crit</span>
  <span class="badge badge-sev-high">$(& $t 'ioe.high'): $high</span>
  <span class="badge badge-sev-medium">$(& $t 'ioe.medium'): $med</span>
  <span class="badge badge-sev-low">$(& $t 'ioe.low'): $low</span>
</div>
<ul class="ioe-list">
"@)
    foreach ($i in $shown) {
        $sevClass = 'sev-' + ("$($i.Severity)").ToLower()
        $sevColor = Get-GuerrillaSeverityColorVar -Severity $i.Severity
        $aff = if ($i.Affected -gt 1) { " &middot; $(& $tr 'ioe.affected' $i.Affected)" } else { '' }
        $warn = if ($i.Status -eq 'WARN') { " &middot; $(& $t 'ioe.warning')" } else { '' }
        $catLabel = & $Esc (Get-GuerrillaLocalizedCategoryName -Name "$($i.Category)" -Language $Language)
        [void]$sb.Append("<li class=`"ioe-item $sevClass`"><div class=`"ioe-sev`" style=`"color:$sevColor`">$(& $Esc $i.Severity)</div><div><div class=`"ioe-name`">$(& $Esc $i.Name)</div><div class=`"ioe-meta`">$catLabel &middot; $(& $Esc $i.CheckId)$aff$warn</div><div class=`"ioe-ev`">$(& $Esc (& $trunc $i.Evidence))</div></div></li>")
    }
    [void]$sb.Append('</ul>')
    if ($more -gt 0) { [void]$sb.Append("<p class=`"ioe-note`">$(& $t 'ioe.more' $more)</p>") }
    return $sb.ToString()
}

# Renders a finding's affected accounts/objects (from its Details hashtable) as one or more
# labeled BULLETED lists. Prefers the explicit AffectedItems/AffectedLabel convention; otherwise
# auto-detects any Details entry that is a non-empty array of scalars (strings/valuetypes) — e.g.
# ActiveSuperAdmins, StaleAdmins — and labels it by splitting the camelCase key. Caps each list at
# 25 items, appending a "+N more" bullet beyond that. HTML-encodes every item. Returns '' when there
# is nothing to render. Shared so the AD / Entra / GWS / Campaign reports all surface affected entities
# the same way.
#
# An entry may also be an array of GROUPS — elements carrying both a Label and an Items collection
# (hashtable or object) — which render as a bullet per group with its own indented sub-list. That is
# how a finding surfaces two-level evidence, e.g. GWS-K12-004's one-bullet-per-delegation-grant with
# the scopes each grant holds nested beneath it. Both levels are capped independently at 25.
# Arrays of any OTHER object shape are still skipped deliberately: findings whose rich detail already
# has a dedicated section (ADPATH's Details.Paths/Chains -> the Attack Paths section) must not be
# duplicated here, so opting in means adopting the Label/Items shape.
function Get-GuerrillaReportAffectedHtml {
    param([hashtable]$Details, [string]$Language = 'en')
    if (-not $Details -or $Details.Count -eq 0) { return '' }

    # Reads a named member from either a hashtable or an object; $null when absent.
    $member = {
        param($o, [string]$n)
        if ($null -eq $o) { return $null }
        if ($o -is [System.Collections.IDictionary]) {
            if ($o.Contains($n)) { return $o[$n] }
            return $null
        }
        $prop = $o.PSObject.Properties[$n]
        if ($prop) { return $prop.Value }
        return $null
    }

    $t = Get-GuerrillaReportStringResolver -Language $Language -Raw
    $pairs = [System.Collections.Generic.List[object]]::new()
    if ($Details.ContainsKey('AffectedItems')) {
        $lbl = if ($Details.AffectedLabel) { [string]$Details.AffectedLabel } else { & $t 'sections.affectedItems' }
        $pairs.Add(@{ Label = $lbl; Items = @($Details.AffectedItems); Grouped = $false })
    } else {
        foreach ($k in $Details.Keys) {
            if ($k -in @('AffectedItems', 'AffectedLabel')) { continue }
            $v = $Details[$k]
            if ($v -is [string] -or $v -is [valuetype]) { continue }
            if ($v -is [System.Collections.IEnumerable]) {
                $arr = @($v | Where-Object { $null -ne $_ })
                if ($arr.Count -eq 0) { continue }
                $scalar = $true
                $grouped = $true
                foreach ($el in $arr) {
                    if ($el -is [string] -or $el -is [valuetype]) { $grouped = $false; continue }
                    $scalar = $false
                    if ($null -eq (& $member $el 'Label') -or $null -eq (& $member $el 'Items')) { $grouped = $false }
                }
                if (-not $scalar -and -not $grouped) { continue }
                $label = ($k -creplace '([a-z0-9])([A-Z])', '$1 $2')
                $pairs.Add(@{ Label = $label; Items = $arr; Grouped = (-not $scalar) })
            }
        }
    }

    $enc = { param($s) [System.Web.HttpUtility]::HtmlEncode([string]$s) }
    $out = [System.Text.StringBuilder]::new()
    foreach ($p in $pairs) {
        $items = @($p.Items)
        if ($items.Count -eq 0) { continue }
        $cap = 25
        $shown = @($items | Select-Object -First $cap)
        $lbl = & $enc $p.Label
        [void]$out.Append("<div class=`"affected`"><span class=`"affected-label`">$lbl ($($items.Count)):</span><ul class=`"affected-items`">")
        foreach ($it in $shown) {
            if (-not $p.Grouped) {
                [void]$out.Append("<li>$(& $enc $it)</li>")
                continue
            }
            [void]$out.Append("<li class=`"affected-group`">$(& $enc (& $member $it 'Label'))")
            $sub = @((& $member $it 'Items') | Where-Object { $null -ne $_ })
            if ($sub.Count -gt 0) {
                [void]$out.Append('<ul class="affected-sub">')
                foreach ($s in @($sub | Select-Object -First $cap)) {
                    [void]$out.Append("<li>$(& $enc $s)</li>")
                }
                if ($sub.Count -gt $cap) {
                    [void]$out.Append("<li class=`"more`">+$($sub.Count - $cap) more</li>")
                }
                [void]$out.Append('</ul>')
            }
            [void]$out.Append('</li>')
        }
        if ($items.Count -gt $cap) {
            [void]$out.Append("<li class=`"more`">+$($items.Count - $cap) more</li>")
        }
        [void]$out.Append('</ul></div>')
    }
    return $out.ToString()
}

# Interactive findings filter — a live filter bar (status + severity buttons + text search)
# plus the client-side script that shows/hides any <tr class="gg-row" data-status data-sev data-text>.
# Styled entirely by the shared component classes; the host report tags its finding rows with
# those attributes.
function Get-GuerrillaFindingsFilterHtml {
    [CmdletBinding()]
    param([string[]]$Statuses = @('FAIL', 'WARN', 'PASS', 'SKIP'),
          [string[]]$Severities = @('Critical', 'High', 'Medium', 'Low'),
          [string]$Language = 'en')

    $t = Get-GuerrillaReportStringResolver -Language $Language

    $statusBtns = "<button class=`"gg-btn active`" data-f=`"status`" data-v=`"all`">$(& $t 'filter.all')</button>" +
        (($Statuses | ForEach-Object { "<button class=`"gg-btn`" data-f=`"status`" data-v=`"$_`">$_</button>" }) -join '')
    $sevBtns = "<button class=`"gg-btn active`" data-f=`"sev`" data-v=`"all`">$(& $t 'filter.all')</button>" +
        (($Severities | ForEach-Object { "<button class=`"gg-btn`" data-f=`"sev`" data-v=`"$_`">$_</button>" }) -join '')

    @"
<div class="gg-filter" id="ggFilter">
  <span class="gg-lbl">$(& $t 'filter.status')</span>$statusBtns
  <span class="gg-lbl" style="margin-left:0.5rem">$(& $t 'filter.severity')</span>$sevBtns
  <input type="text" id="ggSearch" class="gg-search" placeholder="$(& $t 'filter.searchPlaceholder')">
</div>
<div class="gg-empty" id="ggEmpty">$(& $t 'filter.empty')</div>
<script>
document.addEventListener('DOMContentLoaded', function () {
  var bar = document.getElementById('ggFilter'); if (!bar) return;
  var state = { status: 'all', sev: 'all', q: '' };
  function apply() {
    var q = state.q.toLowerCase(), shown = 0;
    document.querySelectorAll('tr.gg-row').forEach(function (r) {
      var okS = state.status === 'all' || (r.getAttribute('data-status') || '').toUpperCase() === state.status.toUpperCase();
      var okV = state.sev === 'all' || (r.getAttribute('data-sev') || '').toUpperCase() === state.sev.toUpperCase();
      var okQ = q === '' || (r.getAttribute('data-text') || '').indexOf(q) >= 0;
      var vis = okS && okV && okQ; r.style.display = vis ? '' : 'none'; if (vis) shown++;
    });
    var active = state.status !== 'all' || state.sev !== 'all' || q !== '';
    if (active) { document.querySelectorAll('details.cat-detail').forEach(function (d) { d.open = true; }); }
    var e = document.getElementById('ggEmpty'); if (e) { e.style.display = (shown === 0) ? 'block' : 'none'; }
  }
  bar.querySelectorAll('button[data-f]').forEach(function (b) {
    b.addEventListener('click', function () {
      var t = b.getAttribute('data-f'); state[t] = b.getAttribute('data-v');
      bar.querySelectorAll('button[data-f="' + t + '"]').forEach(function (x) { x.classList.remove('active'); });
      b.classList.add('active'); apply();
    });
  });
  var s = document.getElementById('ggSearch'); if (s) { s.addEventListener('input', function () { state.q = s.value; apply(); }); }
});
</script>
"@
}

function Get-GuerrillaComparisonSectionHtml {
    <#
    .SYNOPSIS
        Shared "What changed since last run" section for every summary report.
    .DESCRIPTION
        Renders a Guerrilla.RunDiff (Compare-GuerrillaRun output) as the
        report's lead section: the three first-class transitions in order
        (newly failing, lost visibility, newly passing), then regressions in
        place, restorations, and NEW/RETIRED labels; the previous run's date
        and module version; the overall score delta, per-pillar deltas, and
        the Not Assessed count delta at the same prominence as the score
        delta. A first recorded run gets an honest line instead of fabricated
        change. $null (comparison not run) renders nothing.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]$RunDiff,
        [Parameter(Mandatory)][scriptblock]$Esc,
        [string]$Language = 'en'
    )

    if ($null -eq $RunDiff) { return '' }

    $t  = Get-GuerrillaReportStringResolver -Language $Language
    $tr = Get-GuerrillaReportStringResolver -Language $Language -Raw

    $html = [System.Text.StringBuilder]::new(8192)
    [void]$html.Append("<div class=`"cmp-section`"><h2>$(& $t 'comparison.heading')</h2>")

    if ($RunDiff.BaselineRun) {
        [void]$html.Append("<p>$(& $tr 'comparison.firstRun')</p>`n</div>`n")
        return $html.ToString()
    }

    $prevDate = "$($RunDiff.Previous.GeneratedAt)"
    if ($prevDate.Length -ge 19) { $prevDate = $prevDate.Substring(0, 19).Replace('T', ' ') + ' UTC' }
    [void]$html.Append("<p class='cmp-meta'>$(& $tr 'comparison.previousRun' (& $Esc $prevDate) (& $Esc "$($RunDiff.Previous.ModuleVersion)"))")
    if ($RunDiff.VersionSkew) {
        [void]$html.Append((& $tr 'comparison.versionSkew' (& $Esc "$($RunDiff.Current.ModuleVersion)")))
    }
    [void]$html.Append('</p>')

    # Score delta and Not Assessed delta at equal prominence.
    $fmtDelta = {
        param($delta, $goodWhenNegative)
        if ($null -eq $delta) { return "<span class='cmp-flat'>n/a</span>" }
        $d = [int]$delta
        if ($d -eq 0) { return "<span class='cmp-flat'>&#9654; 0</span>" }
        $isGood = if ($goodWhenNegative) { $d -lt 0 } else { $d -gt 0 }
        $cls = if ($isGood) { 'cmp-up' } else { 'cmp-down' }
        $arrow = if ($d -gt 0) { '&#9650;' } else { '&#9660;' }
        $sign = if ($d -gt 0) { '+' } else { '' }
        return "<span class='$cls'>$arrow $sign$d</span>"
    }
    # Checks that are dark this run (went dark, or stayed dark) are excluded from
    # the score's denominator by the scoring engine — so a score can RISE simply
    # because checks stopped being assessed. Never style that as a clean
    # improvement: mark the delta as caution and say what it excludes.
    $darkNow = @($RunDiff.LostVisibility).Count + @($RunDiff.StillNotAssessed).Count
    $scoreDeltaHtml = & $fmtDelta $RunDiff.ScoreDelta $false
    if ($darkNow -gt 0 -and $null -ne $RunDiff.ScoreDelta -and [int]$RunDiff.ScoreDelta -gt 0) {
        $scoreDeltaHtml = $scoreDeltaHtml -replace "class='cmp-up'", "class='cmp-caution'"
    }
    [void]$html.Append('<div class="cmp-deltas">')
    [void]$html.Append("<div class='cmp-delta'><div class='val'>$scoreDeltaHtml</div><div class='lbl'>$(& $tr 'comparison.scoreLabel' $RunDiff.Current.OverallScore $RunDiff.Previous.OverallScore)</div></div>")
    [void]$html.Append("<div class='cmp-delta'><div class='val'>$(& $fmtDelta $RunDiff.NotAssessedDelta $true)</div><div class='lbl'>$(& $t 'comparison.notAssessedLabel')</div></div>")
    [void]$html.Append('</div>')
    if ($darkNow -gt 0) {
        [void]$html.Append("<div class='cmp-caveat'>Score excludes $darkNow check$(if ($darkNow -ne 1) { 's' }) not assessed this run " +
            "($(@($RunDiff.LostVisibility).Count) lost visibility, $(@($RunDiff.StillNotAssessed).Count) still not assessed); " +
            'a rising score with dark checks is not a clean improvement.</div>')
    }

    $pillarRows = @($RunDiff.PillarDeltas | Where-Object { $null -ne $_.Delta -and $_.Delta -ne 0 })
    if ($pillarRows.Count -gt 0) {
        [void]$html.Append("<div class=`"cmp-pillars`"><strong>$(& $t 'comparison.pillarsMoved')</strong> ")
        $parts = foreach ($p in $pillarRows) {
            "$(& $Esc $p.Pillar) $(& $fmtDelta $p.Delta $false)"
        }
        [void]$html.Append(($parts -join ' &nbsp;&middot;&nbsp; '))
        [void]$html.Append('</div>')
    }

    $renderClass = {
        param($title, $entries, $color, $showFromTo)
        if (@($entries).Count -eq 0) { return '' }
        $sb = [System.Text.StringBuilder]::new()
        [void]$sb.Append("<div class='cmp-class'><p style='color:$color;font-weight:600;margin:0'>$title`: $(@($entries).Count)</p><ul>")
        foreach ($e in (@($entries) | Select-Object -First 15)) {
            $ou = if ($e.OrgUnitPath) { " <span style='color:var(--g-muted)'>[$(& $Esc $e.OrgUnitPath)]</span>" } else { '' }
            $sev = if ($e.Severity) { "<span class='badge badge-sev-$("$($e.Severity)".ToLower())'>$(& $Esc $e.Severity)</span> " } else { '' }
            $fromTo = if ($showFromTo -and $e.From -and $e.To) { " <span style='color:var(--g-muted)'>($(& $Esc $e.From) &rarr; $(& $Esc $e.To))</span>" }
                      elseif ($showFromTo -and $e.To) { " <span style='color:var(--g-muted)'>(now $(& $Esc $e.To))</span>" }
                      elseif ($showFromTo -and $e.From) { " <span style='color:var(--g-muted)'>(was $(& $Esc $e.From))</span>" }
                      else { '' }
            [void]$sb.Append("<li>$sev$(& $Esc $e.CheckId)$ou$fromTo</li>")
        }
        if (@($entries).Count -gt 15) { [void]$sb.Append("<li style='color:var(--g-muted)'>and $(@($entries).Count - 15) more</li>") }
        [void]$sb.Append('</ul></div>')
        return $sb.ToString()
    }

    # The three first-class transitions, newly-failing first; a check that went
    # dark is lost visibility with its own prominence, never "no change".
    [void]$html.Append((& $renderClass (& $t 'comparison.newlyFailing') $RunDiff.NewlyFailing 'var(--g-bad)' $true))
    [void]$html.Append((& $renderClass (& $t 'comparison.lostVisibility') $RunDiff.LostVisibility 'var(--g-warn)' $true))
    [void]$html.Append((& $renderClass (& $t 'comparison.stillNotAssessed') $RunDiff.StillNotAssessed 'var(--g-warn)' $false))
    [void]$html.Append((& $renderClass (& $t 'comparison.newlyPassing') $RunDiff.NewlyPassing 'var(--g-ok)' $true))
    [void]$html.Append((& $renderClass (& $t 'comparison.regressed') $RunDiff.Regressed 'var(--g-sev-medium)' $true))
    [void]$html.Append((& $renderClass (& $t 'comparison.improved') $RunDiff.Improved 'var(--g-sev-medium)' $true))
    [void]$html.Append((& $renderClass (& $t 'comparison.restoredVisibility') $RunDiff.RestoredVisibility 'var(--g-heading)' $true))
    [void]$html.Append((& $renderClass (& $t 'comparison.newChecks') $RunDiff.NewChecks 'var(--g-heading)' $true))
    [void]$html.Append((& $renderClass (& $t 'comparison.retiredChecks') $RunDiff.RetiredChecks 'var(--g-muted)' $true))

    $changed = @($RunDiff.NewlyFailing).Count + @($RunDiff.LostVisibility).Count + @($RunDiff.NewlyPassing).Count +
        @($RunDiff.Regressed).Count + @($RunDiff.Improved).Count + @($RunDiff.RestoredVisibility).Count
    $stillDark = @($RunDiff.StillNotAssessed).Count
    $stillDarkNote = if ($stillDark -gt 0) {
        " $stillDark check$(if ($stillDark -ne 1) { 's' }) remain$(if ($stillDark -eq 1) { 's' }) not assessed — dark is not stable."
    } else { '' }
    if ($changed -eq 0) {
        [void]$html.Append("<p>No verdict changed since the previous run. $($RunDiff.UnchangedCount) checks are unchanged.$stillDarkNote</p>")
    } else {
        [void]$html.Append("<p class='cmp-meta'>$($RunDiff.UnchangedCount) checks unchanged.$stillDarkNote</p>")
    }

    [void]$html.Append('</div>')
    return $html.ToString()
}
