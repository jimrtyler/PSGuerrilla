# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution

# Report theming engine, rebuilt on the website design tokens so guerrilla.army,
# the desktop GUI, and every generated report read as one product.
#
# The hex values are a manual mirror of the website's src/styles/tokens.json
# (the single source of truth; every light/dark pair there is contrast-verified
# to WCAG 2.1 AA in the site's CI) plus the GUI's Get-GuerrillaGuiTheme. Keep
# all three in sync when the site tokens change.
#
# Model: every report embeds BOTH palettes as --g-* custom properties. Light is
# the default, dark applies under prefers-color-scheme and a data-theme
# attribute wins over both (same cascade as the website's Base.astro). A theme
# toggle in the report header flips the attribute. -Style chooses the initial
# state: Auto (follow the OS), Light, or Dark. The legacy style names remain
# accepted: Professional -> Light, Slate -> Dark, Guerrilla -> Dark.
#
# The Guerrilla / Jim Tyler footer attribution is never themed away; it is
# emitted by the shared shell regardless of style or branding.

function Get-GuerrillaReportTheme {
    <#
    .SYNOPSIS
        Returns the report palettes (Light + Dark) mirrored from the website tokens.
    .DESCRIPTION
        Keys are the kebab-case custom-property names WITHOUT the --g- prefix,
        in the exact order tokens.json declares them.
    #>
    [CmdletBinding()]
    param()

    $light = [ordered]@{
        'bg'            = '#ffffff'
        'surface'       = '#f5f5f7'
        'surface-alt'   = '#e8e8ed'
        'text'          = '#1d1d1f'
        'heading'       = '#1d1d1f'
        'muted'         = '#515154'
        'link'          = '#0066cc'
        'link-hover'    = '#0050a0'
        'accent'        = '#0066cc'
        'on-accent'     = '#ffffff'
        'border'        = '#d2d2d7'
        'border-strong' = '#76767c'
        'focus'         = '#0066cc'
        'code-bg'       = '#f5f5f7'
        'code-text'     = '#1d1d1f'
        'sev-critical'  = '#b32424'
        'sev-high'      = '#9a4a05'
        'sev-medium'    = '#6b5900'
        'sev-low'       = '#207a4e'
        'sev-info'      = '#515154'
        'ok'            = '#207a4e'
        'warn'          = '#9a4a05'
        'bad'           = '#b32424'
    }

    $dark = [ordered]@{
        'bg'            = '#000000'
        'surface'       = '#1c1c1e'
        'surface-alt'   = '#2c2c2e'
        'text'          = '#f5f5f7'
        'heading'       = '#ffffff'
        'muted'         = '#a1a1a6'
        'link'          = '#2997ff'
        'link-hover'    = '#5eb0ff'
        'accent'        = '#0066cc'
        'on-accent'     = '#ffffff'
        'border'        = '#3a3a3c'
        'border-strong' = '#8e8e93'
        'focus'         = '#2997ff'
        'code-bg'       = '#1c1c1e'
        'code-text'     = '#f5f5f7'
        'sev-critical'  = '#f09090'
        'sev-high'      = '#e8a25c'
        'sev-medium'    = '#d9c25a'
        'sev-low'       = '#93c793'
        'sev-info'      = '#a1a1a6'
        'ok'            = '#93c793'
        'warn'          = '#e8a25c'
        'bad'           = '#f09090'
    }

    return @{ Light = $light; Dark = $dark }
}

function Resolve-GuerrillaReportStyle {
    # Normalizes any accepted -Style value (including the legacy theme names)
    # to the three-state model the shell understands.
    [CmdletBinding()]
    param([string]$Style = 'Auto')

    switch ($Style) {
        'Light'        { 'Light' }
        'Dark'         { 'Dark' }
        'Professional' { 'Light' }   # legacy light corporate theme
        'Slate'        { 'Dark' }    # legacy dark dashboard theme
        'Guerrilla'    { 'Dark' }    # legacy dark olive theme
        default        { 'Auto' }
    }
}

function Get-GuerrillaScoreColorVar {
    # Score band -> severity-scale custom property. Shared by every exporter so
    # a 62 is the same color in the AD report, the Campaign report, and the GUI docs.
    [CmdletBinding()]
    param([Parameter(Mandatory)][int]$Score)

    if ($Score -ge 90) { return 'var(--g-ok)' }
    if ($Score -ge 75) { return 'var(--g-sev-low)' }
    if ($Score -ge 60) { return 'var(--g-sev-medium)' }
    if ($Score -ge 40) { return 'var(--g-sev-high)' }
    return 'var(--g-sev-critical)'
}

function Get-GuerrillaSeverityColorVar {
    [CmdletBinding()]
    param([string]$Severity)

    switch ("$Severity") {
        'Critical' { 'var(--g-sev-critical)' }
        'High'     { 'var(--g-sev-high)' }
        'Medium'   { 'var(--g-sev-medium)' }
        'Low'      { 'var(--g-sev-low)' }
        default    { 'var(--g-sev-info)' }
    }
}

function Get-GuerrillaReportThemeStyleBlock {
    <#
    .SYNOPSIS
        Emits the <style>-inner CSS every report shares: both token palettes and
        the full component system (typography, cards, tables, badges, sections).
    .DESCRIPTION
        Exporters append only their genuinely report-specific rules via the
        shell's -ExtraCss. The palette cascade matches the website exactly:
        :root is light, prefers-color-scheme: dark applies dark when no
        data-theme attribute is present, and an explicit data-theme wins.
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('Auto', 'Light', 'Dark', 'Guerrilla', 'Professional', 'Slate')]
        [string]$Style = 'Auto'
    )

    $theme = Get-GuerrillaReportTheme
    $vars = { param($palette) (($palette.Keys | ForEach-Object { "--g-$($_): $($palette[$_]);" }) -join ' ') }
    $lightVars = & $vars $theme.Light
    $darkVars  = & $vars $theme.Dark

    $sb = [System.Text.StringBuilder]::new(24576)
    [void]$sb.AppendLine(":root { $lightVars }")
    [void]$sb.AppendLine("@media (prefers-color-scheme: dark) { :root:not([data-theme]) { $darkVars } }")
    [void]$sb.AppendLine(":root[data-theme=`"dark`"] { $darkVars }")
    [void]$sb.AppendLine(":root[data-theme=`"light`"] { $lightVars }")

    [void]$sb.AppendLine(@'
:root {
  --font-sans: -apple-system, BlinkMacSystemFont, "SF Pro Text", "SF Pro Display", system-ui, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  --font-mono: "SF Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
  --radius: 12px;
  --radius-sm: 8px;
  color-scheme: light dark;
}
:root[data-theme="light"] { color-scheme: light; }
:root[data-theme="dark"] { color-scheme: dark; }

*, *::before, *::after { box-sizing: border-box; }
html { font-size: 100%; }
body {
  margin: 0;
  background: var(--g-bg);
  color: var(--g-text);
  font-family: var(--font-sans);
  font-size: 1.0625rem;
  line-height: 1.6;
  letter-spacing: -0.003em;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  text-rendering: optimizeLegibility;
  -webkit-text-size-adjust: 100%;
}

h1, h2, h3, h4 {
  color: var(--g-heading);
  font-weight: 600;
  line-height: 1.1;
  letter-spacing: -0.02em;
  margin: 1.8em 0 0.5em;
}
h1 { font-size: 2.3rem; font-weight: 700; letter-spacing: -0.03em; margin: 0.6em 0 0.15em; line-height: 1.07; }
h2 { font-size: 1.65rem; }
h3 { font-size: 1.2rem; }
h4 { font-size: 1.05rem; letter-spacing: -0.01em; }
p, ul, ol, dl { margin: 0.9em 0; }
ul, ol { padding-left: 1.4rem; }
li { margin: 0.35em 0; }

a { color: var(--g-link); text-decoration: underline; text-underline-offset: 3px; text-decoration-thickness: 1px; }
a:hover { color: var(--g-link-hover); }
.theme-toggle, details summary, .gg-btn { text-decoration: none; }
:focus-visible { outline: 3px solid var(--g-focus); outline-offset: 2px; border-radius: 3px; }

code, pre, kbd { font-family: var(--font-mono); font-size: 0.86em; }
pre, code:not(pre code) { background: var(--g-code-bg); color: var(--g-code-text); }
code:not(pre code) { padding: 0.15em 0.4em; border-radius: 5px; }
pre { padding: 1em 1.15em; border: 1px solid var(--g-border); border-radius: var(--radius-sm); line-height: 1.5; white-space: pre-wrap; overflow-wrap: anywhere; }

.container { max-width: 75rem; margin: 0 auto; padding: 0 1.5rem; }
main.container { padding-top: 0.5rem; padding-bottom: 4rem; }

/* Report chrome: quiet sticky bar with the wordmark and the theme toggle. */
.report-topbar { border-bottom: 1px solid var(--g-border); background: var(--g-bg); position: sticky; top: 0; z-index: 5; }
.report-topbar .container { display: flex; align-items: center; gap: 1.6rem; padding-top: 0.8rem; padding-bottom: 0.8rem; }
.report-topbar .brand { font-weight: 600; font-size: 1.25rem; letter-spacing: -0.02em; color: var(--g-heading); }
.report-topbar .topbar-meta { color: var(--g-muted); font-size: 0.9rem; }
.report-topbar .controls { margin-left: auto; display: flex; align-items: center; gap: 1rem; }
.theme-toggle {
  font-family: var(--font-sans); font-size: 0.9rem;
  background: var(--g-surface); color: var(--g-text);
  border: 1px solid var(--g-border); border-radius: 980px;
  padding: 0.3em 0.9em; cursor: pointer;
}
.theme-toggle:hover { color: var(--g-link); border-color: var(--g-border-strong); }
.no-js .theme-toggle { display: none; }
.report-subtitle { color: var(--g-muted); font-size: 1rem; margin: 0 0 1.6rem; }

/* White-label banner + firm header. */
.wl-banner { background: var(--g-sev-critical); color: #ffffff; text-align: center; padding: 0.4em 1em; font-weight: 600; letter-spacing: 0.12em; text-transform: uppercase; font-size: 0.8rem; }
.wl-header { display: flex; align-items: center; gap: 1rem; margin: 1.4rem 0 0.4rem; padding-bottom: 1rem; border-bottom: 1px solid var(--g-border); }
.wl-header img { max-height: 56px; max-width: 220px; object-fit: contain; }
.wl-firm { font-size: 1.15rem; font-weight: 600; color: var(--g-heading); letter-spacing: -0.01em; }
.wl-meta { font-size: 0.9rem; color: var(--g-muted); margin-top: 2px; }

/* Cards, stats, notices: soft gray fill, big radius, Apple-style. */
.card { background: var(--g-surface); border: 1px solid transparent; border-radius: var(--radius); padding: 1.25rem 1.4rem; }
.card h2, .card h3 { margin-top: 0; }
.stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(9.5rem, 1fr)); gap: 1rem; margin: 1.75rem 0; }
.stat { background: var(--g-surface); border-radius: var(--radius); padding: 1.35rem 0.9rem; text-align: center; }
.stat .value { display: block; font-size: 2.1rem; font-weight: 600; letter-spacing: -0.02em; color: var(--g-heading); line-height: 1.05; }
.stat .label { display: block; font-size: 0.85rem; color: var(--g-muted); margin-top: 0.5rem; }
.notice { background: var(--g-surface); border-radius: var(--radius); border-left: 3px solid var(--g-link); padding: 1rem 1.25rem; margin: 1.4rem 0; font-size: 0.97rem; }
.notice > :first-child { margin-top: 0; }
.notice > :last-child { margin-bottom: 0; }
.notice.notice-ok { border-left-color: var(--g-ok); }
.notice.notice-warn { border-left-color: var(--g-warn); }
.notice.notice-bad { border-left-color: var(--g-bad); }

/* Score panel */
.score-panel { display: flex; align-items: center; gap: 2rem; background: var(--g-surface); border-radius: var(--radius); padding: 1.5rem 2rem; margin: 1.6rem 0; flex-wrap: wrap; }
.score-ring { width: 120px; height: 120px; position: relative; flex-shrink: 0; }
.score-ring svg { transform: rotate(-90deg); display: block; }
.score-ring .value { position: absolute; inset: 0; display: flex; align-items: center; justify-content: center; font-size: 2rem; font-weight: 700; letter-spacing: -0.02em; color: var(--g-heading); }
.score-detail .label { font-size: 1.35rem; font-weight: 600; letter-spacing: -0.02em; }
.score-detail .desc { color: var(--g-muted); font-size: 0.95rem; margin-top: 0.2rem; }

/* Category cards */
.category-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(20rem, 1fr)); gap: 1rem; margin: 1.4rem 0; }
.cat-card { background: var(--g-surface); border-radius: var(--radius); padding: 1.1rem 1.3rem; }
.cat-card .cat-header { display: flex; justify-content: space-between; align-items: baseline; gap: 0.8rem; margin-bottom: 0.5rem; }
.cat-card .cat-name { font-weight: 600; color: var(--g-heading); }
.cat-card .cat-score { font-size: 1.4rem; font-weight: 600; letter-spacing: -0.02em; }
.cat-card .cat-bar-bg { height: 6px; background: var(--g-surface-alt); border-radius: 3px; overflow: hidden; margin-bottom: 0.5rem; }
.cat-card .cat-bar-fill { height: 100%; border-radius: 3px; }
.cat-card .cat-counts { font-size: 0.85rem; color: var(--g-muted); display: flex; flex-wrap: wrap; gap: 0.9em; }

/* Badges: quiet outline pills (website classes). */
.badge { display: inline-block; font-size: 0.82rem; font-weight: 500; color: var(--g-muted); border: 1px solid var(--g-border); border-radius: 980px; padding: 0.12em 0.7em; white-space: nowrap; }
.badge-sev-critical { color: var(--g-sev-critical); border-color: var(--g-sev-critical); }
.badge-sev-high { color: var(--g-sev-high); border-color: var(--g-sev-high); }
.badge-sev-medium { color: var(--g-sev-medium); border-color: var(--g-sev-medium); }
.badge-sev-low { color: var(--g-sev-low); border-color: var(--g-sev-low); }
.badge-sev-info { color: var(--g-sev-info); border-color: var(--g-sev-info); }
.badge-status-pass { color: var(--g-ok); border-color: var(--g-ok); }
.badge-status-fail { color: var(--g-bad); border-color: var(--g-bad); font-weight: 600; }
.badge-status-warn { color: var(--g-warn); border-color: var(--g-warn); }
.badge-status-skip, .badge-status-error { color: var(--g-muted); border-color: var(--g-border); }
.badge-status-accepted { color: var(--g-muted); border-color: var(--g-border); font-style: italic; }
.verdict-pass { color: var(--g-ok); font-weight: 600; }
.verdict-fail { color: var(--g-bad); font-weight: 600; }
.verdict-warn { color: var(--g-warn); font-weight: 600; }
.verdict-na { color: var(--g-muted); font-weight: 600; }

/* Tables: light rules, sticky header, scroll inside their own container. */
.table-wrap { overflow-x: auto; margin: 1.4em 0; border-radius: var(--radius-sm); }
table { border-collapse: collapse; width: 100%; font-size: 0.92rem; }
th, td { text-align: left; vertical-align: top; padding: 0.6em 0.85em; border-bottom: 1px solid var(--g-border); }
thead th { font-weight: 600; color: var(--g-heading); border-bottom: 1px solid var(--g-border-strong); background: var(--g-bg); position: sticky; top: 0; }
tbody tr:hover { background: var(--g-surface); }
td small { color: var(--g-muted); }

/* Collapsible category sections */
details.cat-detail { background: var(--g-surface); border-radius: var(--radius); margin: 0.8rem 0; }
details.cat-detail summary { padding: 0.9rem 1.3rem; cursor: pointer; list-style: none; display: flex; align-items: center; gap: 0.8rem; font-weight: 600; color: var(--g-heading); }
details.cat-detail summary::-webkit-details-marker { display: none; }
details.cat-detail summary::before { content: '\25b6'; font-size: 0.65em; color: var(--g-muted); transition: transform 0.2s; }
details.cat-detail[open] summary::before { transform: rotate(90deg); }
details.cat-detail summary:hover { color: var(--g-link); }
details.cat-detail summary .sum-counts { margin-left: auto; font-weight: 400; font-size: 0.88rem; color: var(--g-muted); }
details.cat-detail .detail-body { padding: 0 1.3rem 1.1rem; overflow-x: auto; }
details.cat-detail .detail-body table { font-size: 0.9rem; }

/* Affected entities beneath a FAIL/WARN row */
tr.finding-extra td { border-left: 3px solid var(--g-warn); background: var(--g-surface); padding: 0.5em 0.85em 0.9em 1.1em; }
tr.finding-extra:hover td { background: var(--g-surface); }
.affected { margin-top: 0.2em; font-size: 0.88rem; }
.affected-label { color: var(--g-warn); font-weight: 600; }
.affected-items { margin: 0.3em 0 0; padding-left: 1.4rem; }
.affected-items li { word-break: break-word; margin: 0.1em 0; }
.affected-items li.more { list-style: none; margin-left: -1.4rem; font-style: italic; color: var(--g-muted); }

/* Interactive findings filter */
.gg-filter { display: flex; flex-wrap: wrap; align-items: center; gap: 0.5rem; margin: 1rem 0; padding: 0.7rem 0.9rem; background: var(--g-surface); border-radius: var(--radius); }
.gg-filter .gg-lbl { font-size: 0.8rem; font-weight: 600; color: var(--g-muted); margin-right: 0.1rem; }
.gg-btn { background: transparent; border: 1px solid var(--g-border); border-radius: 980px; padding: 0.2em 0.85em; color: var(--g-text); cursor: pointer; font-family: var(--font-sans); font-size: 0.85rem; }
.gg-btn:hover { color: var(--g-link); border-color: var(--g-border-strong); }
.gg-btn.active { background: var(--g-accent); border-color: var(--g-accent); color: var(--g-on-accent); }
.gg-search { flex: 1 1 200px; min-width: 150px; background: var(--g-bg); border: 1px solid var(--g-border); border-radius: 980px; padding: 0.3em 0.9em; color: var(--g-text); font-family: var(--font-sans); font-size: 0.9rem; }
.gg-empty { color: var(--g-muted); font-size: 0.9rem; font-style: italic; margin: 0.5rem 0; display: none; }

/* Shared analysis sections (maturity, attack paths, exposure, comparison) */
.mat-sec { background: var(--g-surface); border-radius: var(--radius); border-left: 3px solid var(--g-border-strong); padding: 1.1rem 1.4rem; margin: 1.4rem 0; }
.mat-sec h3 { margin-top: 0; }
.ap-note { color: var(--g-muted); font-size: 0.92rem; margin: 0.3rem 0 0.9rem; }
.ap-list { list-style: none; margin: 0 0 1.6rem; padding: 0; }
.ap-item { background: var(--g-surface); border-radius: var(--radius-sm); border-left: 3px solid var(--g-sev-critical); padding: 0.7rem 1rem; margin-bottom: 0.5rem; }
.ap-item.priv { border-left-color: var(--g-sev-high); }
.ap-path { font-family: var(--font-mono); font-size: 0.85rem; color: var(--g-heading); word-break: break-word; }
.ap-meta { font-size: 0.8rem; color: var(--g-muted); margin-top: 0.25rem; }
.ap-map { overflow-x: auto; background: var(--g-surface); border-radius: var(--radius); padding: 0.75rem; margin: 0 0 1.6rem; }
.ioe-sum { display: flex; flex-wrap: wrap; gap: 0.5rem; margin: 0.3rem 0 0.9rem; }
.ioe-list { list-style: none; margin: 0 0 1.6rem; padding: 0; }
.ioe-item { display: flex; gap: 1rem; align-items: flex-start; background: var(--g-surface); border-radius: var(--radius-sm); border-left: 3px solid var(--g-sev-info); padding: 0.7rem 1rem; margin-bottom: 0.5rem; }
.ioe-item.sev-critical { border-left-color: var(--g-sev-critical); }
.ioe-item.sev-high { border-left-color: var(--g-sev-high); }
.ioe-item.sev-medium { border-left-color: var(--g-sev-medium); }
.ioe-item.sev-low { border-left-color: var(--g-sev-low); }
.ioe-sev { flex: 0 0 4.5rem; font-size: 0.8rem; font-weight: 600; padding-top: 0.15rem; }
.ioe-name { font-weight: 600; color: var(--g-heading); font-size: 0.97rem; }
.ioe-meta { font-size: 0.82rem; color: var(--g-muted); margin: 0.1rem 0; }
.ioe-ev { font-size: 0.88rem; word-break: break-word; }
.ioe-note { color: var(--g-muted); font-size: 0.9rem; }
.cmp-section { background: var(--g-surface); border-radius: var(--radius); border-left: 3px solid var(--g-link); padding: 1.1rem 1.4rem; margin: 1.4rem 0; }
.cmp-section h2 { margin-top: 0; font-size: 1.35rem; }
.cmp-meta { color: var(--g-muted); font-size: 0.92rem; margin: 0.2rem 0 0.7rem; }
.cmp-deltas { display: flex; flex-wrap: wrap; gap: 1.4rem; margin: 0.7rem 0 1rem; }
.cmp-delta { min-width: 8rem; }
.cmp-delta .val { font-size: 1.5rem; font-weight: 600; letter-spacing: -0.02em; }
.cmp-delta .lbl { font-size: 0.85rem; color: var(--g-muted); }
.cmp-up { color: var(--g-ok); } .cmp-down { color: var(--g-bad); } .cmp-flat { color: var(--g-muted); }
.cmp-caution { color: var(--g-warn); }
.cmp-caveat { font-size: 0.88rem; color: var(--g-warn); margin: -0.3rem 0 0.8rem; }
.cmp-class { margin: 0.7rem 0; }
.cmp-class ul { margin: 0.3rem 0 0.6rem 1.4rem; font-size: 0.92rem; padding: 0; }
.cmp-pillars { font-size: 0.92rem; margin-top: 0.5rem; }

/* Footer: mirrors the site footer. */
.report-footer { margin-top: 4rem; border-top: 1px solid var(--g-border); background: var(--g-surface); color: var(--g-muted); font-size: 0.9rem; }
.report-footer .container { padding-top: 1.75rem; padding-bottom: 2.5rem; }
.report-footer p { margin: 0.35em 0; }
.report-footer a { color: var(--g-link); }

@media print {
  .report-topbar, .gg-filter, .theme-toggle { display: none !important; }
  body { font-size: 10.5pt; }
  .card, .stat, .cat-card, .ap-item, .ioe-item, .notice, details.cat-detail { break-inside: avoid; border: 1px solid var(--g-border); }
  details.cat-detail { display: block; }
  details.cat-detail:not([open]) > *:not(summary) { display: block; }
  thead th { position: static; }
  .report-footer { background: transparent; }
}
'@)

    # @media print cannot force a palette via attribute, so restate the light
    # tokens for print regardless of theme state (PDF export prints light).
    [void]$sb.AppendLine("@media print { :root, :root[data-theme=`"dark`"] { $lightVars } }")

    return $sb.ToString()
}

function Get-GuerrillaReportShellStart {
    <#
    .SYNOPSIS
        Emits everything from <!DOCTYPE html> through the report's title block:
        head + shared stylesheet, topbar with wordmark and theme toggle, the
        white-label banner/header, and the h1 + subtitle.
    .PARAMETER Title
        The h1 text (HTML-encoded here).
    .PARAMETER Subtitle
        Raw HTML fragment rendered under the title (callers escape their data).
    .PARAMETER HtmlTitle
        The <title> text; defaults to Title.
    .PARAMETER TopbarMeta
        Short plain text shown next to the wordmark (e.g. "Security Assessment").
    .PARAMETER ExtraCss
        Exporter-specific CSS appended after the shared block.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Title,
        [string]$Subtitle = '',
        [string]$HtmlTitle,
        [string]$TopbarMeta = 'Security Assessment',
        [ValidateSet('Auto', 'Light', 'Dark', 'Guerrilla', 'Professional', 'Slate')]
        [string]$Style = 'Auto',
        [hashtable]$Branding,
        [string]$ExtraCss = ''
    )

    $esc = { param([string]$s) [System.Web.HttpUtility]::HtmlEncode($s) }

    $resolved = Resolve-GuerrillaReportStyle -Style $Style
    $themeAttr = if ($resolved -eq 'Auto') { '' } else { " data-theme=`"$($resolved.ToLower())`"" }
    if (-not $HtmlTitle) { $HtmlTitle = $Title }

    $css = (Get-GuerrillaReportThemeStyleBlock -Style $Style) + $ExtraCss
    $brand = Get-GuerrillaReportBrandingHtml -Branding $Branding

    $subtitleHtml = if ($Subtitle) { "<p class=`"report-subtitle`">$Subtitle</p>" } else { '' }

    return @"
<!DOCTYPE html>
<html lang="en"$themeAttr>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>$(& $esc $HtmlTitle)</title>
<style>
$css
</style>
</head>
<body>
$($brand.Banner)
<header class="report-topbar">
  <div class="container">
    <span class="brand">Guerrilla</span>
    <span class="topbar-meta">$(& $esc $TopbarMeta)</span>
    <div class="controls">
      <button type="button" class="theme-toggle" id="ggThemeToggle" aria-pressed="false">Dark</button>
    </div>
  </div>
</header>
<main class="container">
$($brand.Header)
<h1>$(& $esc $Title)</h1>
$subtitleHtml
"@
}

function Get-GuerrillaReportShellEnd {
    <#
    .SYNOPSIS
        Closes the report: footer with the (never themed away) Guerrilla / Jim
        Tyler attribution, and the theme-toggle script.
    .PARAMETER FooterNote
        First footer line after "Generated by Guerrilla vX", e.g. the platform label.
    #>
    [CmdletBinding()]
    param(
        [string]$FooterNote = '',
        [string]$TimestampText = '',
        [string]$ModuleVersion
    )

    $esc = { param([string]$s) [System.Web.HttpUtility]::HtmlEncode($s) }

    if (-not $ModuleVersion) {
        $ModuleVersion = '2.0.0'
        try {
            $modVer = $ExecutionContext.SessionState.Module.Version
            if ($modVer) { $ModuleVersion = $modVer.ToString() }
        } catch { }
    }

    $noteHtml = if ($FooterNote) { " &middot; $(& $esc $FooterNote)" } else { '' }
    $tsHtml = if ($TimestampText) { "<p>Report generated: $(& $esc $TimestampText)</p>" } else { '' }

    return @"
</main>
<footer class="report-footer">
  <div class="container">
    <p>Generated by Guerrilla v$(& $esc $ModuleVersion)$noteHtml</p>
    $tsHtml
    <p>By Jim Tyler, Microsoft MVP &middot; <a href="https://github.com/jimrtyler">GitHub</a> &middot; <a href="https://linkedin.com/in/jamestyler">LinkedIn</a> &middot; <a href="https://youtube.com/@jimrtyler">YouTube</a></p>
  </div>
</footer>
<script>
(function () {
  var btn = document.getElementById('ggThemeToggle');
  if (!btn) { return; }
  var KEY = 'guerrilla-report-theme';
  var root = document.documentElement;
  var forced = root.hasAttribute('data-theme');
  if (!forced) {
    try {
      var saved = localStorage.getItem(KEY);
      if (saved === 'light' || saved === 'dark') { root.setAttribute('data-theme', saved); }
    } catch (e) { }
  }
  function current() {
    var attr = root.getAttribute('data-theme');
    if (attr === 'light' || attr === 'dark') { return attr; }
    return (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) ? 'dark' : 'light';
  }
  function paint() {
    var mode = current();
    btn.textContent = mode === 'dark' ? 'Light' : 'Dark';
    btn.setAttribute('aria-pressed', mode === 'dark' ? 'true' : 'false');
  }
  btn.addEventListener('click', function () {
    var next = current() === 'dark' ? 'light' : 'dark';
    root.setAttribute('data-theme', next);
    try { localStorage.setItem(KEY, next); } catch (e) { }
    paint();
  });
  paint();
})();
</script>
</body>
</html>
"@
}

# Extract a normalized branding hashtable from a loaded config (the `branding`
# section of config.json). Returns $null when no branding is configured.
function Get-GuerrillaBranding {
    [CmdletBinding()]
    param($Config)

    if (-not $Config) { return $null }
    $b = $Config.branding
    if (-not $b) { return $null }

    $out = @{}
    foreach ($k in 'FirmName', 'LogoPath', 'ConsultantName', 'ConsultantEmail', 'ClientName', 'Confidentiality') {
        $v = $null
        if ($b -is [System.Collections.IDictionary]) { $v = $b[$k] }
        elseif ($b.PSObject.Properties[$k]) { $v = $b.$k }
        if ($v) { $out[$k] = [string]$v }
    }
    if ($out.Count -eq 0) { return $null }
    return $out
}

# Build the white-label banner + header HTML from a branding hashtable. Returns a
# hashtable with Banner and Header strings (either may be empty). Keys honoured:
# FirmName, LogoPath, ConsultantName, ConsultantEmail, ClientName, Confidentiality.
function Get-GuerrillaReportBrandingHtml {
    [CmdletBinding()]
    param([hashtable]$Branding)

    $esc = { param([string]$s) [System.Web.HttpUtility]::HtmlEncode($s) }
    $result = @{ Banner = ''; Header = '' }
    if (-not $Branding -or $Branding.Count -eq 0) { return $result }

    $firm    = [string]($Branding.FirmName ?? '')
    $logo    = [string]($Branding.LogoPath ?? '')
    $name    = [string]($Branding.ConsultantName ?? '')
    $email   = [string]($Branding.ConsultantEmail ?? '')
    $client  = [string]($Branding.ClientName ?? '')
    $conf    = [string]($Branding.Confidentiality ?? '')

    if ($conf) {
        $result.Banner = "<div class=`"wl-banner`">$(& $esc $conf)</div>"
    }

    $parts = [System.Collections.Generic.List[string]]::new()
    if ($logo) { $parts.Add("<img src=`"$(& $esc $logo)`" alt=`"`">") }

    $textParts = [System.Collections.Generic.List[string]]::new()
    if ($firm) { $textParts.Add("<div class=`"wl-firm`">$(& $esc $firm)</div>") }
    if ($name) {
        $by = "Prepared by $(& $esc $name)"
        if ($email) { $by += " &middot; $(& $esc $email)" }
        $textParts.Add("<div class=`"wl-meta`">$by</div>")
    }
    if ($client) { $textParts.Add("<div class=`"wl-meta`">Prepared for $(& $esc $client)</div>") }

    if ($textParts.Count -gt 0) {
        $parts.Add("<div>$($textParts -join '')</div>")
    }

    if ($parts.Count -gt 0) {
        $result.Header = "<div class=`"wl-header`">$($parts -join '')</div>"
    }
    return $result
}
