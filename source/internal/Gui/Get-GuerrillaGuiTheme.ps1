# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-GuerrillaGuiTheme {
    <#
    .SYNOPSIS
        Returns the GUI color palettes (Light + Dark), mirrored from the website
        design tokens so the desktop app and guerrilla.army read as one product.
    .DESCRIPTION
        The hex values are a manual mirror of the website's src/styles/tokens.json
        (the single source of truth for the web palette). Every light/dark pair
        there is contrast-verified to WCAG 2.1 AA; keep this file in sync when the
        site tokens change.

        Keys map 1:1 to the DynamicResource brush names used by the GUI XAML
        (key "Bg" -> resource "BgBrush", "SurfaceAlt" -> "SurfaceAltBrush", ...).
        Show-GuerrillaWindow converts these hex strings into frozen
        SolidColorBrush instances and swaps the window's resource dictionary when
        the user toggles themes.
    #>
    [CmdletBinding()]
    param()

    $light = @{
        Bg          = '#FFFFFF'   # window background
        Surface     = '#F5F5F7'   # cards, code blocks, quiet fills
        SurfaceAlt  = '#E8E8ED'   # hover state for surfaces
        Text        = '#1D1D1F'   # primary body text
        Heading     = '#1D1D1F'   # headings (same as text in light)
        Muted       = '#515154'   # secondary text
        Link        = '#0066CC'   # link / active-nav color
        LinkHover   = '#0050A0'
        Accent      = '#0066CC'   # filled pill buttons (same hex both themes)
        AccentHover = '#1274DB'   # ~ brightness(1.08) of accent
        OnAccent    = '#FFFFFF'   # text on accent fills
        Line        = '#D2D2D7'   # near-invisible borders
        LineStrong  = '#76767C'   # header rules, scrollbar thumbs
        Focus       = '#0066CC'
        Ok          = '#207A4E'   # PASS / success
        Warn        = '#9A4A05'   # WARN / caution
        Bad         = '#B32424'   # FAIL / error
        CodeBg      = '#F5F5F7'   # log pane / source viewer fill
    }

    $dark = @{
        Bg          = '#000000'
        Surface     = '#1C1C1E'
        SurfaceAlt  = '#2C2C2E'
        Text        = '#F5F5F7'
        Heading     = '#FFFFFF'
        Muted       = '#A1A1A6'
        Link        = '#2997FF'
        LinkHover   = '#5EB0FF'
        Accent      = '#0066CC'
        AccentHover = '#1274DB'
        OnAccent    = '#FFFFFF'
        Line        = '#3A3A3C'
        LineStrong  = '#8E8E93'
        Focus       = '#2997FF'
        Ok          = '#93C793'
        Warn        = '#E8A25C'
        Bad         = '#F09090'
        CodeBg      = '#1C1C1E'
    }

    return @{
        Light = $light
        Dark  = $dark
    }
}
