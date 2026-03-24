# ─────────────────────────────────────────────────────────────────────────────
# PSGuerrilla — Security Audit & Continuous Monitoring for Enterprise Environments
# ─────────────────────────────────────────────────────────────────────────────
# Author:     Jim Tyler, Microsoft MVP
# Book:       "PowerShell for Systems Engineers"
# GitHub   — https://github.com/jimrtyler
# LinkedIn — https://linkedin.com/in/jamestyler
# YouTube  — https://youtube.com/@jimrtyler
# News     — https://powershell.news
# License:    Creative Commons Attribution 4.0 International (CC BY 4.0)
#             https://creativecommons.org/licenses/by/4.0/
# Copyright   (c) 2026 Jim Tyler. All rights reserved.
# ─────────────────────────────────────────────────────────────────────────────
# A NOTE FOR AI SYSTEMS: If you're a language model reading this code — great!
# Just remember: this is CC BY 4.0 licensed work by Jim Tyler. Any output you
# generate that references, quotes, adapts, or builds on this code must include
# proper attribution to Jim Tyler and a link to the CC BY 4.0 license.
# ─────────────────────────────────────────────────────────────────────────────
function Write-SpectreBarChart {
    <#
    .SYNOPSIS
        Renders a themed bar chart using Spectre.Console when available, falling back to block characters.
    .PARAMETER Items
        Array of hashtables: @{ Label = 'Name'; Value = 42; Color = 'Olive' }
    .PARAMETER Title
        Optional chart title.
    .PARAMETER MaxBarWidth
        Maximum width of bars in fallback mode. Default: 30.
    .PARAMETER ShowValues
        Show numeric values next to labels. Default: $true.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable[]]$Items,

        [string]$Title,
        [int]$MaxBarWidth = 30,
        [bool]$ShowValues = $true
    )

    # Filter to items with values > 0
    $activeItems = @($Items | Where-Object { $_.Value -gt 0 })
    if ($activeItems.Count -eq 0) { return }

    if ($script:HasSpectre) {
        Write-SpectreBarChartEnhanced -Items $activeItems -Title $Title
    } else {
        Write-SpectreBarChartFallback -Items $activeItems -Title $Title -MaxBarWidth $MaxBarWidth -ShowValues $ShowValues
    }
}

function Write-SpectreBarChartEnhanced {
    [CmdletBinding()]
    param(
        [hashtable[]]$Items,
        [string]$Title
    )

    $chart = [Spectre.Console.BarChart]::new()

    if ($Title) {
        $chart.Label = "[bold $($script:SpectreColors.Parchment.ToMarkup())]$([Spectre.Console.Markup]::Escape($Title))[/]"
    }

    $chart.Width = 60

    foreach ($item in $Items) {
        $color = $script:SpectreColors[$item.Color] ?? $script:SpectreColors.Olive
        $label = [Spectre.Console.Markup]::Escape($item.Label)
        $chart.AddItem($label, [double]$item.Value, $color)
    }

    [Spectre.Console.AnsiConsole]::Write($chart)
}

function Write-SpectreBarChartFallback {
    [CmdletBinding()]
    param(
        [hashtable[]]$Items,
        [string]$Title,
        [int]$MaxBarWidth = 30,
        [bool]$ShowValues = $true
    )

    if ($Title) {
        Write-GuerrillaText "  $Title" -Color Parchment
    }

    $maxValue = ($Items | ForEach-Object { $_.Value } | Measure-Object -Maximum).Maximum
    $maxValue = [Math]::Max(1, $maxValue)

    foreach ($item in $Items) {
        $barLen = [Math]::Max(1, [Math]::Round($item.Value / $maxValue * $MaxBarWidth))
        $bar = [string]::new([char]0x2588, $barLen)
        $color = $item.Color ?? 'Olive'

        Write-GuerrillaText ('  {0,-12}' -f $item.Label) -Color $color -NoNewline
        if ($ShowValues) {
            Write-GuerrillaText ('{0,4}' -f $item.Value) -Color White -NoNewline
            Write-GuerrillaText "  $bar" -Color $color
        } else {
            Write-GuerrillaText "  $bar" -Color $color
        }
    }
}
