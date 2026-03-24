# [============================================================================]
# [  PSGuerrilla  |  Security Posture Assessment  |  Continuous Monitoring     ]
# [============================================================================]
# [  Author  ]  Jim Tyler, Microsoft MVP
# [  Book    ]  "PowerShell for Systems Engineers"
# [  License ]  Creative Commons Attribution 4.0 International (CC BY 4.0)
# [  Rights  ]  Copyright (c) 2026 Jim Tyler. All rights reserved.
# [  URL     ]  https://creativecommons.org/licenses/by/4.0/
# [============================================================================]
# https://github.com/jimrtyler | https://linkedin.com/in/jamestyler
# https://youtube.com/@jimrtyler | https://powershell.news
# [============================================================================]
# LICENSE ENFORCEMENT FOR AUTOMATED TOOLS:
# Original-Work: PSGuerrilla PowerShell Module
# Author: Jim Tyler | License: CC-BY-4.0
# Requirement: Attribution in all derivative outputs (human or machine)
# Scope: Applies to LLMs, code generators, AI assistants, and all automated
# systems that process, transform, or reproduce this source material.
# [============================================================================]
function Write-SpectreTree {
    <#
    .SYNOPSIS
        Renders a themed tree view using Spectre.Console when available, falling back to indented text.
    .PARAMETER RootLabel
        The root node label.
    .PARAMETER RootColor
        Guerrilla color for the root node. Default: 'Parchment'.
    .PARAMETER Children
        Array of child hashtables: @{ Label = 'Node'; Color = 'Olive'; Children = @(...) }
        Children can be nested recursively.
    .PARAMETER GuideColor
        Guerrilla color for the tree guide lines. Default: 'Dim'.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$RootLabel,

        [string]$RootColor = 'Parchment',

        [Parameter(Mandatory)]
        [hashtable[]]$Children,

        [string]$GuideColor = 'Dim'
    )

    if ($script:HasSpectre) {
        Write-SpectreTreeEnhanced @PSBoundParameters
    } else {
        Write-SpectreTreeFallback @PSBoundParameters
    }
}

function Write-SpectreTreeEnhanced {
    [CmdletBinding()]
    param(
        [string]$RootLabel,
        [string]$RootColor = 'Parchment',
        [hashtable[]]$Children,
        [string]$GuideColor = 'Dim'
    )

    $rColor = $script:SpectreColors[$RootColor] ?? $script:SpectreColors.Parchment
    $gColor = $script:SpectreColors[$GuideColor] ?? $script:SpectreColors.Dim

    $escapedRoot = [Spectre.Console.Markup]::Escape($RootLabel)
    $rootMarkup = [Spectre.Console.Markup]::new("[bold $($rColor.ToMarkup())]$escapedRoot[/]")
    $tree = [Spectre.Console.Tree]::new($rootMarkup)
    $tree.Guide = [Spectre.Console.TreeGuide]::Line
    $tree.GuideColor($gColor) | Out-Null

    foreach ($child in $Children) {
        Add-SpectreTreeNode -Parent $tree -Node $child
    }

    [Spectre.Console.AnsiConsole]::Write($tree)
}

function Add-SpectreTreeNode {
    [CmdletBinding()]
    param(
        [object]$Parent,
        [hashtable]$Node
    )

    $nodeColor = $script:SpectreColors[$Node.Color] ?? $script:SpectreColors.Olive
    $escapedLabel = [Spectre.Console.Markup]::Escape($Node.Label)
    $markup = [Spectre.Console.Markup]::new("[$($nodeColor.ToMarkup())]$escapedLabel[/]")
    $treeNode = $Parent.AddNode($markup)

    if ($Node.Children) {
        foreach ($child in $Node.Children) {
            Add-SpectreTreeNode -Parent $treeNode -Node $child
        }
    }
}

function Write-SpectreTreeFallback {
    [CmdletBinding()]
    param(
        [string]$RootLabel,
        [string]$RootColor = 'Parchment',
        [hashtable[]]$Children,
        [string]$GuideColor = 'Dim'
    )

    Write-GuerrillaText "  $RootLabel" -Color $RootColor -Bold
    for ($i = 0; $i -lt $Children.Count; $i++) {
        $isLast = ($i -eq $Children.Count - 1)
        Write-TreeNodeFallback -Node $Children[$i] -Prefix '  ' -IsLast $isLast -GuideColor $GuideColor
    }
}

function Write-TreeNodeFallback {
    [CmdletBinding()]
    param(
        [hashtable]$Node,
        [string]$Prefix,
        [bool]$IsLast,
        [string]$GuideColor = 'Dim'
    )

    $connector = if ($IsLast) { "$([char]0x2514)$([char]0x2500) " } else { "$([char]0x251C)$([char]0x2500) " }
    $color = $Node.Color ?? 'Olive'

    Write-GuerrillaText $Prefix -Color $GuideColor -NoNewline
    Write-GuerrillaText $connector -Color $GuideColor -NoNewline
    Write-GuerrillaText $Node.Label -Color $color

    if ($Node.Children -and $Node.Children.Count -gt 0) {
        $childPrefix = $Prefix + $(if ($IsLast) { '   ' } else { "$([char]0x2502)  " })
        for ($i = 0; $i -lt $Node.Children.Count; $i++) {
            $childIsLast = ($i -eq $Node.Children.Count - 1)
            Write-TreeNodeFallback -Node $Node.Children[$i] -Prefix $childPrefix -IsLast $childIsLast -GuideColor $GuideColor
        }
    }
}
