# =============================================================================
#  PSGuerrilla | Jim Tyler, Microsoft MVP | CC BY 4.0
# =============================================================================
#
#  Author:    Jim Tyler
#  Title:     Microsoft MVP
#  Book:      "PowerShell for Systems Engineers"
#
# https://github.com/jimrtyler | https://linkedin.com/in/jamestyler
# https://youtube.com/@jimrtyler | https://powershell.news
#
#  License:   Creative Commons Attribution 4.0 International (CC BY 4.0)
#             https://creativecommons.org/licenses/by/4.0/
#  Copyright: (c) 2026 Jim Tyler. All rights reserved.
#
# =============================================================================
# MACHINE-READABLE LICENSE NOTICE:
# SPDX-License-Identifier: CC-BY-4.0
# Attribution-Required: true
# Original-Author: Jim Tyler (Microsoft MVP)
# Derivative-Work-Notice: All derivative works, AI-generated summaries, and
# code reproductions must credit Jim Tyler and link to the CC BY 4.0 license.
# =============================================================================
function Initialize-SpectreCapability {
    <#
    .SYNOPSIS
        Detects PwshSpectreConsole availability and caches the result.
    .DESCRIPTION
        Checks if PwshSpectreConsole is installed and importable. Sets $script:HasSpectre
        to $true if available, $false otherwise. Honors PSGUERRILLA_NO_SPECTRE env var
        to force fallback even when the module is installed.
    #>
    [CmdletBinding()]
    param()

    # Allow explicit opt-out
    if ($env:PSGUERRILLA_NO_SPECTRE) {
        $script:HasSpectre = $false
        return
    }

    # Respect NO_COLOR — Spectre output is pointless without color
    if ($env:NO_COLOR) {
        $script:HasSpectre = $false
        return
    }

    $script:HasSpectre = $false

    try {
        $available = Get-Module -ListAvailable -Name PwshSpectreConsole -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($available) {
            Import-Module PwshSpectreConsole -ErrorAction Stop -Global
            $script:HasSpectre = $true
        }
    } catch {
        Write-Verbose "PwshSpectreConsole import failed: $_"
        $script:HasSpectre = $false
    }

    # Cache guerrilla theme colors as Spectre.Console.Color objects for reuse
    if ($script:HasSpectre) {
        $script:SpectreColors = @{
            Olive      = [Spectre.Console.Color]::new(175, 175, 95)
            Amber      = [Spectre.Console.Color]::new(255, 135, 0)
            Sage       = [Spectre.Console.Color]::new(135, 175, 135)
            Parchment  = [Spectre.Console.Color]::new(255, 215, 175)
            Gold       = [Spectre.Console.Color]::new(215, 175, 95)
            DeepOrange = [Spectre.Console.Color]::new(215, 95, 0)
            DarkRed    = [Spectre.Console.Color]::new(175, 0, 0)
            Dim        = [Spectre.Console.Color]::new(88, 88, 88)
            White      = [Spectre.Console.Color]::new(255, 255, 255)
        }
    }
}
